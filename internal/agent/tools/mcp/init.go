// Package mcp provides functionality for managing Model Context Protocol (MCP)
// clients within the Crush application.
package mcp

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/csync"
	"github.com/chenchunrun/SecOps/internal/home"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/pubsub"
	"github.com/chenchunrun/SecOps/internal/version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func parseLevel(level string) slog.Level {
	switch level {
	case "info":
		return slog.LevelInfo
	case "notice":
		return slog.LevelInfo
	case "warning":
		return slog.LevelWarn
	default:
		return slog.LevelDebug
	}
}

// ClientSession wraps an mcp.ClientSession with a context cancel function so
// that the context created during session establishment is properly cleaned up
// on close.
type ClientSession struct {
	*mcp.ClientSession
	cancel context.CancelFunc
}

// Close cancels the session context and then closes the underlying session.
func (s *ClientSession) Close() error {
	s.cancel()
	return s.ClientSession.Close()
}

var (
	sessions    = csync.NewMap[string, *ClientSession]()
	states      = csync.NewMap[string, ClientInfo]()
	broker      = pubsub.NewBroker[Event]()
	initOnce    sync.Once
	initDone    = make(chan struct{})
	initStarted atomic.Bool
	clientLocks sync.Map
)

// lockClient serializes lifecycle and registry changes for one server.
// Waiting callers can cancel without waiting for another network operation.
func lockClient(ctx context.Context, name string) (func(), error) {
	v, _ := clientLocks.LoadOrStore(name, make(chan struct{}, 1))
	gate := v.(chan struct{})
	select {
	case gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-gate
			return nil, err
		}
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// StartInitialize arms the initialization gate before launching the worker.
func StartInitialize(ctx context.Context, permissions permission.Service, cfg *config.ConfigStore) {
	initStarted.Store(true)
	go Initialize(ctx, permissions, cfg)
}

// State represents the current state of an MCP client
type State int

const (
	StateDisabled State = iota
	StateStarting
	StateConnected
	StateError
)

func (s State) String() string {
	switch s {
	case StateDisabled:
		return "disabled"
	case StateStarting:
		return "starting"
	case StateConnected:
		return "connected"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// EventType represents the type of MCP event
type EventType uint

const (
	EventStateChanged EventType = iota
	EventToolsListChanged
	EventPromptsListChanged
	EventResourcesListChanged
)

// Event represents an event in the MCP system
type Event struct {
	Type   EventType
	Name   string
	State  State
	Error  error
	Counts Counts
}

// Counts number of available tools, prompts, etc.
type Counts struct {
	Tools     int
	Prompts   int
	Resources int
}

// ClientInfo holds information about an MCP client's state
type ClientInfo struct {
	Name        string
	State       State
	Error       error
	Client      *ClientSession
	Counts      Counts
	ConnectedAt time.Time
}

// SubscribeEvents returns a channel for MCP events
func SubscribeEvents(ctx context.Context) <-chan pubsub.Event[Event] {
	return broker.Subscribe(ctx)
}

// GetStates returns the current state of all MCP clients
func GetStates() map[string]ClientInfo {
	return states.Copy()
}

// GetState returns the state of a specific MCP client
func GetState(name string) (ClientInfo, bool) {
	return states.Get(name)
}

// Close closes all MCP clients. This should be called during application shutdown.
func Close(ctx context.Context) error {
	var wg sync.WaitGroup
	for name, session := range sessions.Seq2() {
		wg.Go(func() {
			done := make(chan error, 1)
			go func() {
				done <- session.Close()
			}()
			select {
			case err := <-done:
				if err != nil &&
					!errors.Is(err, io.EOF) &&
					!errors.Is(err, context.Canceled) &&
					err.Error() != "signal: killed" {
					slog.Warn("Failed to shutdown MCP client", "name", name, "error", err)
				}
			case <-ctx.Done():
			}
		})
	}
	wg.Wait()
	broker.Shutdown()
	return nil
}

// Initialize initializes MCP clients based on the provided configuration.
func Initialize(ctx context.Context, permissions permission.Service, cfg *config.ConfigStore) {
	initStarted.Store(true)
	slog.Info("Initializing MCP clients")
	var wg sync.WaitGroup
	// Initialize states for all configured MCPs
	for name, m := range cfg.Config().MCP {
		if m.Disabled {
			updateState(name, StateDisabled, nil, nil, Counts{})
			slog.Debug("Skipping disabled MCP", "name", name)
			continue
		}

		// Set initial starting state
		wg.Add(1)
		go func(name string, m config.MCPConfig) {
			defer func() {
				wg.Done()
				if r := recover(); r != nil {
					var err error
					switch v := r.(type) {
					case error:
						err = v
					case string:
						err = fmt.Errorf("panic: %s", v)
					default:
						err = fmt.Errorf("panic: %v", v)
					}
					updateState(name, StateError, err, nil, Counts{})
					slog.Error("Panic in MCP client initialization", "error", err, "name", name)
				}
			}()

			if err := initClient(ctx, cfg, name, m, cfg.Resolver()); err != nil {
				slog.Debug("Failed to initialize MCP client", "name", name, "error", err)
			}
		}(name, m)
	}
	wg.Wait()
	initOnce.Do(func() { close(initDone) })
}

// WaitForInit waits up to 15 seconds for optional MCP initialization.
// If Initialize was never called, this returns immediately.
func WaitForInit(ctx context.Context) error {
	if !initStarted.Load() {
		return ctx.Err()
	}
	return waitForInit(ctx, initDone, 15*time.Second)
}

func waitForInit(ctx context.Context, done <-chan struct{}, timeout time.Duration) error {
	// A slow optional MCP must not prevent the application from becoming usable.
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		slog.Warn("MCP initialization is still running; continuing with available tools")
		return nil
	}
}

// InitializeSingle initializes a single MCP client by name.
func InitializeSingle(ctx context.Context, name string, cfg *config.ConfigStore) error {
	m, exists := cfg.Config().MCP[name]
	if !exists {
		return fmt.Errorf("mcp '%s' not found in configuration", name)
	}

	if m.Disabled {
		return DisableSingle(cfg, name)
	}

	return initClient(ctx, cfg, name, m, cfg.Resolver())
}

// initClient initializes a single MCP client with the given configuration.
func initClient(ctx context.Context, cfg *config.ConfigStore, name string, m config.MCPConfig, resolver config.VariableResolver) error {
	unlock, err := lockClient(ctx, name)
	if err != nil {
		return err
	}
	defer unlock()
	return initClientLocked(ctx, cfg, name, m, resolver)
}

func initClientLocked(ctx context.Context, cfg *config.ConfigStore, name string, m config.MCPConfig, resolver config.VariableResolver) error {
	clearClient(name)
	// Set initial starting state.
	updateState(name, StateStarting, nil, nil, Counts{})
	initCtx, cancel := context.WithTimeout(ctx, mcpTimeout(m))
	defer cancel()

	// createSession handles its own timeout internally.
	session, err := createSession(ctx, name, m, resolver)
	if err != nil {
		return err
	}

	tools, err := getTools(initCtx, session)
	if err != nil {
		slog.Error("Error listing tools", "error", err)
		updateState(name, StateError, err, nil, Counts{})
		session.Close()
		return err
	}

	prompts, err := getPrompts(initCtx, session)
	if err != nil {
		slog.Error("Error listing prompts", "error", err)
		updateState(name, StateError, err, nil, Counts{})
		session.Close()
		return err
	}
	resources, err := getResources(initCtx, session)
	if err == nil {
		err = initCtx.Err()
	}
	if err != nil {
		updateState(name, StateError, err, nil, Counts{})
		session.Close()
		return err
	}

	toolCount := updateTools(cfg, name, tools)
	updatePrompts(name, prompts)
	resourceCount := updateResources(name, resources)
	sessions.Set(name, session)

	updateState(name, StateConnected, nil, session, Counts{
		Tools:     toolCount,
		Prompts:   len(prompts),
		Resources: resourceCount,
	})

	return nil
}

// DisableSingle disables and closes a single MCP client by name.
func DisableSingle(cfg *config.ConfigStore, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	unlock, err := lockClient(ctx, name)
	if err != nil {
		return err
	}
	defer unlock()
	session, ok := sessions.Get(name)
	if ok {
		if err := session.Close(); err != nil &&
			!errors.Is(err, io.EOF) &&
			!errors.Is(err, context.Canceled) &&
			err.Error() != "signal: killed" {
			slog.Warn("Error closing MCP session", "name", name, "error", err)
		}
		sessions.Del(name)
	}

	// Clear tools and prompts for this MCP.
	updateTools(cfg, name, nil)
	updatePrompts(name, nil)
	updateResources(name, nil)

	// Update state to disabled.
	updateState(name, StateDisabled, nil, nil, Counts{})

	slog.Info("Disabled mcp client", "name", name)
	return nil
}

func getOrRenewClient(ctx context.Context, cfg *config.ConfigStore, name string) (*ClientSession, error) {
	unlock, err := lockClient(ctx, name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	sess, ok := sessions.Get(name)
	if !ok {
		return nil, fmt.Errorf("mcp '%s' not available", name)
	}

	m := cfg.Config().MCP[name]
	// Stateless HTTP servers may not implement ping. Each tool request already
	// establishes its own HTTP exchange; do not reconnect solely for a probe.
	if m.Sessionless && m.Type == config.MCPHttp {
		return sess, nil
	}

	timeout := mcpTimeout(m)
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err = sess.Ping(pingCtx, nil)
	if err == nil {
		return sess, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err = initClientLocked(ctx, cfg, name, m, cfg.Resolver()); err != nil {
		return nil, err
	}
	sess, _ = sessions.Get(name)
	return sess, nil
}

// clearClient must be called with the server's lifecycle lock held.
func clearClient(name string) {
	if session, ok := sessions.Get(name); ok {
		sessions.Del(name)
		_ = session.Close()
	}
	allTools.Del(name)
	allPrompts.Del(name)
	allResources.Del(name)
}

// failSession cannot tear down a replacement connection after a stale request.
// The caller must hold the server's lifecycle lock.
func failSession(name string, session *ClientSession, err error) {
	if current, ok := sessions.Get(name); !ok || current != session {
		return
	}
	clearClient(name)
	updateState(name, StateError, err, nil, Counts{})
}

// updateState updates the state of an MCP client and publishes an event
func updateState(name string, state State, err error, client *ClientSession, counts Counts) {
	info := ClientInfo{
		Name:   name,
		State:  state,
		Error:  err,
		Client: client,
		Counts: counts,
	}
	if state == StateConnected {
		info.ConnectedAt = time.Now()
	}
	states.Set(name, info)

	// Publish state change event
	broker.Publish(pubsub.UpdatedEvent, Event{
		Type:   EventStateChanged,
		Name:   name,
		State:  state,
		Error:  err,
		Counts: counts,
	})
}

func createSession(ctx context.Context, name string, m config.MCPConfig, resolver config.VariableResolver) (*ClientSession, error) {
	timeout := mcpTimeout(m)
	mcpCtx, cancel := context.WithCancel(ctx)
	cancelTimer := time.AfterFunc(timeout, cancel)

	transport, err := createTransport(mcpCtx, m, resolver)
	if err != nil {
		updateState(name, StateError, err, nil, Counts{})
		slog.Error("Error creating MCP client", "error", err, "name", name)
		cancel()
		cancelTimer.Stop()
		return nil, err
	}

	client := mcp.NewClient(
		&mcp.Implementation{
			Name:    "crush",
			Version: version.Version,
			Title:   "Crush",
		},
		&mcp.ClientOptions{
			ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
				broker.Publish(pubsub.UpdatedEvent, Event{
					Type: EventToolsListChanged,
					Name: name,
				})
			},
			PromptListChangedHandler: func(context.Context, *mcp.PromptListChangedRequest) {
				broker.Publish(pubsub.UpdatedEvent, Event{
					Type: EventPromptsListChanged,
					Name: name,
				})
			},
			ResourceListChangedHandler: func(context.Context, *mcp.ResourceListChangedRequest) {
				broker.Publish(pubsub.UpdatedEvent, Event{
					Type: EventResourcesListChanged,
					Name: name,
				})
			},
			LoggingMessageHandler: func(ctx context.Context, req *mcp.LoggingMessageRequest) {
				level := parseLevel(string(req.Params.Level))
				slog.Log(ctx, level, "MCP log", "name", name, "logger", req.Params.Logger, "data", req.Params.Data)
			},
		},
	)

	session, err := client.Connect(mcpCtx, transport, nil)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		} else if mcpCtx.Err() != nil {
			err = fmt.Errorf("mcp initialization timed out after %s: %w", timeout, context.DeadlineExceeded)
		}
		err = startupError(err, transport)
		updateState(name, StateError, err, nil, Counts{})
		slog.Error("MCP client failed to initialize", "error", err, "name", name)
		cancel()
		cancelTimer.Stop()
		return nil, err
	}

	cancelTimer.Stop()
	slog.Debug("MCP client initialized", "name", name)
	return &ClientSession{session, cancel}, nil
}

func createTransport(ctx context.Context, m config.MCPConfig, resolver config.VariableResolver) (mcp.Transport, error) {
	var oauthHandler *browserOAuth
	if m.OAuth != nil {
		var err error
		oauthHandler, err = newBrowserOAuth(m)
		if err != nil {
			return nil, err
		}
	}
	if m.Sessionless && m.Type != config.MCPHttp {
		return nil, fmt.Errorf("sessionless requires an http MCP transport")
	}
	switch m.Type {
	case config.MCPStdio:
		command, err := resolver.ResolveValue(m.Command)
		if err != nil {
			return nil, fmt.Errorf("invalid mcp command: %w", err)
		}
		if strings.TrimSpace(command) == "" {
			return nil, fmt.Errorf("mcp stdio config requires a non-empty 'command' field")
		}
		cmd := exec.CommandContext(ctx, home.Long(command), m.Args...)
		cmd.Env = append(os.Environ(), m.ResolvedEnv()...)
		cmd.Stderr = &startupOutput{}
		cmd.WaitDelay = time.Second
		return &mcp.CommandTransport{
			Command: cmd,
		}, nil
	case config.MCPHttp:
		if strings.TrimSpace(m.URL) == "" {
			return nil, fmt.Errorf("mcp http config requires a non-empty 'url' field")
		}
		client := &http.Client{
			Transport: &headerRoundTripper{
				headers: m.ResolvedHeaders(),
			},
		}
		if oauthHandler != nil {
			client.CheckRedirect = oauthHandler.client.CheckRedirect
			// Reuse the validated resource origin, without permitting issuer requests.
			u, _ := oauthURL(m.URL)
			client.Transport = oauthOriginTransport{origins: []string{u.Scheme + "://" + u.Host}, base: &headerRoundTripper{headers: m.ResolvedHeaders()}}
		}
		return &mcp.StreamableClientTransport{
			OAuthHandler:         optionalOAuthHandler(oauthHandler),
			DisableStandaloneSSE: m.Sessionless,
			Endpoint:             m.URL,
			HTTPClient:           client,
		}, nil
	case config.MCPSSE:
		if strings.TrimSpace(m.URL) == "" {
			return nil, fmt.Errorf("mcp sse config requires a non-empty 'url' field")
		}
		client := &http.Client{
			Transport: &headerRoundTripper{
				headers: m.ResolvedHeaders(),
			},
		}
		return &mcp.SSEClientTransport{
			Endpoint:   m.URL,
			HTTPClient: client,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported mcp type: %s", m.Type)
	}
}

type headerRoundTripper struct {
	headers map[string]string
}

func (rt headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range rt.headers {
		req.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func mcpTimeout(m config.MCPConfig) time.Duration {
	if m.OAuth != nil && m.Timeout == 0 {
		return 5 * time.Minute
	}
	return time.Duration(cmp.Or(m.Timeout, 15)) * time.Second
}
