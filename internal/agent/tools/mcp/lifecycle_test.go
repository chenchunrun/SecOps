package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/env"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func TestWaitForInitBounded(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, waitForInit(ctx, make(chan struct{}), time.Millisecond))
	cancel()
	require.ErrorIs(t, waitForInit(ctx, make(chan struct{}), time.Second), context.Canceled)
	done := make(chan struct{})
	close(done)
	require.NoError(t, waitForInit(context.Background(), done, time.Second))
}

func TestClientLockCancellationAndIsolation(t *testing.T) {
	t.Parallel()
	unlock, err := lockClient(context.Background(), t.Name())
	require.NoError(t, err)
	defer unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = lockClient(ctx, t.Name())
	require.ErrorIs(t, err, context.Canceled)
	other, err := lockClient(context.Background(), t.Name()+"-other")
	require.NoError(t, err)
	other()
}

func TestStaleSessionFailureKeepsReplacement(t *testing.T) {
	t.Parallel()
	name := t.Name()
	old, current := &ClientSession{}, &ClientSession{}
	sessions.Set(name, current)
	allTools.Set(name, []*Tool{{Name: "replacement"}})
	updateState(name, StateConnected, nil, current, Counts{Tools: 1})
	t.Cleanup(func() { sessions.Del(name); states.Del(name); allTools.Del(name) })
	unlock, err := lockClient(context.Background(), name)
	require.NoError(t, err)
	defer unlock()
	failSession(name, old, io.EOF)
	got, ok := sessions.Get(name)
	require.True(t, ok)
	require.Same(t, current, got)
	info, _ := GetState(name)
	require.Equal(t, StateConnected, info.State)
	tools, _ := allTools.Get(name)
	require.Equal(t, "replacement", tools[0].Name)
}

func TestSessionlessTransport(t *testing.T) {
	t.Parallel()
	resolver := config.NewEnvironmentVariableResolver(env.NewFromMap(nil))
	for _, sessionless := range []bool{true, false} {
		transport, err := createTransport(context.Background(), config.MCPConfig{
			Type: config.MCPHttp, URL: "https://example.invalid/mcp", Sessionless: sessionless,
		}, resolver)
		require.NoError(t, err)
		require.Equal(t, sessionless, transport.(*mcp.StreamableClientTransport).DisableStandaloneSSE)
	}
	_, err := createTransport(context.Background(), config.MCPConfig{Type: config.MCPStdio, Sessionless: true}, resolver)
	require.ErrorContains(t, err, "requires an http")
}

func TestStartupOutputBoundedAndRedacted(t *testing.T) {
	t.Parallel()
	b := &startupOutput{}
	input := "token=abcdefgh1234 secret-value\x1b[31m\n" + strings.Repeat("x", startupOutputLimit*2)
	n, err := b.Write([]byte(input))
	require.NoError(t, err)
	require.Equal(t, len(input), n)
	require.Len(t, b.data, startupOutputLimit)
	transport := &mcp.CommandTransport{Command: &exec.Cmd{Stderr: b, Env: []string{"CUSTOM_KEY=secret-value"}}}
	err = startupError(io.EOF, transport)
	require.True(t, errors.Is(err, io.EOF))
	require.NotContains(t, err.Error(), "abcdefgh1234")
	require.NotContains(t, err.Error(), "secret-value")
	require.NotContains(t, err.Error(), "\x1b")
}

func TestInitializationDiscoveryTimeout(t *testing.T) {
	t.Parallel()
	name := t.Name()
	var gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			gets.Add(1)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch request.Method {
		case "server/discover":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": -32601, "message": "Method not found"}})
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{
				"protocolVersion": "2025-03-26", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "wedged", "version": "1"},
			}})
		case "tools/list":
			<-r.Context().Done()
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer server.Close()
	defer states.Del(name)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	err := initClient(ctx, nil, name, config.MCPConfig{Type: config.MCPHttp, URL: server.URL, Timeout: 1, Sessionless: true}, nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 4*time.Second)
	require.NoError(t, ctx.Err(), "the server timeout, not the parent timeout, must fire")
	state, ok := GetState(name)
	require.True(t, ok)
	require.Equal(t, StateError, state.State)
	_, ok = sessions.Get(name)
	require.False(t, ok)
	require.Zero(t, gets.Load(), "sessionless must not open a standalone GET stream")
}

func TestCreateSessionPreservesCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := createSession(ctx, t.Name(), config.MCPConfig{Type: config.MCPHttp, URL: "http://127.0.0.1:1"}, nil)
	defer states.Del(t.Name())
	require.ErrorIs(t, err, context.Canceled)
	require.NotContains(t, err.Error(), "timed out")
}

func TestMCPStartupHelper(t *testing.T) {
	marker := os.Getenv("SECOPS_MCP_STARTUP_TEST_MARKER")
	if marker == "" {
		return
	}
	file, err := os.OpenFile(marker, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(3)
	}
	_, _ = file.WriteString("started\n")
	_ = file.Close()
	_, _ = os.Stderr.WriteString("Missing test dependency\n")
	os.Exit(2)
}

func TestStartupDiagnosticsExecuteCommandOnce(t *testing.T) {
	t.Parallel()
	executable, err := os.Executable()
	require.NoError(t, err)
	marker := filepath.Join(t.TempDir(), "starts")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = createSession(ctx, t.Name(), config.MCPConfig{
		Type: config.MCPStdio, Command: executable,
		Args: []string{"-test.run=^TestMCPStartupHelper$"},
		Env:  map[string]string{"SECOPS_MCP_STARTUP_TEST_MARKER": marker},
	}, config.NewEnvironmentVariableResolver(env.NewFromMap(nil)))
	defer states.Del(t.Name())
	require.ErrorContains(t, err, "Missing test dependency")
	starts, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Equal(t, "started\n", string(starts))
}

func TestConcurrentRenewalRestoresRegistries(t *testing.T) {
	// Isolate config loading from the user's providers and credentials.
	dir := t.TempDir()
	t.Setenv("CRUSH_GLOBAL_CONFIG", dir)
	t.Setenv("CRUSH_GLOBAL_DATA", dir)
	t.Setenv("CRUSH_DISABLE_PROVIDER_AUTO_UPDATE", "1")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "crush.json"), []byte(`{"options":{"disable_default_providers":true},"providers":{"test":{"type":"openai-compat","base_url":"http://127.0.0.1:1/v1","api_key":"test-only","models":[{"id":"test-model","name":"Test","context_window":8192,"default_max_tokens":1024}]}}}`), 0o600))
	cfg, err := config.Load(dir, filepath.Join(dir, ".crush"), false)
	require.NoError(t, err)
	server := mcp.NewServer(&mcp.Implementation{Name: "renewal-test", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "before", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	var initializations atomic.Int32
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var request struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &request)
		if request.Method == "initialize" {
			initializations.Add(1)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(httpServer.Close)
	name := t.Name()
	cfg.Config().MCP = config.MCPs{name: {Type: config.MCPHttp, URL: httpServer.URL}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, InitializeSingle(ctx, name, cfg))
	t.Cleanup(func() { _ = DisableSingle(cfg, name); states.Del(name) })
	old, _ := sessions.Get(name)
	require.NoError(t, old.Ping(ctx, nil))
	require.NoError(t, old.Close())
	server.AddTool(&mcp.Tool{Name: "after", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
	const callers = 8
	results := make([]*ClientSession, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() { results[i], errs[i] = getOrRenewClient(ctx, cfg, name) })
	}
	wg.Wait()
	for i := range callers {
		require.NoError(t, errs[i])
		require.Same(t, results[0], results[i])
	}
	require.NotSame(t, old, results[0])
	require.EqualValues(t, 2, initializations.Load(), "concurrent callers must share one renewal")
	tools, _ := allTools.Get(name)
	require.Len(t, tools, 2, "renewal must rediscover tools")
	unlock, err := lockClient(ctx, name)
	require.NoError(t, err)
	failSession(name, results[0], io.EOF)
	unlock()
	_, ok := allTools.Get(name)
	require.False(t, ok, "failed sessions must not advertise stale tools")
	// A sessionless endpoint must not be subjected to a stateful ping probe.
	stateless := &ClientSession{}
	cfg.Config().MCP[name] = config.MCPConfig{Type: config.MCPHttp, Sessionless: true}
	sessions.Set(name, stateless)
	defer sessions.Del(name)
	got, err := getOrRenewClient(ctx, cfg, name)
	require.NoError(t, err)
	require.Same(t, stateless, got)
}
