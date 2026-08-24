//go:build !windows

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
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

	"github.com/charmbracelet/x/ansi"
	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
)

func TestCLIRunCtrlCCancelsProviderAndAllowsRecoveryUnderPTY(t *testing.T) {
	requestStarted := make(chan struct{})
	requestCanceled := make(chan struct{})
	var startedOnce sync.Once
	var canceledOnce sync.Once
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		_ = request.Body.Close()
		current := requestCount.Add(1)
		if current == 1 {
			startedOnce.Do(func() { close(requestStarted) })
			<-request.Context().Done()
			canceledOnce.Do(func() { close(requestCanceled) })
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-recovery\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"pty-mock-model\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"PTY_RECOVERY_OK\"},\"finish_reason\":null}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-recovery\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"pty-mock-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		w.(http.Flusher).Flush()
	}))
	t.Cleanup(func() {
		server.CloseClientConnections()
		server.Close()
	})

	environment := newPersistentPTYEnvironment(t, server.URL)
	first := environment.start(t, "wait until canceled")
	select {
	case <-requestStarted:
	case <-time.After(10 * time.Second):
		first.stop()
		t.Fatal("mock provider did not receive the blocking request")
	}

	cancelStarted := time.Now()
	require.NoError(t, first.write([]byte{3}))
	select {
	case waitErr := <-first.waitDone:
		t.Logf("CLI wait result after Ctrl+C: %v", waitErr)
		require.Less(t, time.Since(cancelStarted), 5*time.Second)
	case <-time.After(5 * time.Second):
		first.stop()
		t.Fatal("CLI did not exit promptly after Ctrl+C")
	}
	first.close()

	select {
	case <-requestCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("provider request context was not canceled")
	}
	require.NotContains(t, strings.ToLower(ansi.Strip(first.transcript.String())), "panic:")

	second := environment.start(t, "verify recovery")
	select {
	case waitErr := <-second.waitDone:
		second.close()
		require.NoError(t, waitErr, "recovery PTY transcript:\n%s", second.transcript.String())
	case <-time.After(10 * time.Second):
		second.stop()
		t.Fatal("recovery CLI run timed out")
	}
	require.Contains(t, ansi.Strip(second.transcript.String()), "PTY_RECOVERY_OK")
	require.GreaterOrEqual(t, requestCount.Load(), int32(2))
}

type persistentPTYEnvironment struct {
	root      string
	home      string
	configDir string
	dataDir   string
}

func newPersistentPTYEnvironment(t *testing.T, baseURL string) persistentPTYEnvironment {
	t.Helper()
	root := t.TempDir()
	environment := persistentPTYEnvironment{
		root:      root,
		home:      filepath.Join(root, "home"),
		configDir: filepath.Join(root, "config"),
		dataDir:   filepath.Join(root, "data"),
	}
	for _, directory := range []string{environment.home, environment.configDir, environment.dataDir} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	config := map[string]any{
		"options": map[string]any{
			"disable_default_providers":    true,
			"disable_provider_auto_update": true,
			"disable_metrics":              true,
			"progress":                     false,
		},
		"providers": map[string]any{
			mockProviderID: map[string]any{
				"name":     "PTY Mock Provider",
				"base_url": baseURL + "/v1",
				"api_key":  mockAPIKey,
				"type":     "openai-compat",
				"models": []map[string]any{{
					"id":                 mockModelID,
					"name":               "PTY Mock Model",
					"context_window":     32768,
					"default_max_tokens": 1024,
				}},
			},
		},
		"models": map[string]any{
			"large": map[string]any{"model": mockModelID, "provider": mockProviderID},
			"small": map[string]any{"model": mockModelID, "provider": mockProviderID},
		},
	}
	configData, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(environment.configDir, "crush.json"), configData, 0o600))
	return environment
}

func (environment persistentPTYEnvironment) start(t *testing.T, prompt string) *runningPTYCommand {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	command := exec.CommandContext(
		ctx,
		testBinary,
		"--cwd", environment.root,
		"--data-dir", environment.dataDir,
		"run",
		"--quiet",
		"--model", mockProviderID+"/"+mockModelID,
		prompt,
	)
	command.Dir = environment.root
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + environment.home,
		"USER=secops-pty",
		"LOGNAME=secops-pty",
		"TMPDIR=" + os.TempDir(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
		"XDG_CONFIG_HOME=" + environment.configDir,
		"XDG_DATA_HOME=" + environment.dataDir,
		"CRUSH_GLOBAL_CONFIG=" + environment.configDir,
		"CRUSH_GLOBAL_DATA=" + environment.dataDir,
		"CRUSH_DISABLE_METRICS=1",
		"CRUSH_DISABLE_PROVIDER_AUTO_UPDATE=1",
	}
	terminal, err := pty.StartWithSize(command, &pty.Winsize{Rows: 32, Cols: 120})
	require.NoError(t, err)

	running := &runningPTYCommand{
		cancel:     cancel,
		command:    command,
		terminal:   terminal,
		waitDone:   make(chan error, 1),
		copyDone:   make(chan struct{}),
		transcript: &lockedBuffer{},
	}
	go func() {
		_, _ = io.Copy(running.transcript, terminal)
		close(running.copyDone)
	}()
	go func() { running.waitDone <- command.Wait() }()
	t.Cleanup(running.stop)
	return running
}

type runningPTYCommand struct {
	cancel     context.CancelFunc
	command    *exec.Cmd
	terminal   *os.File
	waitDone   chan error
	copyDone   chan struct{}
	transcript *lockedBuffer
	closed     atomic.Bool
}

func (running *runningPTYCommand) write(data []byte) error {
	if _, err := running.terminal.Write(data); err != nil {
		return fmt.Errorf("write PTY input: %w", err)
	}
	return nil
}

func (running *runningPTYCommand) close() {
	if !running.closed.CompareAndSwap(false, true) {
		return
	}
	running.cancel()
	_ = running.terminal.Close()
	<-running.copyDone
}

func (running *runningPTYCommand) stop() {
	if running.closed.Load() {
		return
	}
	running.cancel()
	_ = running.terminal.Close()
	select {
	case <-running.waitDone:
	case <-time.After(2 * time.Second):
		if running.command.Process != nil {
			_ = running.command.Process.Kill()
		}
	}
	running.close()
}
