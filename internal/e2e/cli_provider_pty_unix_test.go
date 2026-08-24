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
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
)

const (
	mockProviderID    = "pty-mock"
	mockModelID       = "pty-mock-model"
	mockAPIKey        = "pty-test-key"
	mockPrompt        = "Reply exactly with PTY_STREAM_OK"
	mockStreamContent = "PTY_STREAM_OK"
)

type capturedProviderRequest struct {
	Path          string
	Authorization string
	Body          map[string]any
}

func TestCLIRunStreamsMockProviderResponseUnderPTY(t *testing.T) {
	requests := make(chan capturedProviderRequest, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var body map[string]any
		decodeErr := json.NewDecoder(request.Body).Decode(&body)
		if decodeErr != nil {
			http.Error(w, decodeErr.Error(), http.StatusBadRequest)
			return
		}
		requests <- capturedProviderRequest{
			Path:          request.URL.Path,
			Authorization: request.Header.Get("Authorization"),
			Body:          body,
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-pty\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"pty-mock-model\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"PTY_\"},\"finish_reason\":null}]}\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-pty\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"pty-mock-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"STREAM_OK\"},\"finish_reason\":null}]}\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-pty\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"pty-mock-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		w.(http.Flusher).Flush()
	}))
	t.Cleanup(server.Close)

	transcript, err := runConfiguredProviderPTY(t, server.URL, mockPrompt)
	require.NoError(t, err, "PTY transcript:\n%s", transcript)
	require.Contains(t, ansi.Strip(transcript), mockStreamContent)

	select {
	case captured := <-requests:
		require.Equal(t, "/v1/chat/completions", captured.Path)
		require.Equal(t, "Bearer "+mockAPIKey, captured.Authorization)
		require.Equal(t, mockModelID, captured.Body["model"])
		require.Equal(t, true, captured.Body["stream"])
		encodedBody, marshalErr := json.Marshal(captured.Body)
		require.NoError(t, marshalErr)
		require.Contains(t, string(encodedBody), mockPrompt)
	case <-time.After(2 * time.Second):
		t.Fatal("mock provider did not receive a request")
	}
}

func TestCLIRunSurfacesMockProviderRateLimitUnderPTY(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":{"type":"rate_limit_error","message":"PTY_RATE_LIMIT"}}`)
	}))
	t.Cleanup(server.Close)

	transcript, err := runConfiguredProviderPTY(t, server.URL, "trigger rate limit")
	require.Error(t, err)
	plain := ansi.Strip(transcript)
	require.Contains(t, plain, "rate limit reached")
	require.Contains(t, plain, "provider PTY")
	require.Contains(t, plain, "Mock Provider")
	require.Contains(t, plain, "retry in 15s or switch model/provider")
	require.NotContains(t, plain, "PTY_RATE_LIMIT")
}

func runConfiguredProviderPTY(t *testing.T, baseURL, prompt string) (string, error) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configDir := filepath.Join(root, "config")
	dataDir := filepath.Join(root, "data")
	for _, directory := range []string{home, configDir, dataDir} {
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
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "crush.json"), configData, 0o600))

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		testBinary,
		"--cwd", root,
		"--data-dir", dataDir,
		"run",
		"--quiet",
		"--model", mockProviderID+"/"+mockModelID,
		prompt,
	)
	command.Dir = root
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"USER=secops-pty",
		"LOGNAME=secops-pty",
		"TMPDIR=" + os.TempDir(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
		"XDG_CONFIG_HOME=" + configDir,
		"XDG_DATA_HOME=" + dataDir,
		"CRUSH_GLOBAL_CONFIG=" + configDir,
		"CRUSH_GLOBAL_DATA=" + dataDir,
		"CRUSH_DISABLE_METRICS=1",
		"CRUSH_DISABLE_PROVIDER_AUTO_UPDATE=1",
	}

	terminal, err := pty.StartWithSize(command, &pty.Winsize{Rows: 32, Cols: 120})
	if err != nil {
		return "", fmt.Errorf("start configured provider PTY: %w", err)
	}
	var transcript lockedBuffer
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&transcript, terminal)
		close(copyDone)
	}()
	waitErr := command.Wait()
	_ = terminal.Close()
	<-copyDone
	if ctx.Err() != nil {
		return transcript.String(), fmt.Errorf("configured provider PTY timed out: %w", ctx.Err())
	}
	if waitErr != nil {
		return transcript.String(), fmt.Errorf("configured provider CLI failed: %w", waitErr)
	}
	return strings.TrimSpace(transcript.String()), nil
}
