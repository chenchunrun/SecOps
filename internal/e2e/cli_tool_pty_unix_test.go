//go:build !windows

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/require"
)

const (
	toolPrompt       = "Run the requested harmless verification command"
	toolCallID       = "call-pty-bash-1"
	toolResultMarker = "PTY_TOOL_EXECUTED"
	toolFinalMarker  = "PTY_TOOL_OK"
)

func TestCLIRunExecutesApprovedToolAndReturnsResultUnderPTY(t *testing.T) {
	var mainStage atomic.Int32
	mainRequests := make(chan map[string]any, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		bodyText := string(encoded)
		if strings.Contains(bodyText, "Generate a concise title") {
			writePTYTextStream(w, "PTY tool session")
			return
		}

		mainRequests <- body
		if strings.Contains(bodyText, `"role":"tool"`) {
			switch {
			case mainStage.CompareAndSwap(1, 2):
				writePTYBashToolStream(w)
				return
			case mainStage.CompareAndSwap(2, 3):
				writePTYTextStream(w, toolFinalMarker)
				return
			}
			http.Error(w, "unexpected tool result order", http.StatusConflict)
			return
		}
		if !mainStage.CompareAndSwap(0, 1) {
			http.Error(w, "unexpected main request order", http.StatusConflict)
			return
		}
		writePTYBashToolStream(w)
	}))
	t.Cleanup(func() {
		server.CloseClientConnections()
		server.Close()
	})

	environment := newPersistentPTYEnvironment(t, server.URL)
	running := environment.start(t, toolPrompt)
	select {
	case waitErr := <-running.waitDone:
		running.close()
		require.NoError(t, waitErr, "tool PTY transcript:\n%s", running.transcript.String())
	case <-time.After(15 * time.Second):
		running.stop()
		t.Fatal("tool CLI run timed out")
	}

	plain := ansi.Strip(running.transcript.String())
	require.Contains(t, plain, toolFinalMarker)
	require.Equal(t, int32(3), mainStage.Load(), "model did not receive both tool result turns")

	executionData, err := os.ReadFile(filepath.Join(environment.root, "pty-tool-executions.txt"))
	require.NoError(t, err)
	require.Equal(t, toolResultMarker+"\n", string(executionData), "streamed tool call executed more than once")

	var requests []map[string]any
	for {
		select {
		case request := <-mainRequests:
			requests = append(requests, request)
		default:
			goto drained
		}
	}

drained:
	require.Len(t, requests, 3)
	firstBody, err := json.Marshal(requests[0])
	require.NoError(t, err)
	require.Contains(t, string(firstBody), toolPrompt)
	require.Equal(t, mockModelID, requests[0]["model"])

	secondBody, err := json.Marshal(requests[1])
	require.NoError(t, err)
	require.Contains(t, string(secondBody), toolCallID)
	require.Contains(t, string(secondBody), toolResultMarker)
	require.Contains(t, string(secondBody), `"role":"tool"`)

	thirdBody, err := json.Marshal(requests[2])
	require.NoError(t, err)
	require.Contains(t, string(thirdBody), toolCallID)
	require.Contains(t, string(thirdBody), toolResultMarker)
}

func writePTYBashToolStream(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	first := map[string]any{
		"id":      "chatcmpl-tool",
		"object":  "chat.completion.chunk",
		"created": 1,
		"model":   mockModelID,
		"choices": []map[string]any{{
			"index": 0,
			"delta": map[string]any{
				"role": "assistant",
				"tool_calls": []map[string]any{{
					"index": 0,
					"id":    toolCallID,
					"type":  "function",
					"function": map[string]any{
						"name":      "bash",
						"arguments": `{"description":"Record PTY execution","command":"printf '` + toolResultMarker + `\\n' >> pty-tool-executions.txt && cat pty-tool-executions.txt"}`,
					},
				}},
			},
			"finish_reason": nil,
		}},
	}
	writePTYStreamData(w, first)
	time.Sleep(50 * time.Millisecond)
	finish := map[string]any{
		"id":      "chatcmpl-tool",
		"object":  "chat.completion.chunk",
		"created": 1,
		"model":   mockModelID,
		"choices": []map[string]any{{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": "tool_calls",
		}},
	}
	writePTYStreamData(w, finish)
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	w.(http.Flusher).Flush()
}

func writePTYTextStream(w http.ResponseWriter, content string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	part := map[string]any{
		"id":      "chatcmpl-text",
		"object":  "chat.completion.chunk",
		"created": 1,
		"model":   mockModelID,
		"choices": []map[string]any{{
			"index": 0,
			"delta": map[string]any{
				"role":    "assistant",
				"content": content,
			},
			"finish_reason": nil,
		}},
	}
	writePTYStreamData(w, part)
	finish := map[string]any{
		"id":      "chatcmpl-text",
		"object":  "chat.completion.chunk",
		"created": 1,
		"model":   mockModelID,
		"choices": []map[string]any{{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": "stop",
		}},
	}
	writePTYStreamData(w, finish)
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	w.(http.Flusher).Flush()
}

func writePTYStreamData(w http.ResponseWriter, data any) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return
	}
	_, _ = io.WriteString(w, "data: "+string(encoded)+"\n\n")
	w.(http.Flusher).Flush()
}
