package orchestrator

import (
	"context"
	"testing"

	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/agent"
	"github.com/chenchunrun/SecOps/internal/message"
	"github.com/stretchr/testify/require"
)

type mockCoordinator struct {
	runSessionID string
	runPrompt    string
	runCalled    bool
	cancelled    string
	cancelAll    bool
	busy         bool
	queue        []string
	model        agent.Model
}

func (m *mockCoordinator) Run(ctx context.Context, sessionID, prompt string, attachments ...message.Attachment) (*fantasy.AgentResult, error) {
	m.runCalled = true
	m.runSessionID = sessionID
	m.runPrompt = prompt
	return &fantasy.AgentResult{}, nil
}

func (m *mockCoordinator) ActiveAgentID() string   { return "coder" }
func (m *mockCoordinator) Cancel(sessionID string) { m.cancelled = sessionID }
func (m *mockCoordinator) CancelAll()              { m.cancelAll = true }
func (m *mockCoordinator) IsSessionBusy(sessionID string) bool {
	return m.busy && sessionID == "busy-session"
}
func (m *mockCoordinator) IsBusy() bool                       { return m.busy }
func (m *mockCoordinator) QueuedPrompts(sessionID string) int { return len(m.queue) }
func (m *mockCoordinator) QueuedPromptsList(sessionID string) []string {
	return append([]string(nil), m.queue...)
}
func (m *mockCoordinator) ClearQueue(sessionID string)             { m.queue = nil }
func (m *mockCoordinator) Summarize(context.Context, string) error { return nil }
func (m *mockCoordinator) Model() agent.Model                      { return m.model }
func (m *mockCoordinator) UpdateModels(context.Context) error      { return nil }

func TestTurnOrchestratorDelegatesRun(t *testing.T) {
	t.Parallel()

	coord := &mockCoordinator{}
	orchestrator := NewTurnOrchestrator(coord)

	_, err := orchestrator.Run(context.Background(), "sess-1", "hello")
	require.NoError(t, err)
	require.True(t, coord.runCalled)
	require.Equal(t, "sess-1", coord.runSessionID)
	require.Equal(t, "hello", coord.runPrompt)
}

func TestTurnOrchestratorDelegatesControlMethods(t *testing.T) {
	t.Parallel()

	coord := &mockCoordinator{
		busy:  true,
		queue: []string{"a", "b"},
	}
	orchestrator := NewTurnOrchestrator(coord)

	require.Equal(t, "coder", orchestrator.ActiveAgentID())
	require.True(t, orchestrator.IsBusy())
	require.True(t, orchestrator.IsSessionBusy("busy-session"))
	require.Equal(t, 2, orchestrator.QueuedPrompts("busy-session"))
	require.Equal(t, []string{"a", "b"}, orchestrator.QueuedPromptsList("busy-session"))

	orchestrator.Cancel("busy-session")
	require.Equal(t, "busy-session", coord.cancelled)

	orchestrator.ClearQueue("busy-session")
	require.Empty(t, coord.queue)

	orchestrator.CancelAll()
	require.True(t, coord.cancelAll)
}
