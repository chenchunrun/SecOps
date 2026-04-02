package orchestrator

import (
	"context"

	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/agent"
	"github.com/chenchunrun/SecOps/internal/message"
)

// TurnOrchestrator is a thin compatibility shell around the existing
// coordinator. It fixes a stable orchestration entrypoint without changing the
// current run loop behavior.
type TurnOrchestrator struct {
	coordinator agent.Coordinator
}

func NewTurnOrchestrator(coordinator agent.Coordinator) *TurnOrchestrator {
	return &TurnOrchestrator{coordinator: coordinator}
}

func (o *TurnOrchestrator) Run(ctx context.Context, sessionID, prompt string, attachments ...message.Attachment) (*fantasy.AgentResult, error) {
	return o.coordinator.Run(ctx, sessionID, prompt, attachments...)
}

func (o *TurnOrchestrator) ActiveAgentID() string {
	return o.coordinator.ActiveAgentID()
}

func (o *TurnOrchestrator) Cancel(sessionID string) {
	o.coordinator.Cancel(sessionID)
}

func (o *TurnOrchestrator) CancelAll() {
	o.coordinator.CancelAll()
}

func (o *TurnOrchestrator) IsSessionBusy(sessionID string) bool {
	return o.coordinator.IsSessionBusy(sessionID)
}

func (o *TurnOrchestrator) IsBusy() bool {
	return o.coordinator.IsBusy()
}

func (o *TurnOrchestrator) QueuedPrompts(sessionID string) int {
	return o.coordinator.QueuedPrompts(sessionID)
}

func (o *TurnOrchestrator) QueuedPromptsList(sessionID string) []string {
	return o.coordinator.QueuedPromptsList(sessionID)
}

func (o *TurnOrchestrator) ClearQueue(sessionID string) {
	o.coordinator.ClearQueue(sessionID)
}

func (o *TurnOrchestrator) Summarize(ctx context.Context, sessionID string) error {
	return o.coordinator.Summarize(ctx, sessionID)
}

func (o *TurnOrchestrator) Model() agent.Model {
	return o.coordinator.Model()
}

func (o *TurnOrchestrator) UpdateModels(ctx context.Context) error {
	return o.coordinator.UpdateModels(ctx)
}
