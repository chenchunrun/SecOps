package agent

import (
	"strings"

	"github.com/chenchunrun/SecOps/internal/agent/handoff"
	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/message"
)

// pendingHandoffFromMessages returns the newest valid handoff embedded in an
// assistant message that appears strictly after the last user message in msgs.
// Msgs must be chronological (oldest first), loaded before the current user
// turn is persisted. The second return value is the assistant message ID that
// contained the handoff, or empty when err is non-nil.
func pendingHandoffFromMessages(msgs []message.Message, consumerAgentID string) (*handoff.Handoff, string, error) {
	lastUser := lastUserMessageIndex(msgs)
	if lastUser < 0 {
		return nil, "", handoff.ErrNoValidHandoff
	}
	for i := len(msgs) - 1; i > lastUser; i-- {
		m := msgs[i]
		if m.Role != message.Assistant {
			continue
		}
		body := m.ConcatenateTextContent()
		if body == "" {
			continue
		}
		h, err := handoff.ExtractFromMarkdown(body)
		if err != nil {
			continue
		}
		if !handoffMatchesConsumer(h.ToAgent, consumerAgentID) {
			continue
		}
		return h, m.ID, nil
	}
	return nil, "", handoff.ErrNoValidHandoff
}

func recordHandoffInjected(sessionID, consumerAgentID, sourceMessageID string, h *handoff.Handoff) {
	if h == nil || sessionID == "" {
		return
	}
	ev := audit.NewAuditEventBuilder(audit.EventTypeAgentHandoffConsumed).
		WithSession(sessionID).
		WithAction("inject_structured_handoff_prompt_prefix").
		WithResource("crush_handoff", h.FromAgent, "").
		WithResult(audit.ResultSuccess).
		WithDetail("handoff_version", h.Version).
		WithDetail("consumer_agent_id", consumerAgentID).
		WithDetail("from_agent", h.FromAgent).
		WithDetail("to_agent", h.ToAgent).
		WithDetail("source_assistant_message_id", sourceMessageID).
		WithDetail("handoff_audit_ref", h.AuditRef).
		WithDetail("risk_level", h.RiskLevel).
		WithDetail("touched_paths_count", len(h.TouchedPaths)).
		WithDetail("followups_count", len(h.Followups)).
		Build()
	_ = audit.RecordGlobal(ev)
}

func lastUserMessageIndex(msgs []message.Message) int {
	last := -1
	for i := range msgs {
		if msgs[i].Role == message.User {
			last = i
		}
	}
	return last
}

func handoffMatchesConsumer(toAgent, consumer string) bool {
	toAgent = strings.TrimSpace(strings.ToLower(toAgent))
	consumer = strings.TrimSpace(strings.ToLower(consumer))
	if consumer == "" {
		return true
	}
	if toAgent == "" {
		return true
	}
	return toAgent == consumer
}
