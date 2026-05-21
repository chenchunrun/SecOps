package agent

import (
	"context"
	"strings"

	"github.com/chenchunrun/SecOps/internal/agent/handoff"
	"github.com/chenchunrun/SecOps/internal/message"
)

func handoffConsumeKey(sessionID, assistantMsgID, consumerAgent string) string {
	return sessionID + "\x00" + assistantMsgID + "\x00" + strings.ToLower(strings.TrimSpace(consumerAgent))
}

func (c *coordinator) prependStructuredHandoff(ctx context.Context, sessionID string, prompt string) string {
	if c == nil || strings.TrimSpace(sessionID) == "" || c.messages == nil {
		return prompt
	}

	active := strings.TrimSpace(c.ActiveAgentID())
	if active == "" {
		return prompt
	}

	msgs, err := c.messages.List(ctx, sessionID)
	if err != nil || len(msgs) == 0 {
		return prompt
	}

	var assistant *message.Message
	for i := len(msgs) - 1; i >= 0; i-- {
		msg := msgs[i]
		if msg.Role != message.Assistant || msg.IsSummaryMessage {
			continue
		}
		assistant = &msgs[i]
		break
	}
	if assistant == nil {
		return prompt
	}

	key := handoffConsumeKey(sessionID, assistant.ID, active)

	c.handoffPromptMu.Lock()
	_, consumed := c.handoffConsumed[key]
	c.handoffPromptMu.Unlock()
	if consumed {
		return prompt
	}

	md := assistant.ConcatenateTextContent()
	if strings.TrimSpace(md) == "" {
		return prompt
	}

	h, err := handoff.ExtractFromMarkdown(md)
	if err != nil {
		return prompt
	}

	to := strings.TrimSpace(h.ToAgent)
	if to == "" || !strings.EqualFold(to, active) {
		return prompt
	}

	injection := handoff.FormatForPrompt(h)
	if strings.TrimSpace(injection) == "" {
		return prompt
	}

	c.handoffPromptMu.Lock()
	if c.handoffConsumed == nil {
		c.handoffConsumed = make(map[string]struct{})
	}
	c.handoffConsumed[key] = struct{}{}
	c.handoffPromptMu.Unlock()

	return injection + prompt
}
