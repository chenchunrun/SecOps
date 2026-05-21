package agent

import (
	"errors"
	"testing"

	"github.com/chenchunrun/SecOps/internal/agent/handoff"
	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/message"
	"github.com/stretchr/testify/require"
)

func TestPendingHandoffFromMessages_suffixOnly(t *testing.T) {
	t.Parallel()
	oldFence := "```crush-handoff\n" +
		`{"handoff_version":1,"from_agent":"task","to_agent":"coder","summary":"old","followups":[],"touched_paths":[]}` +
		"\n```\n"
	newFence := "```crush-handoff\n" +
		`{"handoff_version":1,"from_agent":"planner","to_agent":"coder","summary":"new","followups":[],"touched_paths":[]}` +
		"\n```\n"
	msgs := []message.Message{
		{Role: message.User, Parts: []message.ContentPart{message.TextContent{Text: "first"}}},
		{ID: "a-old", Role: message.Assistant, Parts: []message.ContentPart{message.TextContent{Text: oldFence}}},
		{Role: message.User, Parts: []message.ContentPart{message.TextContent{Text: "second"}}},
		{ID: "a-new", Role: message.Assistant, Parts: []message.ContentPart{message.TextContent{Text: newFence}}},
	}
	h, srcID, err := pendingHandoffFromMessages(msgs, "coder")
	require.NoError(t, err)
	require.Equal(t, "a-new", srcID)
	require.Equal(t, "new", h.Summary)
	require.Equal(t, "planner", h.FromAgent)
}

func TestPendingHandoffFromMessages_ignoresBeforeLastUser(t *testing.T) {
	t.Parallel()
	fence := "```crush-handoff\n" +
		`{"handoff_version":1,"from_agent":"task","to_agent":"coder","summary":"only-in-old-turn","followups":[],"touched_paths":[]}` +
		"\n```\n"
	msgs := []message.Message{
		{Role: message.User, Parts: []message.ContentPart{message.TextContent{Text: "first"}}},
		{Role: message.Assistant, Parts: []message.ContentPart{message.TextContent{Text: fence}}},
		{Role: message.User, Parts: []message.ContentPart{message.TextContent{Text: "second"}}},
	}
	_, _, err := pendingHandoffFromMessages(msgs, "coder")
	require.True(t, errors.Is(err, handoff.ErrNoValidHandoff))
}

func TestPendingHandoffFromMessages_toAgentFilter(t *testing.T) {
	t.Parallel()
	fence := "```crush-handoff\n" +
		`{"handoff_version":1,"from_agent":"task","to_agent":"coder","summary":"x","followups":[],"touched_paths":[]}` +
		"\n```\n"
	msgs := []message.Message{
		{Role: message.User, Parts: []message.ContentPart{message.TextContent{Text: "u"}}},
		{Role: message.Assistant, Parts: []message.ContentPart{message.TextContent{Text: fence}}},
	}
	_, _, err := pendingHandoffFromMessages(msgs, "ops_agent")
	require.True(t, errors.Is(err, handoff.ErrNoValidHandoff))
}

func TestPendingHandoffFromMessages_noUserRole(t *testing.T) {
	t.Parallel()
	fence := "```crush-handoff\n" +
		`{"handoff_version":1,"from_agent":"task","summary":"x","followups":[],"touched_paths":[]}` +
		"\n```\n"
	msgs := []message.Message{
		{Role: message.Assistant, Parts: []message.ContentPart{message.TextContent{Text: fence}}},
	}
	_, _, err := pendingHandoffFromMessages(msgs, "coder")
	require.True(t, errors.Is(err, handoff.ErrNoValidHandoff))
}

func TestRecordHandoffInjected_writesAuditEvent(t *testing.T) {
	// Uses process-wide audit store; keep serial to avoid parallel test races.
	store := audit.NewInMemoryAuditStore()
	audit.SetGlobalStore(store)
	t.Cleanup(func() { audit.SetGlobalStore(audit.NewInMemoryAuditStore()) })

	raw := `{"handoff_version":1,"from_agent":"planner","to_agent":"coder","summary":"Ship it.","followups":[],"touched_paths":["README.md"],"risk_level":"low","audit_ref":"ref-99"}`
	h, err := handoff.ParseJSON([]byte(raw))
	require.NoError(t, err)

	recordHandoffInjected("sess-handoff-test", "coder", "asst-src-1", h)

	got, listErr := store.ListEvents(&audit.AuditFilter{SessionID: "sess-handoff-test"})
	require.NoError(t, listErr)
	require.Len(t, got, 1)
	require.Equal(t, audit.EventTypeAgentHandoffConsumed, got[0].EventType)
	require.Equal(t, "inject_structured_handoff_prompt_prefix", got[0].Action)
	require.Equal(t, "coder", got[0].Details["consumer_agent_id"])
	require.Equal(t, 1, got[0].Details["handoff_version"])
	require.Equal(t, "asst-src-1", got[0].Details["source_assistant_message_id"])
	require.Equal(t, "ref-99", got[0].Details["handoff_audit_ref"])
}
