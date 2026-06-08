package handoff

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseJSON_full(t *testing.T) {
	t.Parallel()
	raw := `{
  "handoff_version": 1,
  "from_agent": "security_expert_agent",
  "to_agent": "coder",
  "summary": "Investigation summarized.",
  "touched_paths": ["internal/agent/handoff/handoff.go"],
  "risk_level": "medium",
  "followups": ["Add test."],
  "audit_ref": "trace-1"
}`
	h, err := ParseJSON([]byte(raw))
	require.NoError(t, err)
	require.Equal(t, 1, h.Version)
	require.Equal(t, "security_expert_agent", h.FromAgent)
	require.Equal(t, "coder", h.ToAgent)
	require.Len(t, h.Followups, 1)
}

func TestParseJSON_legacySourceTarget(t *testing.T) {
	t.Parallel()
	raw := `{
  "handoff_version": "1",
  "source_agent": "task",
  "target_agent": "coder",
  "summary": "Plan ready.",
  "touched_paths": ["README.md"],
  "followups": []
}`
	h, err := ParseJSON([]byte(raw))
	require.NoError(t, err)
	require.Equal(t, "task", h.FromAgent)
	require.Equal(t, "coder", h.ToAgent)
}

func TestParseJSON_rejectsTraversal(t *testing.T) {
	t.Parallel()
	raw := `{"handoff_version":1,"from_agent":"ops","to_agent":"coder","summary":"x","touched_paths":["../etc/passwd"],"followups":[]}`
	_, err := ParseJSON([]byte(raw))
	require.Error(t, err)
	require.Contains(t, err.Error(), `..`)
}

func TestParseJSON_requiresToAgent(t *testing.T) {
	t.Parallel()
	raw := `{"handoff_version":1,"from_agent":"ops","summary":"x","followups":[],"touched_paths":[]}`
	_, err := ParseJSON([]byte(raw))
	require.Error(t, err)
	require.Contains(t, err.Error(), "to_agent")
}

func TestExtractFromMarkdown_prefersFirstValid(t *testing.T) {
	t.Parallel()
	md := "intro\n```go\nprintln()\n```\n```crush-handoff\n" +
		`{"handoff_version":1,"from_agent":"ops_agent","to_agent":"coder","summary":"done","followups":[],"touched_paths":[]}` +
		"\n```\n"
	h, err := ExtractFromMarkdown(md)
	require.NoError(t, err)
	require.Equal(t, "ops_agent", h.FromAgent)
}

func TestExtractFromMarkdown_rejectsPlainFence(t *testing.T) {
	t.Parallel()
	// Bare fences are not a recognized handoff namespace and must be ignored
	// to keep the prompt-injection surface scoped.
	md := "```\n" + `{"handoff_version":1,"from_agent":"task","to_agent":"coder","summary":"s","followups":[]}` + "\n```"
	_, err := ExtractFromMarkdown(md)
	require.True(t, errors.Is(err, ErrNoValidHandoff))
}

func TestExtractFromMarkdown_ErrNoValidHandoff(t *testing.T) {
	t.Parallel()
	_, err := ExtractFromMarkdown("no fences")
	require.True(t, errors.Is(err, ErrNoValidHandoff))
}

func TestFenceLanguageRejectsJSON(t *testing.T) {
	t.Parallel()
	// A generic ```json fence is not the dedicated handoff namespace and must
	// not be treated as an injection source.
	md := "```json\n" + `{"handoff_version":1,"from_agent":"coder","to_agent":"planner","summary":"x","followups":[]}` + "\n```"
	_, err := ExtractFromMarkdown(md)
	require.True(t, errors.Is(err, ErrNoValidHandoff))
}

func TestFenceLanguageAllowsHandoff(t *testing.T) {
	t.Parallel()
	md := "```handoff\n" + `{"handoff_version":1,"from_agent":"coder","to_agent":"planner","summary":"x","followups":[]}` + "\n```"
	h, err := ExtractFromMarkdown(md)
	require.NoError(t, err)
	require.Equal(t, "coder", h.FromAgent)
}

func TestFormatForPrompt_wrapsJSON(t *testing.T) {
	t.Parallel()
	h := &Handoff{
		Version:      1,
		FromAgent:    "coder",
		ToAgent:      "planner",
		Summary:      "Ship checklist.",
		TouchedPaths: []string{"README.md"},
		Followups:    []string{"Run tests."},
	}
	require.NoError(t, h.Validate())
	s := FormatForPrompt(h)
	require.Contains(t, s, "<structured_handoff>")
	require.Contains(t, s, "```crush-handoff")
	require.Contains(t, s, "Ship checklist.")
	require.Contains(t, s, "</structured_handoff>")
	require.LessOrEqual(t, len(s), len(h.Summary)+512)
}
