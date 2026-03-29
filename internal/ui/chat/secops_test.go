package chat

import (
	"strings"
	"testing"

	"github.com/chenchunrun/SecOps/internal/message"
	"github.com/chenchunrun/SecOps/internal/ui/styles"
)

func TestSummarizeIncidentAssessResult(t *testing.T) {
	content := `{
  "incident_id": "inc-1",
  "platform": "linux",
  "executive_summary": "Top ATT&CK assessment is T1078 (Valid Accounts) with confidence 0.82.",
  "evidence_summary": ["Alerts: 3 total from auth-service.", "Logs: 12 filtered entries from 200 total."],
  "containment_advice": ["Enforce MFA immediately.", "Restrict suspicious IPs."],
  "attack_assessment": {
    "assessment": {
      "tactics": ["Credential Access", "Initial Access"],
      "techniques": [
        {"technique_id": "T1078", "name": "Valid Accounts", "confidence": 0.82}
      ],
      "next_actions": ["Review session activity."]
    }
  }
}`

	summary, pretty, err := summarizeIncidentAssessResult(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(summary, "Executive Summary:") || !strings.Contains(summary, "Top Technique: T1078") {
		t.Fatalf("unexpected summary: %q", summary)
	}
	if !strings.Contains(pretty, `"incident_id": "inc-1"`) {
		t.Fatalf("unexpected pretty json: %q", pretty)
	}
}

func TestSummarizeAttackReasonResult(t *testing.T) {
	content := `{
  "incident_id": "inc-2",
  "platform": "linux",
  "assessment": {
    "summary": "Most likely attacker path starts with valid account abuse.",
    "tactics": ["Credential Access"],
    "techniques": [
      {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "confidence": 0.77,
        "reasons": ["successful login after failures", "anomalous source IP"]
      }
    ],
    "next_actions": ["Reset affected credentials."]
  }
}`

	summary, pretty, err := summarizeAttackReasonResult(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(summary, "Assessment:") || !strings.Contains(summary, "Why: successful login after failures") {
		t.Fatalf("unexpected summary: %q", summary)
	}
	if !strings.Contains(pretty, `"technique_id": "T1078"`) {
		t.Fatalf("unexpected pretty json: %q", pretty)
	}
}

func TestNewToolMessageItem_UsesSecOpsRenderer(t *testing.T) {
	sty := styles.DefaultStyles()
	toolCall := message.ToolCall{
		ID:       "tool-1",
		Name:     "incident_assess",
		Input:    `{"incident_id":"inc-1"}`,
		Finished: true,
	}
	result := &message.ToolResult{
		ToolCallID: "tool-1",
		Name:       "incident_assess",
		Content: `{
  "incident_id": "inc-1",
  "executive_summary": "Top ATT&CK assessment is T1078 (Valid Accounts) with confidence 0.82.",
  "evidence_summary": ["Alerts: 3 total from auth-service."],
  "containment_advice": ["Enforce MFA immediately."],
  "attack_assessment": {
    "assessment": {
      "tactics": ["Credential Access"],
      "techniques": [
        {"technique_id": "T1078", "name": "Valid Accounts", "confidence": 0.82}
      ]
    }
  }
}`,
	}

	item := NewToolMessageItem(&sty, "msg-1", toolCall, result, false)
	rendered := item.Render(100)
	if !strings.Contains(rendered, "Incident Assess") {
		t.Fatalf("expected secops header, got %q", rendered)
	}
	if !strings.Contains(rendered, "Top Technique: T1078") {
		t.Fatalf("expected summarized secops output, got %q", rendered)
	}
	if strings.Contains(rendered, `"incident_id": "inc-1"`) {
		t.Fatalf("expected collapsed secops renderer to hide pretty JSON by default, got %q", rendered)
	}
}

func TestExtractMessageItems_SecOpsToolSessionFlow(t *testing.T) {
	sty := styles.DefaultStyles()

	assistantMsg := &message.Message{
		ID:   "assistant-1",
		Role: message.Assistant,
	}
	assistantMsg.SetToolCalls([]message.ToolCall{
		{
			ID:       "tool-incident-1",
			Name:     "incident_assess",
			Input:    `{"incident_id":"inc-session-1"}`,
			Finished: true,
		},
	})
	assistantMsg.AddFinish(message.FinishReasonToolUse, "", "")

	toolMsg := &message.Message{
		ID:   "tool-msg-1",
		Role: message.Tool,
	}
	toolMsg.SetToolResults([]message.ToolResult{
		{
			ToolCallID: "tool-incident-1",
			Name:       "incident_assess",
			Content: `{
  "incident_id": "inc-session-1",
  "executive_summary": "Top ATT&CK assessment is T1078 (Valid Accounts) with confidence 0.82.",
  "evidence_summary": ["Alerts: 3 total from auth-service."],
  "containment_advice": ["Enforce MFA immediately."],
  "attack_assessment": {
    "assessment": {
      "tactics": ["Credential Access"],
      "techniques": [
        {"technique_id": "T1078", "name": "Valid Accounts", "confidence": 0.82}
      ]
    }
  }
}`,
		},
	})

	toolResults := BuildToolResultMap([]*message.Message{toolMsg})
	items := ExtractMessageItems(&sty, assistantMsg, toolResults, false)
	if len(items) != 1 {
		t.Fatalf("expected 1 tool item, got %d", len(items))
	}

	rendered := items[0].Render(100)
	if !strings.Contains(rendered, "Incident Assess") {
		t.Fatalf("expected incident assess renderer in session flow, got %q", rendered)
	}
	if !strings.Contains(rendered, "Executive Summary:") {
		t.Fatalf("expected summarized secops content in session flow, got %q", rendered)
	}
	if strings.Contains(rendered, `"incident_id": "inc-session-1"`) {
		t.Fatalf("expected collapsed session flow to hide raw JSON by default, got %q", rendered)
	}
}
