package secops

import "testing"

func TestIncidentAssessTool_Type(t *testing.T) {
	tool := NewIncidentAssessTool(nil)
	if tool.Type() != ToolTypeIncidentAssess {
		t.Fatalf("expected %v, got %v", ToolTypeIncidentAssess, tool.Type())
	}
}

func TestIncidentAssessTool_Execute(t *testing.T) {
	tool := NewIncidentAssessTool(nil)
	result, err := tool.Execute(&IncidentAssessParams{
		IncidentID: "INC-ASSESS-001",
		AlertResult: &AlertCheckResult{
			System: "prometheus",
			Total:  1,
			Alerts: []AlertInfo{
				{
					ID:       "alert-1",
					Name:     "Brute force attempt",
					Status:   "firing",
					Severity: "critical",
					Message:  "50 failed login attempts against admin account",
				},
			},
		},
		TimelineResult: &IncidentTimelineResult{
			IncidentID: "INC-ASSESS-001",
			Events: []TimelineEvent{
				{
					Type:        "escalation",
					Actor:       "soc",
					Description: "Escalated to security team after suspicious login",
					Severity:    "high",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	out, ok := result.(*IncidentAssessResult)
	if !ok {
		t.Fatalf("expected *IncidentAssessResult, got %T", result)
	}
	if out.ExecutiveSummary == "" {
		t.Fatal("expected executive summary")
	}
	if len(out.AttackAssessment.Assessment.Techniques) == 0 {
		t.Fatal("expected ATT&CK assessment techniques")
	}
	if len(out.ContainmentAdvice) == 0 {
		t.Fatal("expected containment advice")
	}
}
