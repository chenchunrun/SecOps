package secops

import "testing"

func TestAttackReasonTool_Type(t *testing.T) {
	tool := NewAttackReasonTool(nil)
	if tool.Type() != ToolTypeAttackReason {
		t.Fatalf("expected %v, got %v", ToolTypeAttackReason, tool.Type())
	}
}

func TestAttackReasonTool_ValidateParams(t *testing.T) {
	tool := NewAttackReasonTool(nil)
	if err := tool.ValidateParams(&AttackReasonParams{}); err == nil {
		t.Fatal("expected missing input validation error")
	}
}

func TestAttackReasonTool_Execute(t *testing.T) {
	tool := NewAttackReasonTool(nil)
	result, err := tool.Execute(&AttackReasonParams{
		IncidentID: "INC-ATTACK-001",
		Events: []AttackReasonEvidence{
			{
				ID:        "evt-1",
				Source:    "alert_check",
				EventType: "failed_login_burst",
				Severity:  "HIGH",
				Raw:       "50 failed login attempts against admin account",
			},
			{
				ID:        "evt-2",
				Source:    "incident_timeline",
				EventType: "successful_login_after_failures",
				Severity:  "HIGH",
				Raw:       "successful login after failures from suspicious IP",
			},
		},
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	out, ok := result.(*AttackReasonResult)
	if !ok {
		t.Fatalf("expected *AttackReasonResult, got %T", result)
	}
	if len(out.Assessment.Techniques) == 0 {
		t.Fatal("expected at least one ATT&CK technique")
	}
	if out.Assessment.Techniques[0].TechniqueID == "" {
		t.Fatal("expected top technique id")
	}
}

func TestAttackReasonTool_ExecuteWithSecOpsResults(t *testing.T) {
	tool := NewAttackReasonTool(nil)
	result, err := tool.Execute(&AttackReasonParams{
		IncidentID: "INC-ATTACK-002",
		AlertResult: &AlertCheckResult{
			System: "prometheus",
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
		AccessReviewResult: &AccessReviewResult{
			Entries: []AccessEntry{
				{
					Principal:  "user:admin@example.com",
					Permission: "iam:*",
					Resource:   "*",
					Risk:       "high",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	out, ok := result.(*AttackReasonResult)
	if !ok {
		t.Fatalf("expected *AttackReasonResult, got %T", result)
	}
	if len(out.Assessment.Techniques) == 0 {
		t.Fatal("expected ATT&CK techniques from secops result normalization")
	}
}
