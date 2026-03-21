package permission

import (
	"sync"
	"testing"
	"time"
)

func TestNewDefaultService(t *testing.T) {
	svc := NewDefaultService()
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestDefaultService_Request_Nil(t *testing.T) {
	svc := NewDefaultService()
	err := svc.Request(nil)
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestDefaultService_Request_MissingFields(t *testing.T) {
	svc := NewDefaultService()

	// Missing session ID
	err := svc.Request(&PermissionRequest{ToolName: "test"})
	if err == nil {
		t.Error("expected error for missing session_id")
	}

	// Missing tool name
	err = svc.Request(&PermissionRequest{SessionID: "sess-1"})
	if err == nil {
		t.Error("expected error for missing tool_name")
	}
}

func TestDefaultService_Request_LowRisk(t *testing.T) {
	svc := NewDefaultService()

	req := &PermissionRequest{
		SessionID: "sess-1",
		ToolName:  "log_analyzer",
		Action:    "read",
		ResourceType: ResourceTypeFile,
		ResourcePath: "/var/log/syslog",
	}

	err := svc.Request(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Low risk should be auto-approved
	if req.Decision != DecisionAutoApprove {
		t.Errorf("expected auto_approve for low risk, got %s (score=%d)", req.Decision, req.RiskScore)
	}
}

func TestDefaultService_Request_HighRisk(t *testing.T) {
	svc := NewDefaultService()

	req := &PermissionRequest{
		SessionID:    "sess-1",
		ToolName:     "shell",
		Action:       "delete",
		ResourceType: ResourceTypeSystem,
		ResourcePath: "/etc/shadow",
	}

	err := svc.Request(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// High risk should NOT be auto-approved
	if req.Decision == DecisionAutoApprove {
		t.Errorf("expected non-auto-approve for high risk, got auto_approve (score=%d)", req.RiskScore)
	}
}

func TestDefaultService_Check(t *testing.T) {
	svc := NewDefaultService()

	// Check non-existent permission
	allowed, err := svc.Check("sess-1", "tool-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("expected permission to not exist")
	}

	// Request a low-risk permission (should auto-approve)
	req := &PermissionRequest{
		SessionID:    "sess-1",
		ToolName:     "tool-1",
		Action:       "read",
		ResourceType: ResourceTypeFile,
		ResourcePath: "/tmp/test",
	}
	_ = svc.Request(req)

	// Now check should pass
	allowed, err = svc.Check("sess-1", "tool-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("expected permission to be granted after low-risk request")
	}
}

func TestDefaultService_Check_EmptyArgs(t *testing.T) {
	svc := NewDefaultService()

	_, err := svc.Check("", "tool")
	if err == nil {
		t.Error("expected error for empty sessionID")
	}

	_, err = svc.Check("sess", "")
	if err == nil {
		t.Error("expected error for empty toolName")
	}
}

func TestDefaultService_CheckCapability(t *testing.T) {
	svc := NewDefaultService()

	// Check non-existent capability
	has, err := svc.CheckCapability("user-1", "file:read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Error("expected user to not have capability")
	}

	// Grant capability
	svc.GrantCapability("user-1", "file:read")

	// Now check should pass
	has, err = svc.CheckCapability("user-1", "file:read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has {
		t.Error("expected user to have capability after grant")
	}

	// Revoke capability
	svc.RevokeCapability("user-1", "file:read")

	has, err = svc.CheckCapability("user-1", "file:read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Error("expected user to not have capability after revoke")
	}
}

func TestDefaultService_EvaluateRisk(t *testing.T) {
	svc := NewDefaultService()

	tests := []struct {
		name        string
		req         *PermissionRequest
		minScore    int
		maxSeverity Severity
	}{
		{
			name: "low risk read",
			req: &PermissionRequest{
				Action:       "read",
				ResourceType: ResourceTypeFile,
				ResourcePath: "/tmp/test",
			},
			minScore:    0,
			maxSeverity: SeverityLow,
		},
		{
			name: "high risk delete system",
			req: &PermissionRequest{
				Action:       "delete",
				ResourceType: ResourceTypeSystem,
				ResourcePath: "/etc/shadow",
			},
			minScore: 60,
		},
		{
			name: "medium risk write database",
			req: &PermissionRequest{
				Action:       "write",
				ResourceType: ResourceTypeDatabase,
			},
			minScore: 40,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, _, err := svc.EvaluateRisk(tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if score < tt.minScore {
				t.Errorf("expected score >= %d, got %d", tt.minScore, score)
			}
		})
	}
}

func TestDefaultService_MakeDecision(t *testing.T) {
	svc := NewDefaultService()

	tests := []struct {
		name     string
		score    int
		expected PermissionDecision
	}{
		{"deny high risk", 85, DecisionDeny},
		{"admin review", 65, DecisionAdminReview},
		{"user confirm", 45, DecisionUserConfirm},
		{"auto approve", 10, DecisionAutoApprove},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &PermissionRequest{RiskScore: tt.score}
			decision, err := svc.MakeDecision(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, decision)
			}
		})
	}
}

func TestDefaultService_AuditLog(t *testing.T) {
	svc := NewDefaultService()

	req := &PermissionRequest{
		SessionID: "sess-1",
		ToolName:  "test",
	}

	err := svc.AuditLog(req, DecisionAutoApprove)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	logs := svc.GetAuditLog()
	if len(logs) != 1 {
		t.Errorf("expected 1 audit log, got %d", len(logs))
	}
}

func TestDefaultService_AuditLog_Nil(t *testing.T) {
	svc := NewDefaultService()
	err := svc.AuditLog(nil, DecisionDeny)
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestDefaultService_Concurrent(t *testing.T) {
	svc := NewDefaultService()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			req := &PermissionRequest{
				SessionID:    "sess-concurrent",
				ToolName:     "tool",
				Action:       "read",
				ResourceType: ResourceTypeFile,
				ResourcePath: "/tmp/test",
				RequestTime:  time.Now(),
			}

			_ = svc.Request(req)
			_, _ = svc.Check("sess-concurrent", "tool")
			svc.GrantCapability("user-1", "test:cap")
			_, _ = svc.CheckCapability("user-1", "test:cap")
		}(i)
	}

	wg.Wait()
}
