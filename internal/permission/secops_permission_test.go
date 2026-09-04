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

func TestDefaultService_SessionCapabilityLifecycle(t *testing.T) {
	t.Parallel()
	svc := NewDefaultService()
	now := time.Now().UTC()
	grant := CapabilityGrant{
		SessionID:       "session-1",
		Subject:         "analyst",
		Capability:      "network:scan",
		Target:          "*.example.com",
		AuthorizationID: "auth-1",
		GrantedBy:       "tester",
		GrantedAt:       now,
		ExpiresAt:       now.Add(time.Hour),
	}
	if err := svc.GrantSessionCapability(grant); err != nil {
		t.Fatalf("grant session capability: %v", err)
	}
	resolved, ok := svc.FindSessionCapability("session-1", "analyst", "network:scan", "api.example.com")
	if !ok || resolved.AuthorizationID != "auth-1" {
		t.Fatalf("unexpected resolved grant: %#v, ok=%v", resolved, ok)
	}
	if _, ok := svc.FindSessionCapability("session-2", "analyst", "network:scan", "api.example.com"); ok {
		t.Fatal("grant leaked into another session")
	}
	if _, ok := svc.FindSessionCapability("session-1", "analyst", "network:scan", "example.com"); ok {
		t.Fatal("wildcard scope must not include the apex domain")
	}
	removed := svc.RevokeSessionCapability("session-1", "analyst", "network:scan", "")
	if len(removed) != 1 || len(svc.ListSessionCapabilities("session-1", "analyst")) != 0 {
		t.Fatalf("unexpected revoke result: %#v", removed)
	}
}

func TestDefaultService_SessionCapabilityNormalizesTargetsAndSupportsCIDR(t *testing.T) {
	t.Parallel()
	svc := NewDefaultService()
	now := time.Now().UTC()
	for _, target := range []string{"https://API.EXAMPLE.COM:443/path", "10.20.0.0/16"} {
		err := svc.GrantSessionCapability(CapabilityGrant{
			SessionID:  "session-1",
			Subject:    "analyst",
			Capability: "network:scan",
			Target:     target,
			GrantedBy:  "tester",
			GrantedAt:  now,
			ExpiresAt:  now.Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("grant target %q: %v", target, err)
		}
	}
	if _, ok := svc.FindSessionCapability("session-1", "analyst", "network:scan", "api.example.com"); !ok {
		t.Fatal("expected URL target to match its normalized hostname")
	}
	if _, ok := svc.FindSessionCapability("session-1", "analyst", "network:scan", "10.20.8.9"); !ok {
		t.Fatal("expected address inside CIDR scope to match")
	}
	if _, ok := svc.FindSessionCapability("session-1", "analyst", "network:scan", "10.21.8.9"); ok {
		t.Fatal("address outside CIDR scope matched")
	}
}

func TestDefaultService_SessionCapabilityRejectsUnboundedTarget(t *testing.T) {
	t.Parallel()
	svc := NewDefaultService()
	err := svc.GrantSessionCapability(CapabilityGrant{
		SessionID:  "session-1",
		Subject:    "analyst",
		Capability: "network:scan",
		Target:     "*",
		GrantedBy:  "tester",
		GrantedAt:  time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
	})
	if err == nil {
		t.Fatal("expected unbounded target to be rejected")
	}
}

func TestDefaultService_SessionCapabilityExpires(t *testing.T) {
	t.Parallel()
	svc := NewDefaultService()
	err := svc.GrantSessionCapability(CapabilityGrant{
		SessionID:  "session-1",
		Subject:    "analyst",
		Capability: "network:scan",
		Target:     "127.0.0.1",
		GrantedBy:  "tester",
		GrantedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt:  time.Now().Add(-time.Hour),
	})
	if err == nil {
		t.Fatal("expected an already expired grant to be rejected")
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
		SessionID:    "sess-1",
		ToolName:     "log_analyzer",
		Action:       "read",
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
