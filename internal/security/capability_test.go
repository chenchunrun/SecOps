package security

import (
	"testing"
)

func TestCheckCapability_Ops(t *testing.T) {
	tests := []struct {
		name       string
		role       string
		capability string
		expected   bool
	}{
		// Viewer role tests
		{"viewer can read logs", "viewer", "log:read", true},
		{"viewer can query monitoring", "viewer", "monitoring:query", true},
		{"viewer cannot analyze logs", "viewer", "log:analyze", false},
		{"viewer cannot process:kill", "viewer", "process:kill", false},
		{"viewer cannot shell:read-write", "viewer", "shell:read-write", false},

		// Operator role tests
		{"operator can analyze logs", "operator", "log:analyze", true},
		{"operator can query processes", "operator", "process:query", true},
		{"operator can kill processes", "operator", "process:kill", true},
		{"operator can network:diagnose", "operator", "network:diagnose", true},
		{"operator can shell:read-only", "operator", "shell:read-only", true},
		{"operator can log:export", "operator", "log:export", false},

		// Admin role tests
		{"admin can export logs", "admin", "log:export", true},
		{"admin can file:write", "admin", "file:write", true},
		{"admin can shell:read-write", "admin", "shell:read-write", true},
		{"admin can compliance:check", "admin", "compliance:check", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckCapability(tt.role, tt.capability)
			if result != tt.expected {
				t.Errorf("CheckCapability(%q, %q) = %v, want %v", tt.role, tt.capability, result, tt.expected)
			}
		})
	}
}

func TestCheckCapability_Security(t *testing.T) {
	tests := []struct {
		name       string
		role       string
		capability string
		expected   bool
	}{
		// Analyst role tests
		{"analyst can security:scan", "analyst", "security:scan", true},
		{"analyst can security:audit", "analyst", "security:audit", true},
		{"analyst can security:analyze", "analyst", "security:analyze", true},
		{"analyst can compliance:report", "analyst", "compliance:report", true},
		{"analyst cannot network:scan", "analyst", "network:scan", false},
		{"analyst cannot process:kill", "analyst", "process:kill", false},

		// Responder role tests
		{"responder can network:scan", "responder", "network:scan", true},
		{"responder can process:kill", "responder", "process:kill", true},
		{"responder can file:delete", "responder", "file:delete", true},
		{"responder can compliance:check", "responder", "compliance:check", true},
		{"responder can security:incident", "responder", "security:incident", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckCapability(tt.role, tt.capability)
			if result != tt.expected {
				t.Errorf("CheckCapability(%q, %q) = %v, want %v", tt.role, tt.capability, result, tt.expected)
			}
		})
	}
}

func TestGetCapabilitiesForRole(t *testing.T) {
	caps := GetCapabilitiesForRole("viewer")
	if len(caps) == 0 {
		t.Error("expected viewer to have capabilities, got none")
	}
	for _, cap := range caps {
		if cap.RequiredRole != "viewer" && cap.RequiredRole != "" {
			t.Errorf("viewer should only have viewer or no-role capabilities, got %q", cap.RequiredRole)
		}
	}

	caps = GetCapabilitiesForRole("admin")
	if len(caps) == 0 {
		t.Error("expected admin to have capabilities, got none")
	}

	caps = GetCapabilitiesForRole("analyst")
	if len(caps) == 0 {
		t.Error("expected analyst to have capabilities, got none")
	}

	caps = GetCapabilitiesForRole("unknown")
	if len(caps) != 0 {
		t.Errorf("expected unknown role to have no capabilities, got %d", len(caps))
	}
}

func TestRiskAssessor_AssessPermissionRequest(t *testing.T) {
	ra := NewRiskAssessor()

	tests := []struct {
		name          string
		toolName      string
		resourcePath  string
		expectedLevel RiskLevel
		minScore      int
	}{
		{
			name:          "safe tool with safe path",
			toolName:      "cat",
			resourcePath:  "/var/tmp/file.txt",
			expectedLevel: RiskLevelLow,
			minScore:      0,
		},
		{
			name:          "banned tool",
			toolName:      "rm -rf /",
			resourcePath:  "/tmp",
			expectedLevel: RiskLevelMedium,
			minScore:      40,
		},
		{
			name:          "tool accessing critical resource",
			toolName:      "ls",
			resourcePath:  "/etc",
			expectedLevel: RiskLevelLow,
			minScore:      20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ra.AssessPermissionRequest(tt.toolName, tt.resourcePath)
			if result.Score < tt.minScore {
				t.Errorf("expected score >= %d, got %d", tt.minScore, result.Score)
			}
			if result.Level != tt.expectedLevel {
				t.Errorf("expected level %s, got %s", tt.expectedLevel, result.Level)
			}
		})
	}
}
