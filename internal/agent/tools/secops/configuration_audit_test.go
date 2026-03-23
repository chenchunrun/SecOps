package secops

import (
	"testing"
)

func TestConfigurationAuditTool_Type(t *testing.T) {
	tool := NewConfigurationAuditTool(nil)
	if tool.Type() != ToolTypeConfigurationAudit {
		t.Errorf("expected %v, got %v", ToolTypeConfigurationAudit, tool.Type())
	}
}

func TestConfigurationAuditTool_ValidateParams(t *testing.T) {
	tool := NewConfigurationAuditTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name:    "valid SSH target",
			params:  &ConfigAuditParams{Targets: []ConfigAuditTarget{ConfigSSH}},
			wantErr: false,
		},
		{
			name:    "valid sudo target",
			params:  &ConfigAuditParams{Targets: []ConfigAuditTarget{ConfigSudo}},
			wantErr: false,
		},
		{
			name:    "multiple targets",
			params:  &ConfigAuditParams{Targets: []ConfigAuditTarget{ConfigSSH, ConfigSudo, ConfigFirewall}},
			wantErr: false,
		},
		{
			name:    "missing targets",
			params:  &ConfigAuditParams{},
			wantErr: true,
		},
		{
			name:    "invalid target",
			params:  &ConfigAuditParams{Targets: []ConfigAuditTarget{ConfigAuditTarget("invalid")}},
			wantErr: true,
		},
		{
			name:    "invalid type",
			params:  "invalid",
			wantErr: true,
		},
		{
			name: "invalid remote port",
			params: &ConfigAuditParams{
				Targets:    []ConfigAuditTarget{ConfigSSH},
				RemoteHost: "10.0.0.2",
				RemotePort: 70000,
			},
			wantErr: true,
		},
		{
			name: "remote user without remote host",
			params: &ConfigAuditParams{
				Targets:    []ConfigAuditTarget{ConfigSSH},
				RemoteUser: "ops",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tool.ValidateParams(tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigurationAuditTool_Execute(t *testing.T) {
	tool := NewConfigurationAuditTool(nil)

	params := &ConfigAuditParams{
		Targets:       []ConfigAuditTarget{ConfigSSH},
		CheckSecurity: true,
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	auditResult, ok := result.(*ConfigAuditResult)
	if !ok {
		t.Fatal("expected ConfigAuditResult")
	}

	if auditResult.TotalRules == 0 {
		t.Error("expected rules in result")
	}

	if auditResult.Score < 0 || auditResult.Score > 100 {
		t.Errorf("expected score between 0-100, got %f", auditResult.Score)
	}
}

func TestConfigurationAuditTool_GetSSHRules(t *testing.T) {
	tool := NewConfigurationAuditTool(nil)
	params := &ConfigAuditParams{}

	rules := tool.getSSHRules(params)

	if len(rules) == 0 {
		t.Error("expected SSH rules")
	}

	expectedIDs := map[string]bool{
		"SSH-001": true,
		"SSH-002": true,
		"SSH-003": true,
	}

	for _, rule := range rules {
		if !expectedIDs[rule.ID] {
			t.Errorf("unexpected rule ID: %s", rule.ID)
		}
		if rule.Target != ConfigSSH {
			t.Errorf("expected target SSH, got %v", rule.Target)
		}
	}
}

func TestConfigurationAuditTool_GetSudoRules(t *testing.T) {
	tool := NewConfigurationAuditTool(nil)
	params := &ConfigAuditParams{}

	rules := tool.getSudoRules(params)

	if len(rules) == 0 {
		t.Error("expected sudo rules")
	}

	for _, rule := range rules {
		if rule.Target != ConfigSudo {
			t.Errorf("expected target sudo, got %v", rule.Target)
		}
	}
}

func TestConfigurationAuditTool_CalculateScore(t *testing.T) {
	tool := NewConfigurationAuditTool(nil)

	tests := []struct {
		name         string
		passed       int
		failed       int
		warning      int
		info         int
		minScore     float64
		maxScore     float64
	}{
		{
			name:     "all passed",
			passed:   10,
			failed:   0,
			warning:  0,
			info:     0,
			minScore: 100,
			maxScore: 100,
		},
		{
			name:     "all failed",
			passed:   0,
			failed:   10,
			warning:  0,
			info:     0,
			minScore: 0,
			maxScore: 0,
		},
		{
			name:     "half passed",
			passed:   5,
			failed:   5,
			warning:  0,
			info:     0,
			minScore: 50,
			maxScore: 50,
		},
		{
			name:     "with warnings",
			passed:   5,
			failed:   2,
			warning:  3,
			info:     0,
			minScore: 65,
			maxScore: 65,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ConfigAuditResult{
				PassedRules:  tt.passed,
				FailedRules:  tt.failed,
				WarningRules: tt.warning,
				InfoRules:    tt.info,
				TotalRules:   tt.passed + tt.failed + tt.warning + tt.info,
			}

			score := tool.calculateScore(result)

			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("expected score between %f-%f, got %f", tt.minScore, tt.maxScore, score)
			}
		})
	}
}

func TestConfigurationAuditTool_DetermineRiskLevel(t *testing.T) {
	tool := NewConfigurationAuditTool(nil)

	tests := []struct {
		name           string
		failedRules    int
		warningRules   int
		score          float64
		expectedLevel  string
	}{
		{
			name:          "no failures",
			failedRules:   0,
			warningRules:  0,
			score:         100,
			expectedLevel: "pass",
		},
		{
			name:          "with warnings",
			failedRules:   0,
			warningRules:  2,
			score:         75,
			expectedLevel: "low",
		},
		{
			name:          "medium risk",
			failedRules:   2,
			warningRules:  0,
			score:         70,
			expectedLevel: "medium",
		},
		{
			name:          "high risk",
			failedRules:   2,
			warningRules:  0,
			score:         50,
			expectedLevel: "high",
		},
		{
			name:          "critical risk",
			failedRules:   5,
			warningRules:  0,
			score:         30,
			expectedLevel: "critical",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ConfigAuditResult{
				FailedRules:  tt.failedRules,
				WarningRules: tt.warningRules,
				Score:        tt.score,
			}

			level := tool.determineRiskLevel(result)

			if level != tt.expectedLevel {
				t.Errorf("expected level %s, got %s", tt.expectedLevel, level)
			}
		})
	}
}

func TestConfigurationAuditTool_GenerateRecommendations(t *testing.T) {
	tool := NewConfigurationAuditTool(nil)

	result := &ConfigAuditResult{
		FailedRules:  2,
		WarningRules: 1,
		TotalRules:   5,
		Score:        60,
		Rules: []*ConfigAuditRule{
			{
				ID:          "SSH-001",
				Status:      "fail",
				Remediation: "Disable root login",
			},
		},
	}

	recommendations := tool.generateRecommendations(result)

	if len(recommendations) < 1 {
		t.Errorf("expected at least 1 recommendation, got %d", len(recommendations))
	}
}

func TestConfigurationAuditTool_MultipleTargets(t *testing.T) {
	tool := NewConfigurationAuditTool(nil)

	params := &ConfigAuditParams{
		Targets: []ConfigAuditTarget{ConfigSSH, ConfigSudo, ConfigFirewall},
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	auditResult, ok := result.(*ConfigAuditResult)
	if !ok {
		t.Fatal("expected ConfigAuditResult")
	}

	// Should have rules from all three targets
	if auditResult.TotalRules < 3 {
		t.Errorf("expected at least 3 rules from multiple targets, got %d", auditResult.TotalRules)
	}
}

func BenchmarkConfigurationAuditTool_Execute(b *testing.B) {
	tool := NewConfigurationAuditTool(nil)
	params := &ConfigAuditParams{
		Targets: []ConfigAuditTarget{ConfigSSH, ConfigSudo},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}

func TestConfigurationAuditTool_Execute_RemoteSystemInfo(t *testing.T) {
	tool := NewConfigurationAuditTool(nil)

	params := &ConfigAuditParams{
		Targets:    []ConfigAuditTarget{ConfigSSH},
		RemoteHost: "10.0.0.2",
		RemoteUser: "ops",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	auditResult, ok := result.(*ConfigAuditResult)
	if !ok {
		t.Fatal("expected ConfigAuditResult")
	}
	if auditResult.SystemInfo != "remote:ops@10.0.0.2" {
		t.Fatalf("expected remote system info, got %q", auditResult.SystemInfo)
	}
}

func TestFormatAuditRemoteTarget(t *testing.T) {
	if got := formatAuditRemoteTarget("ops", "10.0.0.2"); got != "ops@10.0.0.2" {
		t.Fatalf("unexpected target: %s", got)
	}
	if got := formatAuditRemoteTarget("", "10.0.0.2"); got != "10.0.0.2" {
		t.Fatalf("unexpected target: %s", got)
	}
}
