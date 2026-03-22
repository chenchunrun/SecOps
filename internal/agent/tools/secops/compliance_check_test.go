package secops

import (
	"testing"
)

func TestComplianceCheckTool_Type(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	if tool.Type() != ToolTypeComplianceCheck {
		t.Errorf("expected %v, got %v", ToolTypeComplianceCheck, tool.Type())
	}
}

func TestComplianceCheckTool_ValidateParams(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name:    "valid CIS",
			params:  &ComplianceCheckParams{Framework: FrameworkCIS},
			wantErr: false,
		},
		{
			name:    "valid PCI-DSS",
			params:  &ComplianceCheckParams{Framework: FrameworkPCIDSS},
			wantErr: false,
		},
		{
			name:    "valid SOC2",
			params:  &ComplianceCheckParams{Framework: FrameworkSOC2},
			wantErr: false,
		},
		{
			name:    "missing framework",
			params:  &ComplianceCheckParams{},
			wantErr: true,
		},
		{
			name:    "invalid framework",
			params:  &ComplianceCheckParams{Framework: ComplianceFramework("invalid")},
			wantErr: true,
		},
		{
			name:    "invalid type",
			params:  "invalid",
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

func TestComplianceCheckTool_Execute(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	params := &ComplianceCheckParams{
		Framework: FrameworkCIS,
		Full:      false,
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	checkResult, ok := result.(*ComplianceCheckResult)
	if !ok {
		t.Fatal("expected ComplianceCheckResult")
	}

	if checkResult.Framework != FrameworkCIS {
		t.Errorf("expected framework %v, got %v", FrameworkCIS, checkResult.Framework)
	}

	if checkResult.TotalRules == 0 {
		t.Error("expected non-zero total rules")
	}

	if checkResult.Score < 0 || checkResult.Score > 100 {
		t.Errorf("expected score between 0-100, got %f", checkResult.Score)
	}
}

func TestComplianceCheckTool_GetCISRules(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	rules := tool.getCISRules()

	if len(rules) == 0 {
		t.Error("expected CIS rules")
	}

	// 检查规则结构
	for _, rule := range rules {
		if rule.ID == "" {
			t.Error("expected rule ID")
		}
		if rule.Title == "" {
			t.Error("expected rule title")
		}
		if rule.Framework != FrameworkCIS {
			t.Errorf("expected framework %v, got %v", FrameworkCIS, rule.Framework)
		}
	}
}

func TestComplianceCheckTool_CalculateScore(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	tests := []struct {
		name         string
		passed       int
		failed       int
		warning      int
		total        int
		minScore     float64
		maxScore     float64
	}{
		{
			name:     "all passed",
			passed:   10,
			failed:   0,
			warning:  0,
			total:    10,
			minScore: 100,
			maxScore: 100,
		},
		{
			name:     "all failed",
			passed:   0,
			failed:   10,
			warning:  0,
			total:    10,
			minScore: 0,
			maxScore: 0,
		},
		{
			name:     "half passed",
			passed:   5,
			failed:   5,
			warning:  0,
			total:    10,
			minScore: 50,
			maxScore: 50,
		},
		{
			name:     "with warnings",
			passed:   5,
			failed:   2,
			warning:  3,
			total:    10,
			minScore: 65, // (5*100 + 3*50) / 10 = 65
			maxScore: 65,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ComplianceCheckResult{
				PassedRules:  tt.passed,
				FailedRules:  tt.failed,
				WarningRules: tt.warning,
				TotalRules:   tt.total,
			}

			score := tool.calculateScore(result)

			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("expected score between %f-%f, got %f", tt.minScore, tt.maxScore, score)
			}
		})
	}
}

func TestComplianceCheckTool_DetermineStatus(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	tests := []struct {
		name          string
		failedRules   int
		score         float64
		expectedStatus ComplianceStatus
	}{
		{
			name:           "no failures",
			failedRules:    0,
			score:          100,
			expectedStatus: StatusPassed,
		},
		{
			name:           "high score",
			failedRules:    1,
			score:          85,
			expectedStatus: StatusWarning,
		},
		{
			name:           "low score",
			failedRules:    5,
			score:          50,
			expectedStatus: StatusFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ComplianceCheckResult{
				FailedRules: tt.failedRules,
				Score:       tt.score,
			}

			status := tool.determineStatus(result)

			if status != tt.expectedStatus {
				t.Errorf("expected status %v, got %v", tt.expectedStatus, status)
			}
		})
	}
}

func TestComplianceCheckTool_FilterByCategory(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	rules := tool.getRulesForFramework(FrameworkCIS, []string{"network"})

	if len(rules) == 0 {
		t.Error("expected filtered rules")
	}

	for _, rule := range rules {
		if rule.Category != "network" {
			t.Errorf("expected category 'network', got %s", rule.Category)
		}
	}
}

func TestComplianceCheckTool_FilterByRuleID(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	allRules := tool.getCISRules()
	if len(allRules) < 2 {
		t.Skip("need at least 2 rules for this test")
	}

	ruleID := []string{allRules[0].ID}
	filtered := tool.filterRulesByID(allRules, ruleID)

	if len(filtered) != 1 {
		t.Errorf("expected 1 rule, got %d", len(filtered))
	}

	if filtered[0].ID != ruleID[0] {
		t.Errorf("expected rule %s, got %s", ruleID[0], filtered[0].ID)
	}
}

func BenchmarkComplianceCheckTool_Execute(b *testing.B) {
	tool := NewComplianceCheckTool(nil)
	params := &ComplianceCheckParams{
		Framework: FrameworkCIS,
		Full:      false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}
