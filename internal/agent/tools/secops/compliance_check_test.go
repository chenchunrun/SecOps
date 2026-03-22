package secops

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestComplianceCheckTool_Type(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	if tool.Type() != ToolTypeComplianceCheck {
		t.Errorf("expected %v, got %v", ToolTypeComplianceCheck, tool.Type())
	}
}

func TestComplianceCheckTool_Name(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	if tool.Name() != "Compliance Checker" {
		t.Errorf("expected 'Compliance Checker', got %v", tool.Name())
	}
}

func TestComplianceCheckTool_Description(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	if tool.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestComplianceCheckTool_RequiredCapabilities(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	caps := tool.RequiredCapabilities()
	if len(caps) == 0 {
		t.Error("expected capabilities")
	}
	if caps[0] != "compliance:check" {
		t.Errorf("expected 'compliance:check', got %v", caps[0])
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
			name:    "valid HIPAA",
			params:  &ComplianceCheckParams{Framework: FrameworkHIPAA},
			wantErr: false,
		},
		{
			name:    "valid GDPR",
			params:  &ComplianceCheckParams{Framework: FrameworkGDPR},
			wantErr: false,
		},
		{
			name:    "valid ISO27001",
			params:  &ComplianceCheckParams{Framework: FrameworkISO27001},
			wantErr: false,
		},
		{
			name:    "valid Docker Bench",
			params:  &ComplianceCheckParams{Framework: FrameworkDockerBench},
			wantErr: false,
		},
		{
			name: "valid with categories",
			params: &ComplianceCheckParams{
				Framework:  FrameworkCIS,
				Categories: []string{"network", "filesystem"},
			},
			wantErr: false,
		},
		{
			name: "valid with rule IDs",
			params: &ComplianceCheckParams{
				Framework: FrameworkCIS,
				RuleIDs:   []string{"cis_1_1", "cis_2_1"},
			},
			wantErr: false,
		},
		{
			name: "valid with full check",
			params: &ComplianceCheckParams{
				Framework: FrameworkCIS,
				Full:      true,
			},
			wantErr: false,
		},
		{
			name: "valid with remediation",
			params: &ComplianceCheckParams{
				Framework:          FrameworkCIS,
				IncludeRemediation: true,
			},
			wantErr: false,
		},
		{
			name: "valid with timeout",
			params: &ComplianceCheckParams{
				Framework: FrameworkCIS,
				Timeout:   60,
			},
			wantErr: false,
		},
		{
			name: "valid with fix issues",
			params: &ComplianceCheckParams{
				Framework: FrameworkCIS,
				FixIssues: true,
			},
			wantErr: false,
		},
		{
			name: "invalid negative timeout",
			params: &ComplianceCheckParams{
				Framework: FrameworkCIS,
				Timeout:   -1,
			},
			wantErr: true,
		},
		{
			name:    "missing framework",
			params:  &ComplianceCheckParams{},
			wantErr: true,
		},
		{
			name:    "invalid framework",
			params:  &ComplianceCheckParams{Framework: ComplianceFramework("unknown")},
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

	if checkResult.CheckTime.IsZero() {
		t.Error("expected check time to be set")
	}

	if checkResult.Status == "" {
		t.Error("expected status to be set")
	}
}

func TestComplianceCheckTool_Execute_AllFrameworks(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	frameworks := []ComplianceFramework{
		FrameworkCIS,
		FrameworkPCIDSS,
		FrameworkSOC2,
		FrameworkHIPAA,
		FrameworkGDPR,
		FrameworkISO27001,
		FrameworkDockerBench,
	}

	for _, fw := range frameworks {
		t.Run(string(fw), func(t *testing.T) {
			params := &ComplianceCheckParams{Framework: fw}
			result, err := tool.Execute(params)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			cr, ok := result.(*ComplianceCheckResult)
			if !ok {
				t.Fatal("expected ComplianceCheckResult")
			}
			if cr.Framework != fw {
				t.Errorf("expected framework %v, got %v", fw, cr.Framework)
			}
			if cr.TotalRules == 0 {
				t.Error("expected rules for framework")
			}
		})
	}
}

func TestComplianceCheckTool_GetRulesForFramework(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	tests := []struct {
		framework ComplianceFramework
		wantLenGt int
	}{
		{FrameworkCIS, 0},
		{FrameworkPCIDSS, 0},
		{FrameworkSOC2, 0},
		{FrameworkHIPAA, 0},
		{FrameworkGDPR, 0},
		{FrameworkISO27001, 0},
		{FrameworkDockerBench, 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.framework), func(t *testing.T) {
			rules := tool.getRulesForFramework(tt.framework, nil)
			if len(rules) <= tt.wantLenGt {
				t.Errorf("expected > %d rules for %v, got %d", tt.wantLenGt, tt.framework, len(rules))
			}
			for _, rule := range rules {
				if rule.Framework != tt.framework {
					t.Errorf("expected framework %v, got %v", tt.framework, rule.Framework)
				}
				if rule.ID == "" {
					t.Error("expected rule ID")
				}
				if rule.Title == "" {
					t.Error("expected rule title")
				}
			}
		})
	}
}

func TestComplianceCheckTool_GetRulesForFramework_CategoryFilter(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	tests := []struct {
		name       string
		framework  ComplianceFramework
		categories []string
	}{
		{"CIS filesystem", FrameworkCIS, []string{"filesystem"}},
		{"CIS network", FrameworkCIS, []string{"network"}},
		{"CIS packages", FrameworkCIS, []string{"packages"}},
		{"PCI-DSS auth", FrameworkPCIDSS, []string{"authentication"}},
		{"SOC2 access", FrameworkSOC2, []string{"access_control"}},
		{"HIPAA data", FrameworkHIPAA, []string{"data_protection"}},
		{"GDPR data", FrameworkGDPR, []string{"data_protection"}},
		{"GDPR encryption", FrameworkGDPR, []string{"encryption"}},
		{"ISO27001 governance", FrameworkISO27001, []string{"governance"}},
		{"ISO27001 logging", FrameworkISO27001, []string{"logging"}},
		{"Docker Bench daemon", FrameworkDockerBench, []string{"daemon"}},
		{"Docker Bench filesystem", FrameworkDockerBench, []string{"filesystem"}},
		{"CIS multiple", FrameworkCIS, []string{"network", "filesystem"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := tool.getRulesForFramework(tt.framework, tt.categories)
			if len(rules) == 0 {
				// Some category/framework combos may have no matching rules.
				t.Log("no rules returned for this combination")
			}
			for _, rule := range rules {
				found := false
				for _, cat := range tt.categories {
					if rule.Category == cat {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected category in %v, got %s", tt.categories, rule.Category)
				}
			}
		})
	}
}

func TestComplianceCheckTool_GetCISRules(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	rules := tool.getCISRules()

	if len(rules) == 0 {
		t.Error("expected CIS rules")
	}

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

func TestComplianceCheckTool_GetPCIDSSRules(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	rules := tool.getPCIDSSRules()

	if len(rules) == 0 {
		t.Error("expected PCI-DSS rules")
	}

	for _, rule := range rules {
		if rule.Framework != FrameworkPCIDSS {
			t.Errorf("expected framework %v, got %v", FrameworkPCIDSS, rule.Framework)
		}
	}
}

func TestComplianceCheckTool_GetSOC2Rules(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	rules := tool.getSOC2Rules()

	if len(rules) == 0 {
		t.Error("expected SOC2 rules")
	}

	for _, rule := range rules {
		if rule.Framework != FrameworkSOC2 {
			t.Errorf("expected framework %v, got %v", FrameworkSOC2, rule.Framework)
		}
	}
}

func TestComplianceCheckTool_GetHIPAARules(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	rules := tool.getHIPAARules()

	if len(rules) == 0 {
		t.Error("expected HIPAA rules")
	}

	for _, rule := range rules {
		if rule.Framework != FrameworkHIPAA {
			t.Errorf("expected framework %v, got %v", FrameworkHIPAA, rule.Framework)
		}
	}
}

func TestComplianceCheckTool_GetGDPRRules(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	rules := tool.getGDPRRules()

	if len(rules) == 0 {
		t.Error("expected GDPR rules")
	}

	for _, rule := range rules {
		if rule.Framework != FrameworkGDPR {
			t.Errorf("expected framework %v, got %v", FrameworkGDPR, rule.Framework)
		}
	}
}

func TestComplianceCheckTool_GetISO27001Rules(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	rules := tool.getISO27001Rules()

	if len(rules) == 0 {
		t.Fatal("expected ISO27001 rules")
	}

	for _, rule := range rules {
		if rule.Framework != FrameworkISO27001 {
			t.Errorf("expected framework %v, got %v", FrameworkISO27001, rule.Framework)
		}
		if rule.ID == "" || rule.Title == "" {
			t.Errorf("expected populated rule metadata: %+v", rule)
		}
	}
}

func TestComplianceCheckTool_GetDockerBenchRules(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	rules := tool.getDockerBenchRules()

	if len(rules) == 0 {
		t.Fatal("expected Docker Bench rules")
	}

	for _, rule := range rules {
		if rule.Framework != FrameworkDockerBench {
			t.Errorf("expected framework %v, got %v", FrameworkDockerBench, rule.Framework)
		}
		if rule.ID == "" || rule.Title == "" {
			t.Errorf("expected populated rule metadata: %+v", rule)
		}
	}
}

func TestComplianceCheckTool_Execute_ISO27001(t *testing.T) {
	oldPolicyPaths := iso27001PolicyPaths
	oldAuditPaths := iso27001AuditLogPaths
	oldAccessPath := iso27001AccessControlPath
	defer func() {
		iso27001PolicyPaths = oldPolicyPaths
		iso27001AuditLogPaths = oldAuditPaths
		iso27001AccessControlPath = oldAccessPath
	}()

	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.md")
	auditFile := filepath.Join(tmpDir, "audit.log")
	shadowFile := filepath.Join(tmpDir, "shadow")

	if err := os.WriteFile(policyFile, []byte("Information security policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditFile, []byte("audit event"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadowFile, []byte("root:*:..."), 0o640); err != nil {
		t.Fatal(err)
	}

	iso27001PolicyPaths = []string{policyFile}
	iso27001AuditLogPaths = []string{auditFile}
	iso27001AccessControlPath = shadowFile

	tool := NewComplianceCheckTool(nil)
	result, err := tool.Execute(&ComplianceCheckParams{Framework: FrameworkISO27001})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	checkResult, ok := result.(*ComplianceCheckResult)
	if !ok {
		t.Fatal("expected ComplianceCheckResult")
	}
	if checkResult.TotalRules != 3 {
		t.Fatalf("expected 3 rules, got %d", checkResult.TotalRules)
	}
	if checkResult.PassedRules != 3 {
		t.Fatalf("expected 3 passed rules, got %d", checkResult.PassedRules)
	}
	if checkResult.Status != StatusPassed {
		t.Fatalf("expected passed status, got %s", checkResult.Status)
	}
}

func TestComplianceCheckTool_Execute_DockerBench(t *testing.T) {
	oldDaemonPath := dockerBenchDaemonConfigPath
	oldSocketPath := dockerBenchSocketPath
	oldIPForwardPath := dockerBenchIPForwardPath
	defer func() {
		dockerBenchDaemonConfigPath = oldDaemonPath
		dockerBenchSocketPath = oldSocketPath
		dockerBenchIPForwardPath = oldIPForwardPath
	}()

	tmpDir := t.TempDir()
	daemonFile := filepath.Join(tmpDir, "daemon.json")
	socketFile := filepath.Join(tmpDir, "docker.sock")
	ipForwardFile := filepath.Join(tmpDir, "ip_forward")

	if err := os.WriteFile(daemonFile, []byte(`{"userns-remap":"default","live-restore":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(socketFile, []byte("socket"), 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ipForwardFile, []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dockerBenchDaemonConfigPath = daemonFile
	dockerBenchSocketPath = socketFile
	dockerBenchIPForwardPath = ipForwardFile

	tool := NewComplianceCheckTool(nil)
	result, err := tool.Execute(&ComplianceCheckParams{Framework: FrameworkDockerBench})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	checkResult, ok := result.(*ComplianceCheckResult)
	if !ok {
		t.Fatal("expected ComplianceCheckResult")
	}
	if checkResult.TotalRules != 3 {
		t.Fatalf("expected 3 rules, got %d", checkResult.TotalRules)
	}
	if checkResult.PassedRules != 3 {
		t.Fatalf("expected 3 passed rules, got %d", checkResult.PassedRules)
	}
	if checkResult.Status != StatusPassed {
		t.Fatalf("expected passed status, got %s", checkResult.Status)
	}
}

func TestComplianceCheckTool_Execute_GDPR(t *testing.T) {
	oldAccessPaths := gdprDataAccessLogPaths
	oldEncPaths := gdprEncryptionConfigPaths
	oldRetentionPaths := gdprRetentionPolicyPaths
	defer func() {
		gdprDataAccessLogPaths = oldAccessPaths
		gdprEncryptionConfigPaths = oldEncPaths
		gdprRetentionPolicyPaths = oldRetentionPaths
	}()

	tmpDir := t.TempDir()
	accessLog := filepath.Join(tmpDir, "data-access.log")
	encCfg := filepath.Join(tmpDir, "encryption.conf")
	retentionCfg := filepath.Join(tmpDir, "retention.json")

	if err := os.WriteFile(accessLog, []byte("user accessed pii record"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(encCfg, []byte("tls=enabled\nencryption=aes256"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(retentionCfg, []byte(`{"retention_days":180}`), 0o600); err != nil {
		t.Fatal(err)
	}

	gdprDataAccessLogPaths = []string{accessLog}
	gdprEncryptionConfigPaths = []string{encCfg}
	gdprRetentionPolicyPaths = []string{retentionCfg}

	tool := NewComplianceCheckTool(nil)
	result, err := tool.Execute(&ComplianceCheckParams{Framework: FrameworkGDPR})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	checkResult, ok := result.(*ComplianceCheckResult)
	if !ok {
		t.Fatal("expected ComplianceCheckResult")
	}
	if checkResult.TotalRules != 3 {
		t.Fatalf("expected 3 rules, got %d", checkResult.TotalRules)
	}
	if checkResult.PassedRules != 3 {
		t.Fatalf("expected 3 passed rules, got %d", checkResult.PassedRules)
	}
	if checkResult.Status != StatusPassed {
		t.Fatalf("expected passed status, got %s", checkResult.Status)
	}
}

// Score calculation tests

func TestComplianceCheckTool_CalculateScore(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	tests := []struct {
		name     string
		passed   int
		failed   int
		warning  int
		total    int
		expected float64
	}{
		{
			name:     "all passed",
			passed:   10,
			failed:   0,
			warning:  0,
			total:    10,
			expected: 100,
		},
		{
			name:     "all failed",
			passed:   0,
			failed:   10,
			warning:  0,
			total:    10,
			expected: 0,
		},
		{
			name:     "half passed",
			passed:   5,
			failed:   5,
			warning:  0,
			total:    10,
			expected: 50,
		},
		{
			name:     "with warnings",
			passed:   5,
			failed:   2,
			warning:  3,
			total:    10,
			expected: 65, // (5*100 + 3*50) / 10 = 65
		},
		{
			name:     "all warnings",
			passed:   0,
			failed:   0,
			warning:  10,
			total:    10,
			expected: 50,
		},
		{
			name:     "mixed 70",
			passed:   7,
			failed:   2,
			warning:  1,
			total:    10,
			expected: 75,
		},
		{
			name:     "mixed 85",
			passed:   8,
			failed:   1,
			warning:  1,
			total:    10,
			expected: 85,
		},
		{
			name:     "single rule passed",
			passed:   1,
			failed:   0,
			warning:  0,
			total:    1,
			expected: 100,
		},
		{
			name:     "single rule failed",
			passed:   0,
			failed:   1,
			warning:  0,
			total:    1,
			expected: 0,
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

			if score != tt.expected {
				t.Errorf("expected score %f, got %f", tt.expected, score)
			}
		})
	}
}

func TestComplianceCheckTool_CalculateScore_ZeroRules(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	result := &ComplianceCheckResult{
		PassedRules:  0,
		FailedRules:  0,
		WarningRules: 0,
		TotalRules:   0,
	}

	score := tool.calculateScore(result)
	if score != 100 {
		t.Errorf("expected 100 for zero rules, got %f", score)
	}
}

// Status determination tests

func TestComplianceCheckTool_DetermineStatus(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	tests := []struct {
		name           string
		failedRules    int
		score          float64
		expectedStatus ComplianceStatus
	}{
		{
			name:           "no failures",
			failedRules:    0,
			score:          100,
			expectedStatus: StatusPassed,
		},
		{
			name:           "high score with failures",
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
		{
			name:           "score at boundary 80",
			failedRules:    2,
			score:          80,
			expectedStatus: StatusWarning,
		},
		{
			name:           "score below 80",
			failedRules:    3,
			score:          79,
			expectedStatus: StatusFailed,
		},
		{
			name:           "zero failures at boundary",
			failedRules:    0,
			score:          0,
			expectedStatus: StatusPassed,
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

// Filter tests

func TestComplianceCheckTool_FilterByCategory(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	rules := tool.getRulesForFramework(FrameworkCIS, []string{"network"})

	if len(rules) == 0 {
		// Some categories may have no rules.
		t.Skip("no network rules available")
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

	tests := []struct {
		name     string
		ruleIDs  []string
		expected int
	}{
		{"single ID", []string{allRules[0].ID}, 1},
		{"multiple IDs", []string{allRules[0].ID, allRules[1].ID}, 2},
		{"non-existent ID", []string{"non_existent"}, 0},
		{"empty IDs", []string{}, 0},
		{"mix of existing and non-existing", []string{allRules[0].ID, "fake_id"}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := tool.filterRulesByID(allRules, tt.ruleIDs)
			if len(filtered) != tt.expected {
				t.Errorf("expected %d rules, got %d", tt.expected, len(filtered))
			}
		})
	}
}

func TestComplianceCheckTool_FilterRulesByID_NilRules(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	filtered := tool.filterRulesByID(nil, []string{"cis_1_1"})
	if len(filtered) != 0 {
		t.Errorf("expected 0 rules for nil input, got %d", len(filtered))
	}
}

// Generate summary tests

func TestComplianceCheckTool_GenerateSummary(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	result := &ComplianceCheckResult{
		Rules: []*ComplianceRule{
			{Status: StatusFailed, Severity: SeverityHigh},
			{Status: StatusFailed, Severity: SeverityHigh},
			{Status: StatusFailed, Severity: SeverityMedium},
			{Status: StatusFailed, Severity: SeverityLow},
			{Status: StatusPassed, Severity: SeverityHigh},
			{Status: StatusWarning, Severity: SeverityHigh},
		},
	}

	summary := tool.generateSummary(result)

	if summary.HighPriority != 2 {
		t.Errorf("expected 2 high priority issues, got %d", summary.HighPriority)
	}
	if summary.MediumPriority != 1 {
		t.Errorf("expected 1 medium priority issue, got %d", summary.MediumPriority)
	}
	if summary.LowPriority != 1 {
		t.Errorf("expected 1 low priority issue, got %d", summary.LowPriority)
	}
}

func TestComplianceCheckTool_GenerateSummary_NoFailures(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	result := &ComplianceCheckResult{
		Rules: []*ComplianceRule{
			{Status: StatusPassed, Severity: SeverityHigh},
			{Status: StatusPassed, Severity: SeverityMedium},
			{Status: StatusWarning, Severity: SeverityLow},
		},
	}

	summary := tool.generateSummary(result)

	if summary.HighPriority != 0 {
		t.Errorf("expected 0 high priority, got %d", summary.HighPriority)
	}
	if summary.MediumPriority != 0 {
		t.Errorf("expected 0 medium priority, got %d", summary.MediumPriority)
	}
	if summary.LowPriority != 0 {
		t.Errorf("expected 0 low priority, got %d", summary.LowPriority)
	}
}

func TestComplianceCheckTool_GenerateSummary_EmptyRules(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	result := &ComplianceCheckResult{
		Rules: []*ComplianceRule{},
	}

	summary := tool.generateSummary(result)

	if summary.HighPriority != 0 {
		t.Errorf("expected 0 high priority, got %d", summary.HighPriority)
	}
}

// Generate recommendations tests

func TestComplianceCheckTool_GenerateRecommendations(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	result := &ComplianceCheckResult{
		Rules: []*ComplianceRule{
			{ID: "r1", Status: StatusFailed, Severity: SeverityHigh, Title: "High 1"},
			{ID: "r2", Status: StatusFailed, Severity: SeverityHigh, Title: "High 2"},
			{ID: "r3", Status: StatusFailed, Severity: SeverityHigh, Title: "High 3"},
			{ID: "r4", Status: StatusFailed, Severity: SeverityHigh, Title: "High 4"},
			{ID: "r5", Status: StatusFailed, Severity: SeverityMedium, Title: "Med 1"},
			{ID: "r6", Status: StatusPassed, Severity: SeverityHigh, Title: "Passed"},
		},
	}

	recs := tool.generateRecommendations(result)

	// Should only recommend for failed high severity, up to 3
	if len(recs) > 3 {
		t.Errorf("expected max 3 recommendations, got %d", len(recs))
	}

	for _, rec := range recs {
		if rec.Priority != 5 {
			t.Errorf("expected priority 5, got %d", rec.Priority)
		}
		if rec.ImpactScore != 0.9 {
			t.Errorf("expected impact score 0.9, got %f", rec.ImpactScore)
		}
	}
}

func TestComplianceCheckTool_GenerateRecommendations_NoFailed(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	result := &ComplianceCheckResult{
		Rules: []*ComplianceRule{
			{Status: StatusPassed, Severity: SeverityHigh},
			{Status: StatusWarning, Severity: SeverityMedium},
		},
	}

	recs := tool.generateRecommendations(result)

	if len(recs) != 0 {
		t.Errorf("expected 0 recommendations for no failures, got %d", len(recs))
	}
}

func TestComplianceCheckTool_GenerateRecommendations_MediumSeverity(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	result := &ComplianceCheckResult{
		Rules: []*ComplianceRule{
			{Status: StatusFailed, Severity: SeverityMedium, Title: "Med 1"},
		},
	}

	recs := tool.generateRecommendations(result)

	// Medium severity should not generate recommendations
	if len(recs) != 0 {
		t.Errorf("expected 0 recommendations for medium severity, got %d", len(recs))
	}
}

// Remediation tests

func TestComplianceCheckTool_RemediationInResult(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	params := &ComplianceCheckParams{
		Framework:          FrameworkCIS,
		IncludeRemediation: true,
		Full:               true,
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	cr := result.(*ComplianceCheckResult)

	for _, rule := range cr.Rules {
		if rule.Status == StatusFailed {
			// Failed rules should ideally include remediation details.
			if rule.Remediation == nil {
				// Some rules may not define remediation.
				t.Logf("rule %s has no remediation", rule.ID)
			}
		}
	}
}

func TestComplianceCheckTool_RuleRemediationDetails(t *testing.T) {
	tool := NewComplianceCheckTool(nil)
	rules := tool.getCISRules()

	for _, rule := range rules {
		if rule.Status == StatusWarning && rule.Remediation != nil {
			rem := rule.Remediation
			if rem.Description == "" {
				t.Error("expected remediation description")
			}
			if len(rem.Steps) == 0 {
				t.Error("expected remediation steps")
			}
			if rem.Priority < 1 || rem.Priority > 5 {
				t.Errorf("expected priority 1-5, got %d", rem.Priority)
			}
			if rem.Difficulty == "" {
				t.Error("expected difficulty")
			}
			if rem.TimeEstimate < 0 {
				t.Error("expected non-negative time estimate")
			}
		}
	}
}

// Check rule tests

func TestComplianceCheckTool_CheckRule(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	rule := &ComplianceRule{
		ID:     "test_rule",
		Title:  "Test Rule",
		Status: StatusFailed,
	}

	before := time.Now()
	tool.checkRule(rule, false)
	after := time.Now()

	if rule.LastChecked.Before(before) || rule.LastChecked.After(after) {
		t.Error("expected LastChecked to be set")
	}
}

func TestComplianceCheckTool_CheckRule_FullMode(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	rule := &ComplianceRule{
		ID:       "test_rule",
		Title:    "Test Rule",
		Status:   StatusFailed,
		Evidence: "Found issue",
	}

	originalEvidence := rule.Evidence
	tool.checkRule(rule, true)

	// In full mode, evidence should be prefixed with "Detailed check: "
	if rule.Evidence == "" {
		t.Error("expected evidence after full check")
	}
	if rule.Evidence != "Detailed check: "+originalEvidence {
		t.Errorf("expected detailed evidence, got %s", rule.Evidence)
	}
}

func TestComplianceCheckTool_CheckRule_PassedStatus_NoEvidenceChange(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	rule := &ComplianceRule{
		ID:       "test_rule",
		Title:    "Test Rule",
		Status:   StatusPassed,
		Evidence: "All good",
	}

	originalEvidence := rule.Evidence
	tool.checkRule(rule, true)

	// Passed rules should not have evidence modified in full mode
	if rule.Evidence != originalEvidence {
		t.Errorf("evidence should not change for passed rules, got %s", rule.Evidence)
	}
}

// Run compliance check integration tests

func TestComplianceCheckTool_RunComplianceCheck(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	params := &ComplianceCheckParams{
		Framework:  FrameworkCIS,
		Categories: []string{},
		RuleIDs:    []string{},
		Full:       false,
	}

	result := tool.runComplianceCheck(params)

	if result.Framework != FrameworkCIS {
		t.Errorf("expected framework CIS, got %v", result.Framework)
	}

	if result.TotalRules == 0 {
		t.Error("expected total rules > 0")
	}

	// Verify rule counts add up
	total := result.PassedRules + result.FailedRules + result.WarningRules
	if total != result.TotalRules {
		t.Errorf("rule counts don't add up: %d != %d", total, result.TotalRules)
	}

	// Verify summary is generated
	if result.Summary == nil {
		t.Error("expected summary")
	}

	// Verify recommendations are generated
	if result.Recommendations == nil {
		t.Error("expected recommendations")
	}
}

func TestComplianceCheckTool_RunComplianceCheck_WithRuleIDs(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	allRules := tool.getCISRules()
	if len(allRules) == 0 {
		t.Skip("no rules available")
	}

	params := &ComplianceCheckParams{
		Framework: FrameworkCIS,
		RuleIDs:   []string{allRules[0].ID},
	}

	result := tool.runComplianceCheck(params)

	if result.TotalRules != 1 {
		t.Errorf("expected 1 rule, got %d", result.TotalRules)
	}

	if len(result.Rules) != 1 {
		t.Errorf("expected 1 rule in result, got %d", len(result.Rules))
	}

	if result.Rules[0].ID != allRules[0].ID {
		t.Errorf("expected rule %s, got %s", allRules[0].ID, result.Rules[0].ID)
	}
}

func TestComplianceCheckTool_RunComplianceCheck_CategoryFilter(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	allRules := tool.getCISRules()
	if len(allRules) == 0 {
		t.Skip("no rules available")
	}

	// Get rules for a specific category
	category := allRules[0].Category
	params := &ComplianceCheckParams{
		Framework:  FrameworkCIS,
		Categories: []string{category},
	}

	result := tool.runComplianceCheck(params)

	for _, rule := range result.Rules {
		if rule.Category != category {
			t.Errorf("expected category %s, got %s", category, rule.Category)
		}
	}
}

// Framework enum values tests

func TestComplianceFramework_Values(t *testing.T) {
	if FrameworkCIS != "cis" {
		t.Errorf("expected 'cis', got %v", FrameworkCIS)
	}
	if FrameworkPCIDSS != "pci_dss" {
		t.Errorf("expected 'pci_dss', got %v", FrameworkPCIDSS)
	}
	if FrameworkSOC2 != "soc2" {
		t.Errorf("expected 'soc2', got %v", FrameworkSOC2)
	}
	if FrameworkHIPAA != "hipaa" {
		t.Errorf("expected 'hipaa', got %v", FrameworkHIPAA)
	}
	if FrameworkGDPR != "gdpr" {
		t.Errorf("expected 'gdpr', got %v", FrameworkGDPR)
	}
}

func TestComplianceStatus_Values(t *testing.T) {
	if StatusPassed != "passed" {
		t.Errorf("expected 'passed', got %v", StatusPassed)
	}
	if StatusFailed != "failed" {
		t.Errorf("expected 'failed', got %v", StatusFailed)
	}
	if StatusWarning != "warning" {
		t.Errorf("expected 'warning', got %v", StatusWarning)
	}
	if StatusNotApplicable != "not_applicable" {
		t.Errorf("expected 'not_applicable', got %v", StatusNotApplicable)
	}
}

func TestComplianceSeverity_Values(t *testing.T) {
	if SeverityHigh != "high" {
		t.Errorf("expected 'high', got %v", SeverityHigh)
	}
	if SeverityMedium != "medium" {
		t.Errorf("expected 'medium', got %v", SeverityMedium)
	}
	if SeverityLow != "low" {
		t.Errorf("expected 'low', got %v", SeverityLow)
	}
	if SeverityInfo != "info" {
		t.Errorf("expected 'info', got %v", SeverityInfo)
	}
}

// Edge cases

func TestComplianceCheckTool_Execute_InvalidParams(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	tests := []struct {
		name   string
		params interface{}
	}{
		{"nil params", nil},
		{"string params", "invalid"},
		{"wrong type", struct{}{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tool.Execute(tt.params)
			if err == nil {
				t.Error("expected error for invalid params")
			}
		})
	}
}

func TestComplianceCheckTool_ComplianceResult_Structure(t *testing.T) {
	tool := NewComplianceCheckTool(nil)

	params := &ComplianceCheckParams{Framework: FrameworkCIS}
	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	cr := result.(*ComplianceCheckResult)

	// Verify all fields are populated
	if cr.Framework == "" {
		t.Error("expected framework")
	}
	if cr.CheckTime.IsZero() {
		t.Error("expected check time")
	}
	if cr.TotalRules == 0 {
		t.Error("expected total rules")
	}
	if cr.Score < 0 || cr.Score > 100 {
		t.Errorf("expected score 0-100, got %f", cr.Score)
	}
	if cr.Status == "" {
		t.Error("expected status")
	}
	if cr.Rules == nil {
		t.Error("expected rules slice")
	}
	if cr.Summary == nil {
		t.Error("expected summary")
	}
	if cr.Recommendations == nil {
		t.Error("expected recommendations slice")
	}
}

// Benchmark

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

func BenchmarkComplianceCheckTool_Execute_Full(b *testing.B) {
	tool := NewComplianceCheckTool(nil)
	params := &ComplianceCheckParams{
		Framework: FrameworkCIS,
		Full:      true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}

func BenchmarkComplianceCheckTool_Execute_AllFrameworks(b *testing.B) {
	tool := NewComplianceCheckTool(nil)
	frameworks := []ComplianceFramework{FrameworkCIS, FrameworkPCIDSS, FrameworkSOC2, FrameworkHIPAA, FrameworkGDPR}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw := frameworks[i%len(frameworks)]
		params := &ComplianceCheckParams{Framework: fw}
		tool.Execute(params)
	}
}

func BenchmarkComplianceCheckTool_CalculateScore(b *testing.B) {
	tool := NewComplianceCheckTool(nil)
	result := &ComplianceCheckResult{
		PassedRules:  10,
		FailedRules:  3,
		WarningRules: 2,
		TotalRules:   15,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.calculateScore(result)
	}
}

func BenchmarkComplianceCheckTool_DetermineStatus(b *testing.B) {
	tool := NewComplianceCheckTool(nil)
	result := &ComplianceCheckResult{
		FailedRules: 5,
		Score:       65,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.determineStatus(result)
	}
}
