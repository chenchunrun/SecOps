package secops

import (
	"testing"
)

func TestSecurityScanTool_Type(t *testing.T) {
	tool := NewSecurityScanTool(nil)
	if tool.Type() != ToolTypeSecurityScan {
		t.Errorf("expected %v, got %v", ToolTypeSecurityScan, tool.Type())
	}
}

func TestSecurityScanTool_ValidateParams(t *testing.T) {
	tool := NewSecurityScanTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid params",
			params: &SecurityScanParams{
				Scanner:    ScannerTrivy,
				Target:     TargetImage,
				TargetPath: "ubuntu:latest",
			},
			wantErr: false,
		},
		{
			name:    "missing scanner",
			params:  &SecurityScanParams{Target: TargetImage, TargetPath: "ubuntu:latest"},
			wantErr: true,
		},
		{
			name:    "missing target",
			params:  &SecurityScanParams{Scanner: ScannerTrivy, TargetPath: "ubuntu:latest"},
			wantErr: true,
		},
		{
			name:    "missing target path",
			params:  &SecurityScanParams{Scanner: ScannerTrivy, Target: TargetImage},
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

func TestSecurityScanTool_Execute(t *testing.T) {
	tool := NewSecurityScanTool(nil)

	params := &SecurityScanParams{
		Scanner:    ScannerTrivy,
		Target:     TargetImage,
		TargetPath: "ubuntu:latest",
		Full:       true,
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	scanResult, ok := result.(*ScanResult)
	if !ok {
		t.Fatal("expected ScanResult")
	}

	if scanResult.Scanner != ScannerTrivy {
		t.Errorf("expected scanner %v, got %v", ScannerTrivy, scanResult.Scanner)
	}

	if scanResult.TotalVulnerabilities == 0 {
		t.Error("expected vulnerabilities in result")
	}
}

func TestSecurityScanTool_StatisticsVulnerabilities(t *testing.T) {
	tool := NewSecurityScanTool(nil)

	result := &ScanResult{
		Vulnerabilities: []*Vulnerability{
			{Severity: VulnCritical},
			{Severity: VulnHigh},
			{Severity: VulnHigh},
			{Severity: VulnMedium},
		},
	}

	tool.statisticsVulnerabilities(result)

	if result.TotalVulnerabilities != 4 {
		t.Errorf("expected 4 total vulnerabilities, got %d", result.TotalVulnerabilities)
	}

	if result.CriticalCount != 1 {
		t.Errorf("expected 1 critical, got %d", result.CriticalCount)
	}

	if result.HighCount != 2 {
		t.Errorf("expected 2 high, got %d", result.HighCount)
	}

	if result.MediumCount != 1 {
		t.Errorf("expected 1 medium, got %d", result.MediumCount)
	}

	if result.Stats == nil || result.Stats.RiskScore == 0 {
		t.Error("expected risk score to be calculated")
	}
}

func TestSecurityScanTool_GenerateRecommendations(t *testing.T) {
	tool := NewSecurityScanTool(nil)

	result := &ScanResult{
		CriticalCount: 2,
		HighCount:     3,
		MediumCount:   5,
		TotalVulnerabilities: 10,
	}

	recommendations := tool.generateRecommendations(result)

	if len(recommendations) < 2 {
		t.Errorf("expected at least 2 recommendations, got %d", len(recommendations))
	}
}

func BenchmarkSecurityScanTool_Execute(b *testing.B) {
	tool := NewSecurityScanTool(nil)
	params := &SecurityScanParams{
		Scanner:    ScannerTrivy,
		Target:     TargetImage,
		TargetPath: "ubuntu:latest",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}
