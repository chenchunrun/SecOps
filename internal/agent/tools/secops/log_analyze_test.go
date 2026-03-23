package secops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogAnalyzeTool_Type(t *testing.T) {
	tool := NewLogAnalyzeTool(nil)
	if tool.Type() != ToolTypeLogAnalyze {
		t.Errorf("expected %v, got %v", ToolTypeLogAnalyze, tool.Type())
	}
}

func TestLogAnalyzeTool_Name(t *testing.T) {
	tool := NewLogAnalyzeTool(nil)
	expected := "Log Analyzer"
	if tool.Name() != expected {
		t.Errorf("expected %s, got %s", expected, tool.Name())
	}
}

func TestLogAnalyzeTool_RequiredCapabilities(t *testing.T) {
	tool := NewLogAnalyzeTool(nil)
	caps := tool.RequiredCapabilities()

	if len(caps) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(caps))
	}

	capMap := make(map[string]bool)
	for _, cap := range caps {
		capMap[cap] = true
	}

	if !capMap["log:read"] {
		t.Error("expected 'log:read' capability")
	}
	if !capMap["log:analyze"] {
		t.Error("expected 'log:analyze' capability")
	}
}

func TestLogAnalyzeTool_ValidateParams(t *testing.T) {
	tool := NewLogAnalyzeTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name:    "valid params",
			params:  &LogAnalyzeParams{Source: LogSourceSyslog},
			wantErr: false,
		},
		{
			name:    "missing source",
			params:  &LogAnalyzeParams{},
			wantErr: true,
		},
		{
			name:    "invalid type",
			params:  "invalid",
			wantErr: true,
		},
		{
			name: "invalid date range",
			params: &LogAnalyzeParams{
				Source:    LogSourceSyslog,
				StartTime: time.Now(),
				EndTime:   time.Now().Add(-1 * time.Hour),
			},
			wantErr: true,
		},
		{
			name: "invalid regex pattern",
			params: &LogAnalyzeParams{
				Source:  LogSourceSyslog,
				Pattern: "[invalid(",
			},
			wantErr: true,
		},
		{
			name: "invalid remote port",
			params: &LogAnalyzeParams{
				Source:     LogSourceSyslog,
				RemoteHost: "10.0.0.100",
				RemotePort: 70000,
			},
			wantErr: true,
		},
		{
			name: "remote option without host",
			params: &LogAnalyzeParams{
				Source:     LogSourceSyslog,
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

func TestLogAnalyzeTool_Execute(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "syslog.log")
	content := "" +
		"Mar 22 10:01:01 server1 nginx[123]: ERROR Connection refused\n" +
		"Mar 22 10:02:01 server1 nginx[123]: INFO Ready\n"
	if err := os.WriteFile(logFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write test log: %v", err)
	}
	t.Setenv("SECOPS_LOG_SYSLOG_PATHS", logFile)

	tool := NewLogAnalyzeTool(nil)

	params := &LogAnalyzeParams{
		Source:  LogSourceSyslog,
		Keyword: "error",
		Limit:   10,
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	analyzeResult, ok := result.(*LogAnalyzeResult)
	if !ok {
		t.Fatal("expected LogAnalyzeResult")
	}

	if analyzeResult.TotalCount == 0 {
		t.Error("expected non-zero total count")
	}
}

func TestLogAnalyzeTool_Execute_RemoteViaSSH(t *testing.T) {
	tool := NewLogAnalyzeTool(nil)
	var gotName string
	var gotArgs []string
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return []byte(
			"Mar 22 10:01:01 server1 nginx[123]: ERROR Connection refused\n" +
				"Mar 22 10:02:01 server1 nginx[123]: INFO Ready\n",
		), nil, nil
	}

	result, err := tool.Execute(&LogAnalyzeParams{
		Source:          LogSourceSyslog,
		Keyword:         "error",
		Limit:           10,
		RemoteHost:      "10.0.0.100",
		RemoteUser:      "ops",
		RemotePort:      2222,
		RemoteKeyPath:   "/tmp/id_ed25519",
		RemoteProxyJump: "bastion",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	lr, ok := result.(*LogAnalyzeResult)
	if !ok {
		t.Fatal("expected LogAnalyzeResult")
	}
	if lr.TotalCount == 0 || lr.FilteredCount == 0 {
		t.Fatalf("expected remote log entries, got %+v", lr)
	}
	if gotName != "ssh" {
		t.Fatalf("expected ssh command, got %s", gotName)
	}
	if !strings.Contains(strings.Join(gotArgs, " "), "ops@10.0.0.100") {
		t.Fatalf("unexpected ssh args: %q", strings.Join(gotArgs, " "))
	}
}

func TestLogAnalyzeTool_FilterLogs(t *testing.T) {
	tool := NewLogAnalyzeTool(nil)

	now := time.Now()
	entries := []*LogEntry{
		{
			Timestamp: now.Add(-2 * time.Hour),
			Level:     LogLevelError,
			Message:   "Error: connection failed",
			Host:      "server1",
		},
		{
			Timestamp: now.Add(-1 * time.Hour),
			Level:     LogLevelWarning,
			Message:   "Warning: low memory",
			Host:      "server2",
		},
		{
			Timestamp: now,
			Level:     LogLevelInfo,
			Message:   "Info: service started",
			Host:      "server1",
		},
	}

	tests := []struct {
		name          string
		params        *LogAnalyzeParams
		expectedCount int
	}{
		{
			name: "filter by keyword",
			params: &LogAnalyzeParams{
				Source:        LogSourceSyslog,
				Keyword:       "Error",
				CaseSensitive: false,
			},
			expectedCount: 1,
		},
		{
			name: "filter by level",
			params: &LogAnalyzeParams{
				Source: LogSourceSyslog,
				Level:  LogLevelWarning,
			},
			expectedCount: 1,
		},
		{
			name: "filter by time range",
			params: &LogAnalyzeParams{
				Source:    LogSourceSyslog,
				StartTime: now.Add(-2 * time.Hour),
				EndTime:   now.Add(-1 * time.Hour),
			},
			expectedCount: 2,
		},
		{
			name: "no filter",
			params: &LogAnalyzeParams{
				Source: LogSourceSyslog,
			},
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := tool.filterLogs(entries, tt.params)
			if len(filtered) != tt.expectedCount {
				t.Errorf("expected %d entries, got %d", tt.expectedCount, len(filtered))
			}
		})
	}
}

func TestLogAnalyzeTool_AggregateLogs(t *testing.T) {
	tool := NewLogAnalyzeTool(nil)

	entries := []*LogEntry{
		{Timestamp: time.Now(), Level: LogLevelError, Host: "server1", Message: "error1"},
		{Timestamp: time.Now(), Level: LogLevelError, Host: "server1", Message: "error2"},
		{Timestamp: time.Now(), Level: LogLevelWarning, Host: "server2", Message: "warning1"},
	}

	aggregated := tool.aggregateLogs(entries, "host")

	if len(aggregated.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(aggregated.Groups))
	}

	if aggregated.Groups["server1"].Count != 2 {
		t.Errorf("expected server1 count=2, got %d", aggregated.Groups["server1"].Count)
	}

	if aggregated.Groups["server2"].Count != 1 {
		t.Errorf("expected server2 count=1, got %d", aggregated.Groups["server2"].Count)
	}
}

func TestLogAnalyzeTool_DetectAnomalies(t *testing.T) {
	tool := NewLogAnalyzeTool(nil)

	entries := []*LogEntry{
		{
			Timestamp: time.Now(),
			Level:     LogLevelError,
			Message:   "Error: connection failed",
			Host:      "server1",
		},
		{
			Timestamp: time.Now(),
			Level:     LogLevelInfo,
			Message:   "Info: service started",
			Host:      "server1",
		},
	}

	anomalies := tool.detectAnomalies(entries)

	if len(anomalies) != 1 {
		t.Errorf("expected 1 anomaly, got %d", len(anomalies))
	}

	if anomalies[0].Type != "error_detected" {
		t.Errorf("expected error_detected, got %s", anomalies[0].Type)
	}
}

func BenchmarkLogAnalyzeTool_Execute(b *testing.B) {
	tmpDir := b.TempDir()
	logFile := filepath.Join(tmpDir, "syslog.log")
	content := "" +
		"Mar 22 10:01:01 server1 nginx[123]: ERROR Connection refused\n" +
		"Mar 22 10:02:01 server1 nginx[123]: INFO Ready\n"
	if err := os.WriteFile(logFile, []byte(content), 0o644); err != nil {
		b.Fatalf("write benchmark log: %v", err)
	}
	b.Setenv("SECOPS_LOG_SYSLOG_PATHS", logFile)

	tool := NewLogAnalyzeTool(nil)
	params := &LogAnalyzeParams{
		Source:  LogSourceSyslog,
		Keyword: "error",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}
