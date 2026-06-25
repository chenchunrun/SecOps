package secops

import (
	"encoding/json"
	"testing"
	"time"

	attack "github.com/chenchunrun/SecOps/internal/security/attack"
)

func TestSourcePatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source LogSource
	}{
		{"syslog", LogSourceSyslog},
		{"system", LogSourceSystemLog},
		{"application", LogSourceApplication},
		{"audit", LogSourceAudit},
		{"default", LogSource("unknown")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			patterns := sourcePatterns(tc.source)
			if len(patterns) == 0 {
				t.Errorf("expected non-empty patterns for %s", tc.source)
			}
		})
	}
}

func TestSourcePatternsOverride(t *testing.T) {
	cases := []struct {
		name string
		source LogSource
		envKey string
	}{
		{"syslog", LogSourceSyslog, "SECOPS_LOG_SYSLOG_PATHS"},
		{"system", LogSourceSystemLog, "SECOPS_LOG_SYSTEM_PATHS"},
		{"application", LogSourceApplication, "SECOPS_LOG_APPLICATION_PATHS"},
		{"audit", LogSourceAudit, "SECOPS_LOG_AUDIT_PATHS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.envKey, "/custom/path")
			if got := sourcePatternsOverride(tc.source); got != "/custom/path" {
				t.Errorf("sourcePatternsOverride(%s) = %q, want /custom/path", tc.source, got)
			}
			t.Setenv(tc.envKey, "")
			if got := sourcePatternsOverride(tc.source); got != "" {
				t.Errorf("sourcePatternsOverride(%s) with empty env = %q, want empty", tc.source, got)
			}
		})
	}

	t.Run("unknown source returns empty", func(t *testing.T) {
		if got := sourcePatternsOverride(LogSource("nope")); got != "" {
			t.Errorf("expected empty override for unknown source, got %q", got)
		}
	})
}

func TestSplitCSV(t *testing.T) {
	t.Parallel()

	got := splitCSV("a, b ,,c")
	if len(got) != 3 {
		t.Fatalf("expected 3 parts, got %v", got)
	}
	want := map[string]bool{"a": true, "b": true, "c": true}
	for _, v := range got {
		if !want[v] {
			t.Errorf("unexpected part %q in %v", v, got)
		}
	}
}

func TestInferLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		msg  string
		want LogLevel
	}{
		{"system EMERGENCY shutdown", LogLevelEmergency},
		{"ALERT from sensor", LogLevelAlert},
		{"a CRITICAL failure", LogLevelCritical},
		{"ERROR connecting", LogLevelError},
		{"failed with ERR code", LogLevelError}, // "ERR " match
		{"WARNING threshold", LogLevelWarning},
		{"disk WARN high", LogLevelWarning},
		{"NOTICE message", LogLevelNotice},
		{"DEBUG trace", LogLevelDebug},
		{"just an info line", LogLevelInfo},
	}
	for _, tc := range tests {
		if got := inferLevel(tc.msg); got != tc.want {
			t.Errorf("inferLevel(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

func TestLogAnalyzeTool_GetGroupKey(t *testing.T) {
	t.Parallel()

	tool := NewLogAnalyzeTool(nil)
	entry := &LogEntry{Host: "h1", Process: "sshd", Level: LogLevelError, User: "root"}

	tests := []struct {
		by   string
		want string
	}{
		{"host", "h1"},
		{"process", "sshd"},
		{"level", string(LogLevelError)},
		{"user", "root"},
		{"unknown", ""},
	}
	for _, tc := range tests {
		if got := tool.getGroupKey(entry, tc.by); got != tc.want {
			t.Errorf("getGroupKey(by=%q) = %q, want %q", tc.by, got, tc.want)
		}
	}
}

func TestParseInfluxTimestamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   interface{}
		wantOk  bool
	}{
		{"float64", float64(1700000000), true},
		{"int64", int64(1700000000), true},
		{"json number", json.Number("1700000000"), true},
		{"bad json number", json.Number("abc"), false},
		{"rfc3339 string", "2024-01-02T15:04:05Z", true},
		{"int string", "1700000000", true},
		{"garbage string", "not-a-time", false},
		{"unsupported type", []int{1}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts, ok := parseInfluxTimestamp(tc.value)
			if ok != tc.wantOk {
				t.Fatalf("parseInfluxTimestamp(%v) ok = %v, want %v (ts=%v)", tc.value, ok, tc.wantOk, ts)
			}
			if ok && ts.IsZero() {
				t.Errorf("expected non-zero time for %v", tc.value)
			}
		})
	}
}

func TestParseInfluxFloat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		value  interface{}
		wantOk bool
	}{
		{"float64", float64(1.5), true},
		{"int64", int64(2), true},
		{"json number", json.Number("3.5"), true},
		{"bad json number", json.Number("xyz"), false},
		{"numeric string", "4.5", true},
		{"garbage string", "abc", false},
		{"unsupported", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, ok := parseInfluxFloat(tc.value)
			if ok != tc.wantOk {
				t.Fatalf("parseInfluxFloat(%v) ok = %v, want %v (v=%v)", tc.value, ok, tc.wantOk, v)
			}
		})
	}
}

func TestNetworkDiagnosticTool_AnalyzePing(t *testing.T) {
	t.Parallel()

	tool := NewNetworkDiagnosticTool(nil)

	t.Run("nil ping result", func(t *testing.T) {
		t.Parallel()
		r := &NetworkDiagnosticResult{}
		tool.analyzePing(r)
		if r.Status != "error" {
			t.Errorf("expected status error, got %q", r.Status)
		}
		if len(r.Issues) == 0 {
			t.Error("expected at least one issue")
		}
	})

	tests := []struct {
		name           string
		avg            float64
		loss           float64
		wantHealth     string
		wantLossIssue  bool
	}{
		{"good latency", 10, 0, "good", false},
		{"fair latency", 60, 0, "fair", false},
		{"poor latency", 150, 0, "poor", false},
		{"packet loss", 10, 50, "good", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &NetworkDiagnosticResult{
				PingResult: &PingResult{Avg: tc.avg, Loss: tc.loss},
			}
			tool.analyzePing(r)
			if r.LatencyHealth != tc.wantHealth {
				t.Errorf("latency health = %q, want %q", r.LatencyHealth, tc.wantHealth)
			}
			hasLossIssue := false
			for _, issue := range r.Issues {
				if issue == "" {
					continue
				}
				if tc.loss > 0 {
					hasLossIssue = true
				}
			}
			if hasLossIssue != tc.wantLossIssue {
				t.Errorf("loss issue presence = %v, want %v (issues=%v)", hasLossIssue, tc.wantLossIssue, r.Issues)
			}
		})
	}
}

func TestDefaultPolicyDays(t *testing.T) {
	t.Parallel()

	tests := []struct {
		system string
		key    string
		want   int
	}{
		{"aws", "password", 30},
		{"gcp", "cert", 180},
		{"aws", "cert", 365},
		{"aws", "unknown", 90},
		{"aws", "  Password  ", 30}, // trimmed + lowercased
	}
	for _, tc := range tests {
		if got := defaultPolicyDays(tc.system, tc.key); got != tc.want {
			t.Errorf("defaultPolicyDays(%q,%q) = %d, want %d", tc.system, tc.key, got, tc.want)
		}
	}
}

func TestStatusByAge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		age, policy int
		want        string
	}{
		{10, 0, "unknown"},    // non-positive policy
		{100, 90, "overdue"},  // age > policy
		{75, 90, "due"},       // age >= 0.8*policy
		{10, 90, "ok"},
	}
	for _, tc := range tests {
		if got := statusByAge(tc.age, tc.policy); got != tc.want {
			t.Errorf("statusByAge(%d,%d) = %q, want %q", tc.age, tc.policy, got, tc.want)
		}
	}
}

func TestNormalizeAlertEventType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		alert AlertInfo
		want  string
	}{
		{AlertInfo{Name: "failed login burst", Message: "x"}, "failed_login_burst"},
		{AlertInfo{Name: "brute force detected", Message: ""}, "failed_login_burst"},
		{AlertInfo{Name: "x", Message: "credential leaked"}, "credential_exposure"},
		{AlertInfo{Name: "x", Message: "remote ssh session"}, "unexpected_remote_execution"},
		{AlertInfo{Name: "x", Message: "generic noise"}, "security_alert"},
	}
	for _, tc := range tests {
		if got := normalizeAlertEventType(tc.alert); got != tc.want {
			t.Errorf("normalizeAlertEventType(name=%q,msg=%q) = %q, want %q",
				tc.alert.Name, tc.alert.Message, got, tc.want)
		}
	}
}

func TestNormalizeLogEventType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		entry *LogEntry
		want  string
	}{
		{&LogEntry{Message: "Failed password for user"}, "failed_login_burst"},
		{&LogEntry{Message: "Accepted password for root"}, "successful_login_after_failures"},
		{&LogEntry{Process: "sudo command"}, "suspicious_admin_privilege_use"},
		{&LogEntry{Message: "ssh remote command"}, "unexpected_remote_execution"},
		{&LogEntry{Message: "api key in log"}, "credential_exposure"},
		{&LogEntry{Message: "log cleared by user"}, "log_tamper"},
		{&LogEntry{Message: "ordinary line"}, "log_observation"},
	}
	for _, tc := range tests {
		if got := normalizeLogEventType(tc.entry); got != tc.want {
			t.Errorf("normalizeLogEventType(msg=%q) = %q, want %q", tc.entry.Message, got, tc.want)
		}
	}
}

func TestEvidenceFromResults(t *testing.T) {
	t.Parallel()

	t.Run("nil returns empty", func(t *testing.T) {
		t.Parallel()
		if got := evidenceFromLogAnalyzeResult(nil); got != nil {
			t.Error("expected nil for nil log result")
		}
		if got := evidenceFromTimelineResult(nil); got != nil {
			t.Error("expected nil for nil timeline result")
		}
		if got := evidenceFromAccessReviewResult(nil); got != nil {
			t.Error("expected nil for nil access result")
		}
	})

	t.Run("log entries map to evidence, nil entries skipped", func(t *testing.T) {
		t.Parallel()
		result := &LogAnalyzeResult{
			Entries: []*LogEntry{
				{Message: "failed password", Host: "h1", Process: "sshd", Level: LogLevelError, User: "root"},
				nil, // should be skipped
			},
		}
		events := evidenceFromLogAnalyzeResult(result)
		if len(events) != 1 {
			t.Fatalf("expected 1 evidence event, got %d", len(events))
		}
		if events[0].Source != "log_analyze" {
			t.Errorf("expected source log_analyze, got %q", events[0].Source)
		}
		if events[0].EventType != "failed_login_burst" {
			t.Errorf("expected event type failed_login_burst, got %q", events[0].EventType)
		}
	})

	t.Run("timeline events map to evidence", func(t *testing.T) {
		t.Parallel()
		result := &IncidentTimelineResult{
			Events: []TimelineEvent{
				{Type: "alert", Description: "brute force", Actor: "attacker", Severity: "high"},
			},
		}
		events := evidenceFromTimelineResult(result)
		if len(events) != 1 {
			t.Fatalf("expected 1 evidence event, got %d", len(events))
		}
		if events[0].EventType != "failed_login_burst" {
			t.Errorf("expected failed_login_burst, got %q", events[0].EventType)
		}
	})

	t.Run("access entries map to evidence", func(t *testing.T) {
		t.Parallel()
		result := &AccessReviewResult{
			Entries: []AccessEntry{
				{Principal: "admin", Permission: "iam:*", Resource: "*", Risk: "high"},
			},
		}
		events := evidenceFromAccessReviewResult(result)
		if len(events) != 1 {
			t.Fatalf("expected 1 evidence event, got %d", len(events))
		}
		if events[0].EventType != "suspicious_admin_privilege_use" {
			t.Errorf("expected suspicious_admin_privilege_use, got %q", events[0].EventType)
		}
	})
}

// keep the attack import used (EvidenceEvent reference above relies on it for type clarity)
var _ = attack.EvidenceEvent{}

// guard: ensure time import retained for fixture timestamps if extended later
var _ = time.Now
