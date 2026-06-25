package secops

import (
	"testing"
)

// allTools constructs every built-in tool. Constructors accept a nil registry
// (as the existing tests do) since the accessor methods don't depend on it.
func allTools() []SecOpsTool {
	return []SecOpsTool{
		NewAccessReviewTool(nil),
		NewAlertCheckTool(nil),
		NewAttackReasonTool(nil),
		NewBackupCheckTool(nil),
		NewCertificateAuditTool(nil),
		NewComplianceCheckTool(nil),
		NewConfigurationAuditTool(nil),
		NewDatabaseQueryTool(nil),
		NewDeploymentStatusTool(nil),
		NewIncidentAssessTool(nil),
		NewIncidentTimelineTool(nil),
		NewInfrastructureQueryTool(nil),
		NewLogAnalyzeTool(nil),
		NewMonitoringQueryTool(nil),
		NewNetworkDiagnosticTool(nil),
		NewReplicationStatusTool(nil),
		NewResourceMonitorTool(nil),
		NewRotationCheckTool(nil),
		NewSecretAuditTool(nil),
		NewSecurityScanTool(nil),
	}
}

// TestAllTools_Accessors covers the trivial Type/Name/Description/RequiredCapabilities
// accessors for every built-in tool. These small methods were previously uncovered
// across many tools; exercising them directly gives broad, cheap coverage.
func TestAllTools_Accessors(t *testing.T) {
	t.Parallel()

	tools := allTools()
	if len(tools) == 0 {
		t.Fatal("expected at least one tool")
	}

	seenTypes := make(map[ToolType]bool)
	for _, tool := range tools {
		toolType := tool.Type()
		if toolType == "" {
			t.Errorf("expected non-empty ToolType, got empty for %T", tool)
		}
		if seenTypes[toolType] {
			t.Errorf("duplicate ToolType %q across tools", toolType)
		}
		seenTypes[toolType] = true

		if name := tool.Name(); name == "" {
			t.Errorf("expected non-empty Name for %v", toolType)
		}
		if desc := tool.Description(); desc == "" {
			t.Errorf("expected non-empty Description for %v", toolType)
		}
		// RequiredCapabilities may legitimately be empty, but must not panic and must return a slice.
		_ = tool.RequiredCapabilities()
	}
}

func TestRegistry_GetListGetAll(t *testing.T) {
	t.Parallel()

	registry := NewSecOpsToolRegistry()

	// Manually register every tool to exercise Register + Get/List/GetAll mechanics.
	for _, tool := range allTools() {
		if err := registry.Register(tool); err != nil {
			t.Fatalf("Register(%v) error = %v", tool.Type(), err)
		}
	}

	tools := registry.List()
	if len(tools) != len(allTools()) {
		t.Fatalf("List size %d != expected %d", len(tools), len(allTools()))
	}

	for _, tool := range tools {
		fetched, ok := registry.Get(tool.Type())
		if !ok {
			t.Errorf("Get(%v) returned not-ok", tool.Type())
			continue
		}
		if fetched.Type() != tool.Type() {
			t.Errorf("Get(%v) returned wrong type %v", tool.Type(), fetched.Type())
		}
	}

	all := registry.GetAll()
	if len(all) != len(tools) {
		t.Errorf("GetAll size %d != List size %d", len(all), len(tools))
	}

	if _, ok := registry.Get(ToolType("__does_not_exist__")); ok {
		t.Error("expected Get to return false for unknown type")
	}
}

// TestStandaloneHelpers exercises package-level helpers that had no direct coverage.
func TestStandaloneHelpers(t *testing.T) {
	t.Parallel()

	t.Run("normalizeAlertStatus", func(t *testing.T) {
		t.Parallel()
		cases := map[string]string{
			"firing": "firing", "active": "firing", "triggered": "firing",
			"resolved": "resolved", "inactive": "resolved",
			"acknowledged": "acknowledged", "suppressed": "acknowledged",
			"": "firing", "weird": "firing",
		}
		for in, want := range cases {
			if got := normalizeAlertStatus(in); got != want {
				t.Errorf("normalizeAlertStatus(%q) = %q, want %q", in, got, want)
			}
		}
	})

	t.Run("normalizeDatadogState", func(t *testing.T) {
		t.Parallel()
		cases := map[string]string{
			"Alert": "firing", "WARN": "firing", "No Data": "acknowledged",
			"OK": "resolved", "": "firing", "weird": "firing",
		}
		for in, want := range cases {
			if got := normalizeDatadogState(in); got != want {
				t.Errorf("normalizeDatadogState(%q) = %q, want %q", in, got, want)
			}
		}
	})

	t.Run("normalizePagerDutyStatus", func(t *testing.T) {
		t.Parallel()
		cases := map[string]string{
			"triggered": "firing", "resolved": "resolved", "acknowledged": "acknowledged",
			"": "firing", "unknown-state": "firing",
		}
		for in, want := range cases {
			if got := normalizePagerDutyStatus(in); got != want {
				t.Errorf("normalizePagerDutyStatus(%q) = %q, want %q", in, got, want)
			}
		}
	})

	t.Run("defaultIfEmpty", func(t *testing.T) {
		t.Parallel()
		if got := defaultIfEmpty("", "fallback"); got != "fallback" {
			t.Errorf("defaultIfEmpty empty = %q, want fallback", got)
		}
		if got := defaultIfEmpty("   ", "fallback"); got != "fallback" {
			t.Errorf("defaultIfEmpty whitespace = %q, want fallback", got)
		}
		if got := defaultIfEmpty("value", "fallback"); got != "value" {
			t.Errorf("defaultIfEmpty value = %q, want value", got)
		}
	})

	t.Run("formatRFC3339OrNow", func(t *testing.T) {
		t.Parallel()
		if got := formatRFC3339OrNow("2024-01-02T15:04:05Z"); got == "" {
			t.Error("expected non-empty for valid RFC3339 input")
		}
		if got := formatRFC3339OrNow(""); got == "" {
			t.Error("expected non-empty timestamp for empty input")
		}
		if got := formatRFC3339OrNow("not-a-date"); got == "" {
			t.Error("expected non-empty timestamp for invalid input")
		}
	})
}
