package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/pubsub"
	"github.com/chenchunrun/SecOps/internal/security"
)

type testSecOpsTool struct{}

func (t *testSecOpsTool) Type() secops.ToolType { return secops.ToolTypeLogAnalyze }
func (t *testSecOpsTool) Name() string          { return "Log Analyzer" }
func (t *testSecOpsTool) Description() string   { return "test" }
func (t *testSecOpsTool) RequiredCapabilities() []string {
	return []string{"log:read", "log:analyze"}
}
func (t *testSecOpsTool) Execute(params interface{}) (interface{}, error) {
	return map[string]string{"ok": "true"}, nil
}
func (t *testSecOpsTool) ValidateParams(params interface{}) error { return nil }

func TestAdapterInfoUsesToolTypeName(t *testing.T) {
	t.Parallel()

	a := &Adapter{tool: &testSecOpsTool{}}
	info := a.Info()

	if info.Name != string(secops.ToolTypeLogAnalyze) {
		t.Fatalf("expected tool name %q, got %q", secops.ToolTypeLogAnalyze, info.Name)
	}
}

func TestRegisterDefaultSecOpsToolSet_All18(t *testing.T) {
	t.Parallel()

	registry := secops.NewSecOpsToolRegistry()
	if err := RegisterDefaultSecOpsToolSet(registry); err != nil {
		t.Fatalf("RegisterDefaultSecOpsToolSet() error = %v", err)
	}

	all := registry.GetAll()
	if len(all) != 18 {
		t.Fatalf("expected 18 secops tools, got %d", len(all))
	}

	expected := []secops.ToolType{
		secops.ToolTypeLogAnalyze,
		secops.ToolTypeMonitoringQuery,
		secops.ToolTypeComplianceCheck,
		secops.ToolTypeCertificateAudit,
		secops.ToolTypeSecurityScan,
		secops.ToolTypeConfigurationAudit,
		secops.ToolTypeNetworkDiagnostic,
		secops.ToolTypeDatabaseQuery,
		secops.ToolTypeBackupCheck,
		secops.ToolTypeReplicationStatus,
		secops.ToolTypeSecretAudit,
		secops.ToolTypeRotationCheck,
		secops.ToolTypeAccessReview,
		secops.ToolTypeInfrastructureQuery,
		secops.ToolTypeDeploymentStatus,
		secops.ToolTypeAlertCheck,
		secops.ToolTypeIncidentTimeline,
		secops.ToolTypeResourceMonitor,
	}
	for _, tt := range expected {
		if _, ok := all[string(tt)]; !ok {
			t.Fatalf("missing registered secops tool: %s", tt)
		}
	}
}

func TestRegisterSecOpsTools_CountMatchesRegistry(t *testing.T) {
	t.Parallel()

	registry := secops.NewSecOpsToolRegistry()
	if err := RegisterDefaultSecOpsToolSet(registry); err != nil {
		t.Fatalf("RegisterDefaultSecOpsToolSet() error = %v", err)
	}
	tools := RegisterSecOpsTools(registry, nil)
	if len(tools) != 18 {
		t.Fatalf("expected 18 adapter tools, got %d", len(tools))
	}
	seen := map[string]bool{}
	for _, tool := range tools {
		seen[tool.Info().Name] = true
	}
	for name := range registry.GetAll() {
		if !seen[name] {
			t.Fatalf("adapter missing tool %q", name)
		}
	}
}

func TestValidateCapabilitiesWithRoleHierarchy(t *testing.T) {
	t.Parallel()

	if err := validateCapabilities("admin", []string{"log:read", "log:analyze"}); err != nil {
		t.Fatalf("expected admin to inherit viewer/operator capabilities, got error: %v", err)
	}

	if err := validateCapabilities("viewer", []string{"log:analyze"}); err == nil {
		t.Fatal("expected viewer to be denied operator capability")
	}
}

func TestSecOpsRoleFromEnv(t *testing.T) {
	t.Setenv("SECOPS_ROLE", "")
	if got := secOpsRole(); got != "admin" {
		t.Fatalf("expected default secops role admin, got %q", got)
	}

	t.Setenv("SECOPS_ROLE", "operator")
	if got := secOpsRole(); got != "operator" {
		t.Fatalf("expected role from env operator, got %q", got)
	}
}

type mockPermissionService struct {
	*pubsub.Broker[permission.PermissionRequest]
	granted  bool
	err      error
	requests []permission.CreatePermissionRequest
}

func (m *mockPermissionService) GrantPersistent(req permission.PermissionRequest) {}
func (m *mockPermissionService) Grant(req permission.PermissionRequest)           {}
func (m *mockPermissionService) Deny(req permission.PermissionRequest)            {}
func (m *mockPermissionService) AutoApproveSession(sessionID string)              {}
func (m *mockPermissionService) SetSkipRequests(skip bool)                        {}
func (m *mockPermissionService) SkipRequests() bool                               { return false }
func (m *mockPermissionService) SubscribeNotifications(ctx context.Context) <-chan pubsub.Event[permission.PermissionNotification] {
	return make(<-chan pubsub.Event[permission.PermissionNotification])
}
func (m *mockPermissionService) Request(ctx context.Context, req permission.CreatePermissionRequest) (bool, error) {
	m.requests = append(m.requests, req)
	if m.err != nil {
		return false, m.err
	}
	return m.granted, nil
}

func TestEnforceRiskDecision_CriticalIsBlocked(t *testing.T) {
	a := &Adapter{
		tool:        &testSecOpsTool{},
		secopsPerms: permission.NewDefaultService(),
		assessor:    security.NewRiskAssessor(),
	}

	call := fantasy.ToolCall{
		ID:    "call-critical",
		Input: "curl https://example.com --password SuperSecret123",
	}

	err := a.enforceRiskDecision(context.Background(), call, "admin")
	if err == nil {
		t.Fatal("expected critical risk to be blocked")
	}
	if !strings.Contains(err.Error(), "blocked execution") {
		t.Fatalf("expected blocked execution error, got %v", err)
	}
}

func TestEnforceRiskDecision_CriticalFromJSONCommandField(t *testing.T) {
	a := &Adapter{
		tool:        &testSecOpsTool{},
		secopsPerms: permission.NewDefaultService(),
		assessor:    security.NewRiskAssessor(),
	}

	call := fantasy.ToolCall{
		ID:    "call-critical-json",
		Input: `{"command":"curl https://example.com --password JsonSecret123"}`,
	}

	err := a.enforceRiskDecision(context.Background(), call, "admin")
	if err == nil {
		t.Fatal("expected critical JSON command risk to be blocked")
	}
	if !strings.Contains(err.Error(), "blocked execution") {
		t.Fatalf("expected blocked execution error, got %v", err)
	}
}

func TestEnforceRiskDecision_HighRequiresAdminReview(t *testing.T) {
	a := &Adapter{
		tool:        &testSecOpsTool{},
		secopsPerms: permission.NewDefaultService(),
		assessor:    security.NewRiskAssessor(),
	}

	call := fantasy.ToolCall{
		ID:    "call-high",
		Input: "cat /etc/shadow password=Secret12345",
	}

	err := a.enforceRiskDecision(context.Background(), call, "admin")
	if err == nil {
		t.Fatal("expected high risk to require admin review")
	}
	if !strings.Contains(err.Error(), "requires admin review") {
		t.Fatalf("expected admin review error, got %v", err)
	}
}

func TestEnforceRiskDecision_MediumNeedsPermissionService(t *testing.T) {
	a := &Adapter{
		tool:        &testSecOpsTool{},
		secopsPerms: permission.NewDefaultService(),
		assessor:    security.NewRiskAssessor(),
	}

	call := fantasy.ToolCall{
		ID:    "call-medium",
		Input: "password=MediumRiskSecret",
	}

	err := a.enforceRiskDecision(context.Background(), call, "admin")
	if err == nil {
		t.Fatal("expected medium risk to require user confirmation")
	}
	if !strings.Contains(err.Error(), "requires user confirmation") {
		t.Fatalf("expected user confirmation error, got %v", err)
	}
}

func TestNormalizeSecOpsParams(t *testing.T) {
	t.Parallel()

	t.Run("network diagnostic maps legacy fields and command", func(t *testing.T) {
		in := map[string]interface{}{
			"diagnostic_type": "ping",
			"command":         "ping -c 3 8.8.8.8",
		}
		got := normalizeSecOpsParams(secops.ToolTypeNetworkDiagnostic, in)
		if fmt.Sprint(got["type"]) != "ping" {
			t.Fatalf("expected type=ping, got %v", got["type"])
		}
		if fmt.Sprint(got["target"]) != "8.8.8.8" {
			t.Fatalf("expected target=8.8.8.8, got %v", got["target"])
		}
	})

	t.Run("compliance check defaults framework", func(t *testing.T) {
		got := normalizeSecOpsParams(secops.ToolTypeComplianceCheck, map[string]interface{}{})
		if fmt.Sprint(got["framework"]) != "cis" {
			t.Fatalf("expected framework=cis, got %v", got["framework"])
		}
	})

	t.Run("infrastructure query defaults required fields", func(t *testing.T) {
		got := normalizeSecOpsParams(secops.ToolTypeInfrastructureQuery, map[string]interface{}{})
		if fmt.Sprint(got["system_type"]) != "terraform" {
			t.Fatalf("expected system_type=terraform, got %v", got["system_type"])
		}
		if fmt.Sprint(got["query_type"]) != "resources" {
			t.Fatalf("expected query_type=resources, got %v", got["query_type"])
		}
	})
}

func TestEnforceRiskDecision_MediumUserApproved(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	audit.SetGlobalStore(store)
	t.Cleanup(func() { audit.SetGlobalStore(audit.NewInMemoryAuditStore()) })

	perms := &mockPermissionService{
		Broker:  pubsub.NewBroker[permission.PermissionRequest](),
		granted: true,
	}
	a := &Adapter{
		tool:        &testSecOpsTool{},
		perms:       perms,
		secopsPerms: permission.NewDefaultService(),
		assessor:    security.NewRiskAssessor(),
	}

	call := fantasy.ToolCall{
		ID: "call-medium-allow",
		Input: `{
			"command":"echo password=ApprovedSecret",
			"remote_host":"10.0.0.8",
			"remote_user":"ops",
			"remote_env":"prod",
			"remote_profile":"prod-web"
		}`,
	}

	if err := a.enforceRiskDecision(context.Background(), call, "admin"); err != nil {
		t.Fatalf("expected approval to pass, got %v", err)
	}
	if len(perms.requests) != 1 {
		t.Fatalf("expected exactly one permission request, got %d", len(perms.requests))
	}
	req := perms.requests[0]
	if req.Transport != "ssh" {
		t.Fatalf("expected transport ssh, got %q", req.Transport)
	}
	if req.TargetHost != "ops@10.0.0.8" {
		t.Fatalf("expected target host ops@10.0.0.8, got %q", req.TargetHost)
	}
	if req.TargetEnv != "prod" {
		t.Fatalf("expected target env prod, got %q", req.TargetEnv)
	}
	if req.TargetID != "prod-web" {
		t.Fatalf("expected target id prod-web, got %q", req.TargetID)
	}
	if req.Path != "ssh://ops@10.0.0.8" {
		t.Fatalf("expected path ssh://ops@10.0.0.8, got %q", req.Path)
	}

	events, err := store.ListEvents(&audit.AuditFilter{SessionID: "secops"})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("expected at least 2 audit events, got %d", len(events))
	}
	last := events[len(events)-1]
	if last.TargetHost != "ops@10.0.0.8" || last.Transport != "ssh" {
		t.Fatalf("unexpected remote metadata in audit event: %#v", last)
	}
}

func TestEnforceRiskDecision_MediumUserDenied(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	audit.SetGlobalStore(store)
	t.Cleanup(func() { audit.SetGlobalStore(audit.NewInMemoryAuditStore()) })

	perms := &mockPermissionService{
		Broker:  pubsub.NewBroker[permission.PermissionRequest](),
		granted: false,
	}
	a := &Adapter{
		tool:        &testSecOpsTool{},
		perms:       perms,
		secopsPerms: permission.NewDefaultService(),
		assessor:    security.NewRiskAssessor(),
	}

	call := fantasy.ToolCall{
		ID:    "call-medium-deny",
		Input: "password=DeniedSecret",
	}

	err := a.enforceRiskDecision(context.Background(), call, "admin")
	if !errors.Is(err, permission.ErrorPermissionDenied) {
		t.Fatalf("expected permission denied error, got %v", err)
	}

	events, listErr := store.ListEvents(&audit.AuditFilter{EventType: audit.EventTypePermissionDenied})
	if listErr != nil {
		t.Fatalf("list audit events: %v", listErr)
	}
	if len(events) == 0 {
		t.Fatal("expected permission_denied audit event")
	}
}

func TestEnforceRiskDecision_OpsAgentLowRiskNeedsConfirmation(t *testing.T) {
	perms := &mockPermissionService{
		Broker:  pubsub.NewBroker[permission.PermissionRequest](),
		granted: true,
	}
	a := &Adapter{
		tool:        &testSecOpsTool{},
		perms:       perms,
		secopsPerms: permission.NewDefaultService(),
		assessor:    security.NewRiskAssessor(),
	}

	call := fantasy.ToolCall{
		ID:    "call-ops-low",
		Input: "{}",
	}

	if err := a.enforceRiskDecision(context.Background(), call, string(RoleOpsAgent)); err != nil {
		t.Fatalf("expected ops agent low-risk approval to pass, got %v", err)
	}
	if len(perms.requests) != 1 {
		t.Fatalf("expected exactly one permission request for ops agent, got %d", len(perms.requests))
	}
}

func TestExecuteAndRespond_CapabilityDenied(t *testing.T) {
	t.Setenv("SECOPS_ROLE", "viewer")

	a := &Adapter{
		tool:        &testSecOpsTool{},
		secopsPerms: permission.NewDefaultService(),
		assessor:    security.NewRiskAssessor(),
	}

	resp, err := a.executeAndRespond(context.Background(), fantasy.ToolCall{ID: "call-cap-deny", Input: "{}"}, map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected capability denial to return tool error response")
	}
	if !strings.Contains(resp.Content, "capability denied") {
		t.Fatalf("expected capability denied message, got %q", resp.Content)
	}
}

func TestExecuteAndRespond_LowRiskSuccess(t *testing.T) {
	t.Setenv("SECOPS_ROLE", "admin")

	a := &Adapter{
		tool:        &testSecOpsTool{},
		secopsPerms: permission.NewDefaultService(),
		assessor:    security.NewRiskAssessor(),
	}

	resp, err := a.executeAndRespond(context.Background(), fantasy.ToolCall{ID: "call-ok", Input: "{}"}, map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("expected success response, got error content %q", resp.Content)
	}
	if !strings.Contains(resp.Content, "\"ok\":\"true\"") {
		t.Fatalf("unexpected success payload: %q", resp.Content)
	}
}

func TestRiskCandidatesFromInput(t *testing.T) {
	in := `{"target_path":"/etc/shadow","nested":{"query":"password=abc"},"items":[{"command":"curl x"}]}`
	candidates := riskCandidatesFromInput(in)

	if len(candidates) != 3 {
		t.Fatalf("expected 3 risk candidates, got %d: %#v", len(candidates), candidates)
	}
}

func TestParseRemoteContext(t *testing.T) {
	ctx := parseRemoteContext(`{
		"remote_host":"10.0.0.9",
		"remote_user":"ops",
		"remote_env":"staging",
		"remote_profile":"staging-web"
	}`)
	if ctx.Transport != "ssh" {
		t.Fatalf("expected ssh transport, got %q", ctx.Transport)
	}
	if ctx.TargetHost != "ops@10.0.0.9" {
		t.Fatalf("unexpected target host %q", ctx.TargetHost)
	}
	if ctx.TargetEnv != "staging" {
		t.Fatalf("unexpected target env %q", ctx.TargetEnv)
	}
	if ctx.TargetID != "staging-web" {
		t.Fatalf("unexpected target id %q", ctx.TargetID)
	}
}

func TestAdapterRunRejectsUnsafeRemoteSSHParams(t *testing.T) {
	t.Setenv("SECOPS_ROLE", "admin")
	store := audit.NewInMemoryAuditStore()
	audit.SetGlobalStore(store)
	t.Cleanup(func() { audit.SetGlobalStore(audit.NewInMemoryAuditStore()) })

	a := &Adapter{
		tool: &testSecOpsTool{},
	}

	resp, err := a.Run(context.Background(), fantasy.ToolCall{
		ID:    "call-unsafe-remote",
		Input: `{"remote_host":"-oProxyCommand=evil"}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected unsafe remote_host to be rejected")
	}
	if !strings.Contains(resp.Content, "invalid remote ssh parameters") {
		t.Fatalf("unexpected response content: %q", resp.Content)
	}

	events, err := store.ListEvents(&audit.AuditFilter{EventType: audit.EventTypePermissionDenied})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected permission_denied event for remote param validation failure")
	}
	last := events[len(events)-1]
	if last.Action != "remote_param_validation_failed" {
		t.Fatalf("unexpected action: %q", last.Action)
	}
	if got := last.Details["validation_reason_code"]; got != "host_dash_prefix" {
		t.Fatalf("unexpected validation_reason_code: %#v", got)
	}
	if got := last.Details["ssh_option_profile"]; got != "secops_default_v1" {
		t.Fatalf("unexpected ssh_option_profile: %#v", got)
	}
	if got := last.Details["remote_policy_source"]; got != "secops_permission_engine" {
		t.Fatalf("unexpected remote_policy_source: %#v", got)
	}
}

func TestAdapterRunAllowsSafeRemoteSSHParams(t *testing.T) {
	t.Setenv("SECOPS_ROLE", "admin")

	a := &Adapter{
		tool: &testSecOpsTool{},
	}

	resp, err := a.Run(context.Background(), fantasy.ToolCall{
		ID: "call-safe-remote",
		Input: `{
			"remote_host":"10.0.0.9",
			"remote_user":"ops",
			"remote_port":22
		}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("expected safe remote params to pass, got %q", resp.Content)
	}
}

func TestEnforceRiskDecision_RemoteAuditIncludesProfileDetails(t *testing.T) {
	t.Setenv("SECOPS_ROLE", "admin")
	store := audit.NewInMemoryAuditStore()
	audit.SetGlobalStore(store)
	t.Cleanup(func() { audit.SetGlobalStore(audit.NewInMemoryAuditStore()) })

	a := &Adapter{
		tool:        &testSecOpsTool{},
		secopsPerms: permission.NewDefaultService(),
		assessor:    security.NewRiskAssessor(),
	}

	err := a.enforceRiskDecision(context.Background(), fantasy.ToolCall{
		ID:    "call-remote-audit-profile",
		Input: `{"remote_host":"10.0.0.9","remote_user":"ops","remote_env":"prod","remote_profile":"prod-web"}`,
	}, "admin")
	if err != nil {
		t.Fatalf("unexpected enforceRiskDecision error: %v", err)
	}

	events, listErr := store.ListEvents(&audit.AuditFilter{EventType: audit.EventTypePermissionRequest})
	if listErr != nil {
		t.Fatalf("list audit events: %v", listErr)
	}
	if len(events) == 0 {
		t.Fatal("expected permission_request audit events")
	}
	last := events[len(events)-1]
	if got := last.Details["ssh_option_profile"]; got != "secops_default_v1" {
		t.Fatalf("unexpected ssh_option_profile: %#v", got)
	}
	if got := last.Details["remote_policy_source"]; got != "secops_permission_engine" {
		t.Fatalf("unexpected remote_policy_source: %#v", got)
	}
}
