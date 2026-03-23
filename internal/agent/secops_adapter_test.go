package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
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

func TestEnforceRiskDecision_MediumUserApproved(t *testing.T) {
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
		ID:    "call-medium-allow",
		Input: "password=ApprovedSecret",
	}

	if err := a.enforceRiskDecision(context.Background(), call, "admin"); err != nil {
		t.Fatalf("expected approval to pass, got %v", err)
	}
	if len(perms.requests) != 1 {
		t.Fatalf("expected exactly one permission request, got %d", len(perms.requests))
	}
}

func TestEnforceRiskDecision_MediumUserDenied(t *testing.T) {
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
