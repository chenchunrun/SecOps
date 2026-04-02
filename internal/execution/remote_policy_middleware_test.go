package execution

import (
	"context"
	"testing"

	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/policy"
	"github.com/stretchr/testify/require"
)

func TestPolicyRemoteMiddlewareBlocksDeniedRequests(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	audit.SetGlobalStore(store)
	t.Cleanup(func() { audit.SetGlobalStore(audit.NewInMemoryAuditStore()) })

	handler := PolicyRemoteMiddleware()(func(ctx context.Context, req RemoteRequest) (RemoteResult, error) {
		return RemoteResult{Output: "should not run"}, nil
	})

	_, err := handler(context.Background(), RemoteRequest{
		SessionID:   "sess-remote-policy",
		ToolName:    "bash",
		Description: "restart service",
		TargetHost:  "10.0.0.9",
		TargetUser:  "ops",
		RemoteEnv:   "prod",
		PolicyDecision: &policy.Decision{
			Allowed: false,
			Reason:  "remote command denied by profile deny rule: \"rm -rf\"",
			AuditFields: map[string]any{
				"policy_type":   "deny_list",
				"policy_rule":   "rm -rf*",
				"policy_result": "deny",
			},
		},
	})
	require.EqualError(t, err, `remote command denied by profile deny rule: "rm -rf"`)

	events, listErr := store.ListEvents(&audit.AuditFilter{SessionID: "sess-remote-policy"})
	require.NoError(t, listErr)
	require.Len(t, events, 1)
	require.Equal(t, audit.EventTypePermissionDenied, events[0].EventType)
	require.Equal(t, "remote_policy_deny", events[0].Action)
	require.Equal(t, "deny_list", events[0].Details["policy_type"])
}

func TestPolicyRemoteMiddlewareAllowsApprovedRequests(t *testing.T) {
	t.Parallel()

	handler := PolicyRemoteMiddleware()(func(ctx context.Context, req RemoteRequest) (RemoteResult, error) {
		return RemoteResult{Output: "ok"}, nil
	})

	res, err := handler(context.Background(), RemoteRequest{
		PolicyDecision: &policy.Decision{Allowed: true},
	})
	require.NoError(t, err)
	require.Equal(t, "ok", res.Output)
}
