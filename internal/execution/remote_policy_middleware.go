package execution

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/chenchunrun/SecOps/internal/audit"
)

func PolicyRemoteMiddleware() RemoteMiddleware {
	return func(next RemoteHandler) RemoteHandler {
		return func(ctx context.Context, req RemoteRequest) (RemoteResult, error) {
			if req.PolicyDecision == nil || req.PolicyDecision.Allowed {
				return next(ctx, req)
			}

			recordRemotePolicyDeny(req)

			reason := strings.TrimSpace(req.PolicyDecision.Reason)
			if reason == "" {
				reason = "remote execution denied by policy"
			}
			return RemoteResult{}, errors.New(reason)
		}
	}
}

func recordRemotePolicyDeny(req RemoteRequest) {
	fields := map[string]any{}
	if req.PolicyDecision != nil && req.PolicyDecision.AuditFields != nil {
		fields = req.PolicyDecision.AuditFields
	}

	event := audit.NewAuditEventBuilder(audit.EventTypePermissionDenied).
		WithSession(req.SessionID).
		WithAction("remote_policy_deny").
		WithResource("command", req.ToolName, "ssh://"+formatRemoteTarget(req.TargetUser, req.TargetHost)).
		WithResult(audit.ResultDenied).
		WithRemoteTarget("ssh", formatRemoteTarget(req.TargetUser, req.TargetHost), req.RemoteEnv, req.TargetID).
		WithDetail("description", req.Description).
		WithDetail("policy_type", strings.TrimSpace(fmt.Sprint(fields["policy_type"]))).
		WithDetail("policy_rule", strings.TrimSpace(fmt.Sprint(fields["policy_rule"]))).
		WithDetail("policy_result", strings.TrimSpace(fmt.Sprint(fields["policy_result"]))).
		Build()
	if req.PolicyDecision != nil {
		event.ErrorMsg = req.PolicyDecision.Reason
	}
	_ = audit.RecordGlobal(event)
}
