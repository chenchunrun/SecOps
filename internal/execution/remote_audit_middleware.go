package execution

import (
	"context"
	"time"

	"github.com/chenchunrun/SecOps/internal/audit"
)

func AuditRemoteMiddleware() RemoteMiddleware {
	return func(next RemoteHandler) RemoteHandler {
		return func(ctx context.Context, req RemoteRequest) (RemoteResult, error) {
			startedAt := time.Now().UTC()
			recordRemoteAuditStart(req, startedAt)

			result, err := next(ctx, req)
			recordRemoteAuditCompletion(req, result, err, startedAt)
			return result, err
		}
	}
}

func recordRemoteAuditStart(req RemoteRequest, startedAt time.Time) {
	event := audit.NewAuditEventBuilder(audit.EventTypeCommandExecuted).
		WithSession(req.SessionID).
		WithAction("remote_command_started").
		WithResource("command", req.ToolName, req.RemoteWorkingDir).
		WithRemoteTarget("ssh", formatRemoteTarget(req.TargetUser, req.TargetHost), req.RemoteEnv, req.TargetID).
		WithDetail("description", req.Description).
		WithDetail("started_at", startedAt.Format(time.RFC3339Nano)).
		Build()
	event.Result = audit.ResultSuccess
	_ = audit.RecordGlobal(event)
}

func recordRemoteAuditCompletion(req RemoteRequest, result RemoteResult, err error, startedAt time.Time) {
	eventType := audit.EventTypeCommandExecuted
	resultType := audit.ResultSuccess
	builder := audit.NewAuditEventBuilder(eventType).
		WithSession(req.SessionID).
		WithAction("remote_command_completed").
		WithResource("command", req.ToolName, result.WorkingDirectory).
		WithRemoteTarget("ssh", result.RemoteTarget, req.RemoteEnv, req.TargetID).
		WithDetail("description", req.Description).
		WithDetail("started_at", startedAt.Format(time.RFC3339Nano))

	if err != nil {
		eventType = audit.EventTypeCommandFailed
		resultType = audit.ResultFailure
		builder = audit.NewAuditEventBuilder(eventType).
			WithSession(req.SessionID).
			WithAction("remote_command_completed").
			WithResource("command", req.ToolName, result.WorkingDirectory).
			WithRemoteTarget("ssh", result.RemoteTarget, req.RemoteEnv, req.TargetID).
			WithDetail("description", req.Description).
			WithDetail("started_at", startedAt.Format(time.RFC3339Nano)).
			WithError(err.Error())
	}

	event := builder.WithResult(resultType).Build()
	_ = audit.RecordGlobal(event)
}
