package execution

import (
	"context"
	"time"

	"github.com/chenchunrun/SecOps/internal/audit"
)

func AuditLocalMiddleware() LocalMiddleware {
	return func(next LocalHandler) LocalHandler {
		return func(ctx context.Context, req LocalRequest) (LocalResult, error) {
			startedAt := time.Now().UTC()
			recordLocalAuditStart(req, startedAt)

			result, err := next(ctx, req)
			recordLocalAuditCompletion(req, result, err, startedAt)
			return result, err
		}
	}
}

func recordLocalAuditStart(req LocalRequest, startedAt time.Time) {
	event := audit.NewAuditEventBuilder(audit.EventTypeCommandStarted).
		WithSession(req.SessionID).
		WithAction("local_command_started").
		WithResource("command", req.ToolName, req.WorkingDir).
		WithRemoteTarget("local", "", "", "").
		WithDetail("description", req.Description).
		WithDetail("background_requested", req.RunInBackground).
		WithDetail("started_at", startedAt.Format(time.RFC3339Nano)).
		Build()
	_ = audit.RecordGlobal(event)
}

func recordLocalAuditCompletion(req LocalRequest, result LocalResult, err error, startedAt time.Time) {
	eventType := audit.EventTypeCommandExecuted
	resultType := audit.ResultSuccess
	builder := audit.NewAuditEventBuilder(eventType).
		WithSession(req.SessionID).
		WithAction("local_command_completed").
		WithResource("command", req.ToolName, result.WorkingDirectory).
		WithRemoteTarget("local", "", "", "").
		WithDetail("description", req.Description).
		WithDetail("background_requested", req.RunInBackground).
		WithDetail("background", result.Background).
		WithDetail("shell_id", result.ShellID).
		WithDetail("started_at", startedAt.Format(time.RFC3339Nano))

	if err != nil {
		eventType = audit.EventTypeCommandFailed
		resultType = audit.ResultFailure
		builder = audit.NewAuditEventBuilder(eventType).
			WithSession(req.SessionID).
			WithAction("local_command_completed").
			WithResource("command", req.ToolName, result.WorkingDirectory).
			WithRemoteTarget("local", "", "", "").
			WithDetail("description", req.Description).
			WithDetail("background_requested", req.RunInBackground).
			WithDetail("background", result.Background).
			WithDetail("shell_id", result.ShellID).
			WithDetail("started_at", startedAt.Format(time.RFC3339Nano)).
			WithError(err.Error())
	}

	event := builder.WithResult(resultType).Build()
	_ = audit.RecordGlobal(event)
}
