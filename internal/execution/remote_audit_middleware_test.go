package execution

import (
	"context"
	"errors"
	"testing"

	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/stretchr/testify/require"
)

func TestAuditRemoteMiddlewareRecordsStartAndCompletion(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	audit.SetGlobalStore(store)
	t.Cleanup(func() { audit.SetGlobalStore(audit.NewInMemoryAuditStore()) })

	handler := AuditRemoteMiddleware()(func(ctx context.Context, req RemoteRequest) (RemoteResult, error) {
		return RemoteResult{
			WorkingDirectory: "/srv/app",
			RemoteTarget:     "ops@10.0.0.9",
		}, nil
	})

	_, err := handler(context.Background(), RemoteRequest{
		SessionID:        "sess-remote-1",
		ToolName:         "bash",
		Description:      "check status",
		TargetHost:       "10.0.0.9",
		TargetUser:       "ops",
		RemoteWorkingDir: "/srv/app",
		RemoteEnv:        "prod",
		Command:          "systemctl status app",
	})
	require.NoError(t, err)

	events, err := store.ListEvents(&audit.AuditFilter{SessionID: "sess-remote-1"})
	require.NoError(t, err)
	require.Len(t, events, 2)
	require.Equal(t, audit.EventTypeCommandStarted, events[0].EventType)
	require.Equal(t, "remote_command_started", events[0].Action)
	require.Empty(t, events[0].Result)
	require.Equal(t, "remote_command_completed", events[1].Action)
	require.Equal(t, "ssh", events[0].Transport)
	require.Equal(t, "ops@10.0.0.9", events[0].TargetHost)
	require.Equal(t, "check status", events[0].Details["description"])
	require.NotContains(t, events[0].Details, "command")
}

func TestAuditRemoteMiddlewareRecordsFailureEventType(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	audit.SetGlobalStore(store)
	t.Cleanup(func() { audit.SetGlobalStore(audit.NewInMemoryAuditStore()) })

	handler := AuditRemoteMiddleware()(func(ctx context.Context, req RemoteRequest) (RemoteResult, error) {
		return RemoteResult{
			WorkingDirectory: "/srv/app",
			RemoteTarget:     "ops@10.0.0.9",
		}, errors.New("ssh failed")
	})

	_, err := handler(context.Background(), RemoteRequest{
		SessionID:   "sess-remote-2",
		ToolName:    "bash",
		Description: "failing remote command",
		TargetHost:  "10.0.0.9",
		TargetUser:  "ops",
		Command:     "hostname",
	})
	require.Error(t, err)

	events, listErr := store.ListEvents(&audit.AuditFilter{SessionID: "sess-remote-2"})
	require.NoError(t, listErr)
	require.Len(t, events, 2)
	require.Equal(t, audit.EventTypeCommandStarted, events[0].EventType)
	require.Equal(t, audit.EventTypeCommandFailed, events[1].EventType)
	require.Equal(t, audit.ResultFailure, events[1].Result)
	require.Equal(t, "ssh failed", events[1].ErrorMsg)
}
