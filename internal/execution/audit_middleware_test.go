package execution

import (
	"context"
	"errors"
	"testing"

	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/stretchr/testify/require"
)

func TestAuditLocalMiddlewareRecordsStartAndCompletion(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	audit.SetGlobalStore(store)
	t.Cleanup(func() { audit.SetGlobalStore(audit.NewInMemoryAuditStore()) })

	handler := AuditLocalMiddleware()(func(ctx context.Context, req LocalRequest) (LocalResult, error) {
		return LocalResult{WorkingDirectory: req.WorkingDir}, nil
	})

	_, err := handler(context.Background(), LocalRequest{
		SessionID:   "sess-1",
		ToolName:    "bash",
		Description: "list files",
		WorkingDir:  "/tmp/demo",
	})
	require.NoError(t, err)

	events, err := store.ListEvents(&audit.AuditFilter{SessionID: "sess-1"})
	require.NoError(t, err)
	require.Len(t, events, 2)
	require.Equal(t, audit.EventTypeCommandStarted, events[0].EventType)
	require.Equal(t, "local_command_started", events[0].Action)
	require.Empty(t, events[0].Result)
	require.Equal(t, "local_command_completed", events[1].Action)
	require.Equal(t, "bash", events[0].ResourceName)
	require.Equal(t, "local", events[0].Transport)
	require.Equal(t, "list files", events[0].Details["description"])
	require.NotContains(t, events[0].Details, "command")
}

func TestAuditLocalMiddlewareRecordsFailureEventType(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	audit.SetGlobalStore(store)
	t.Cleanup(func() { audit.SetGlobalStore(audit.NewInMemoryAuditStore()) })

	handler := AuditLocalMiddleware()(func(ctx context.Context, req LocalRequest) (LocalResult, error) {
		return LocalResult{WorkingDirectory: req.WorkingDir}, errors.New("boom")
	})

	_, err := handler(context.Background(), LocalRequest{
		SessionID:   "sess-2",
		ToolName:    "bash",
		Description: "failing command",
		WorkingDir:  "/tmp/demo",
	})
	require.Error(t, err)

	events, listErr := store.ListEvents(&audit.AuditFilter{SessionID: "sess-2"})
	require.NoError(t, listErr)
	require.Len(t, events, 2)
	require.Equal(t, audit.EventTypeCommandStarted, events[0].EventType)
	require.Equal(t, audit.EventTypeCommandFailed, events[1].EventType)
	require.Equal(t, audit.ResultFailure, events[1].Result)
	require.Equal(t, "boom", events[1].ErrorMsg)
}
