package scheduler

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/permission"
)

func TestFileObserverPersistsSchedulerEventsOutsideRuntime(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit", "scheduler.jsonl")
	observer, err := NewFileObserver(path)
	require.NoError(t, err)

	events := []Event{
		{
			Decision: Decision{
				RequestID:    "request-selected",
				Outcome:      OutcomeSelected,
				ComputerID:   computer.ID("local-default"),
				Backend:      computer.BackendLocal,
				Capabilities: []string{"file:read"},
				RiskScore:    10,
				Reasons:      []string{"Selected by deterministic policy."},
			},
			PermissionDecision: permission.DecisionAutoApprove,
		},
		{
			Decision: Decision{
				RequestID:    "request-denied",
				Outcome:      OutcomeDenied,
				Capabilities: []string{"file:write"},
				RiskScore:    90,
				Reasons:      []string{"Permission engine denied the request."},
			},
			PermissionDecision: permission.DecisionDeny,
		},
	}
	for _, event := range events {
		require.NoError(t, observer.Record(context.Background(), event))
	}

	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })

	var records []AuditRecord
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var record AuditRecord
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &record))
		records = append(records, record)
	}
	require.NoError(t, scanner.Err())
	require.Len(t, records, 2)
	require.Equal(t, events[0].Decision, records[0].Decision)
	require.Equal(t, events[0].PermissionDecision, records[0].PermissionDecision)
	require.False(t, records[0].RecordedAt.IsZero())
	require.Equal(t, events[1].Decision, records[1].Decision)

	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(path)
		require.NoError(t, statErr)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestFileObserverRejectsEmptyPath(t *testing.T) {
	t.Parallel()

	observer, err := NewFileObserver("")
	require.ErrorIs(t, err, ErrInvalidAuditPath)
	require.Nil(t, observer)
}
