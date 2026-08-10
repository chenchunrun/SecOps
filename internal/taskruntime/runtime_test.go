package taskruntime

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/stretchr/testify/require"
)

type fakeComputer struct {
	id     computer.ID
	result *computer.ExecutionResult
	err    error
	calls  int
}

func (c *fakeComputer) ID() computer.ID {
	return c.id
}

func (c *fakeComputer) Exec(_ context.Context, _ computer.ExecRequest) (*computer.ExecutionResult, error) {
	c.calls++
	return c.result, c.err
}

func TestRuntimePersistsSuccessfulTaskAcrossRestart(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store, err := NewFileStore(root)
	require.NoError(t, err)
	runtime, err := New(store)
	require.NoError(t, err)

	task, err := runtime.Submit(context.Background(), Submission{
		ID:         "task-success",
		ComputerID: "computer-1",
		Request:    computer.ExecRequest{Command: "echo done", MaxOutputBytes: 1024},
	})
	require.NoError(t, err)
	require.Equal(t, StatePending, task.State)

	machine := &fakeComputer{
		id: "computer-1",
		result: &computer.ExecutionResult{
			Output:   "done\n",
			ExitCode: 0,
		},
	}
	task, err = runtime.Run(context.Background(), task.ID, machine)
	require.NoError(t, err)
	require.Equal(t, StateSucceeded, task.State)
	require.Equal(t, 1, task.Attempt)
	require.Equal(t, "done\n", task.Result.Output)
	require.NotZero(t, task.StartedAt)
	require.NotZero(t, task.FinishedAt)

	reopened, err := NewFileStore(root)
	require.NoError(t, err)
	persisted, err := reopened.Get(context.Background(), task.ID)
	require.NoError(t, err)
	require.Equal(t, task, persisted)
}

func TestRuntimePersistsFailureAndCancellation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		execErr   error
		wantState State
	}{
		{name: "failure", execErr: errors.New("backend failed"), wantState: StateFailed},
		{name: "cancelled", execErr: context.Canceled, wantState: StateCancelled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store, err := NewFileStore(t.TempDir())
			require.NoError(t, err)
			runtime, err := New(store)
			require.NoError(t, err)
			task, err := runtime.Submit(context.Background(), Submission{
				ID:         ID("task-" + tt.name),
				ComputerID: "computer-1",
				Request:    computer.ExecRequest{Command: "run"},
			})
			require.NoError(t, err)

			machine := &fakeComputer{id: "computer-1", err: tt.execErr}
			task, runErr := runtime.Run(context.Background(), task.ID, machine)
			require.ErrorIs(t, runErr, tt.execErr)
			require.Equal(t, tt.wantState, task.State)
			require.Equal(t, tt.execErr.Error(), task.Error)

			persisted, err := store.Get(context.Background(), task.ID)
			require.NoError(t, err)
			require.Equal(t, tt.wantState, persisted.State)
		})
	}
}

func TestRuntimeDoesNotReexecuteTerminalTask(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	runtime, err := New(store)
	require.NoError(t, err)
	task, err := runtime.Submit(context.Background(), Submission{
		ID:         "task-once",
		ComputerID: "computer-1",
		Request:    computer.ExecRequest{Command: "change-state"},
	})
	require.NoError(t, err)
	machine := &fakeComputer{id: "computer-1", result: &computer.ExecutionResult{ExitCode: 0}}

	first, err := runtime.Run(context.Background(), task.ID, machine)
	require.NoError(t, err)
	second, err := runtime.Run(context.Background(), task.ID, machine)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, 1, machine.calls)
}

func TestRuntimeRecoveryRequiresExplicitRetry(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	running, err := store.Create(context.Background(), Task{
		ID:         "task-recover",
		ComputerID: "computer-1",
		State:      StateRunning,
		Request:    computer.ExecRequest{Command: "non-idempotent-operation"},
		Attempt:    1,
	})
	require.NoError(t, err)
	runtime, err := New(store)
	require.NoError(t, err)

	recovered, err := runtime.Recover(context.Background())
	require.NoError(t, err)
	require.Len(t, recovered, 1)
	require.Equal(t, running.ID, recovered[0].ID)
	require.Equal(t, StateInterrupted, recovered[0].State)
	require.Contains(t, recovered[0].Error, "outcome is unknown")

	machine := &fakeComputer{id: "computer-1", result: &computer.ExecutionResult{ExitCode: 0}}
	_, err = runtime.Run(context.Background(), running.ID, machine)
	require.ErrorIs(t, err, ErrNotRunnable)
	require.Zero(t, machine.calls)

	retried, err := runtime.Retry(context.Background(), running.ID)
	require.NoError(t, err)
	require.Equal(t, StatePending, retried.State)
	require.Equal(t, 1, retried.Attempt)
	require.Empty(t, retried.Error)

	completed, err := runtime.Run(context.Background(), running.ID, machine)
	require.NoError(t, err)
	require.Equal(t, StateSucceeded, completed.State)
	require.Equal(t, 2, completed.Attempt)
	require.Equal(t, 1, machine.calls)
}

func TestRuntimeRejectsComputerMismatchWithoutExecution(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	runtime, err := New(store)
	require.NoError(t, err)
	task, err := runtime.Submit(context.Background(), Submission{
		ID:         "task-mismatch",
		ComputerID: "computer-1",
		Request:    computer.ExecRequest{Command: "run"},
	})
	require.NoError(t, err)
	machine := &fakeComputer{id: "computer-2"}

	unchanged, err := runtime.Run(context.Background(), task.ID, machine)
	require.ErrorIs(t, err, ErrComputerMismatch)
	require.Equal(t, StatePending, unchanged.State)
	require.Zero(t, machine.calls)
}

func TestFileStoreRejectsTraversalAndStaleUpdates(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store, err := NewFileStore(root)
	require.NoError(t, err)

	_, err = store.Create(context.Background(), Task{ID: "../escape", State: StatePending})
	require.ErrorIs(t, err, ErrInvalidTask)
	_, statErr := filepath.Glob(filepath.Join(filepath.Dir(root), "escape*"))
	require.NoError(t, statErr)

	created, err := store.Create(context.Background(), Task{ID: "task-version", State: StatePending})
	require.NoError(t, err)
	stale := created
	created.State = StateRunning
	created, err = store.Update(context.Background(), created)
	require.NoError(t, err)
	require.Equal(t, uint64(2), created.Version)

	stale.State = StateFailed
	_, err = store.Update(context.Background(), stale)
	require.ErrorIs(t, err, ErrConflict)
	persisted, err := store.Get(context.Background(), created.ID)
	require.NoError(t, err)
	require.Equal(t, StateRunning, persisted.State)
}
