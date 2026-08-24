package taskruntime

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
)

func TestPendingTaskPauseResumeAndCancel(t *testing.T) {
	t.Parallel()
	runtime := newControlRuntime(t)
	_, err := runtime.Submit(context.Background(), Submission{ID: "controlled-task", ComputerID: "computer", Request: computer.ExecRequest{Command: "work"}})
	require.NoError(t, err)
	paused, err := runtime.Pause(context.Background(), "controlled-task")
	require.NoError(t, err)
	require.Equal(t, StatePaused, paused.State)
	resumed, err := runtime.Resume(context.Background(), "controlled-task")
	require.NoError(t, err)
	require.Equal(t, StatePending, resumed.State)
	cancelled, err := runtime.Cancel(context.Background(), "controlled-task")
	require.NoError(t, err)
	require.Equal(t, StateCancelled, cancelled.State)
}

func TestRunningTaskCanPauseAndResumeWithoutCompletingSideEffect(t *testing.T) {
	t.Parallel()
	runtime := newControlRuntime(t)
	_, err := runtime.Submit(context.Background(), Submission{ID: "running-pause", ComputerID: "computer", Request: computer.ExecRequest{Command: "work"}})
	require.NoError(t, err)
	machine := &blockingComputer{id: "computer", started: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, runErr := runtime.Run(context.Background(), "running-pause", machine)
		done <- runErr
	}()
	<-machine.started
	_, err = runtime.Pause(context.Background(), "running-pause")
	require.NoError(t, err)
	require.ErrorIs(t, <-done, context.Canceled)
	paused, err := runtime.Get(context.Background(), "running-pause")
	require.NoError(t, err)
	require.Equal(t, StatePaused, paused.State)
	require.Nil(t, paused.Result)
	resumed, err := runtime.Resume(context.Background(), "running-pause")
	require.NoError(t, err)
	require.Equal(t, StatePending, resumed.State)
}

func newControlRuntime(t *testing.T) *Runtime {
	t.Helper()
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	runtime, err := New(store)
	require.NoError(t, err)
	return runtime
}

type blockingComputer struct {
	id      computer.ID
	started chan struct{}
}

func (c *blockingComputer) ID() computer.ID { return c.id }

func (c *blockingComputer) Exec(ctx context.Context, _ computer.ExecRequest) (*computer.ExecutionResult, error) {
	close(c.started)
	<-ctx.Done()
	return nil, ctx.Err()
}
