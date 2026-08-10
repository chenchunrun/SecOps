package bootstrap

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
	"github.com/stretchr/testify/require"
)

func TestNewComputerRuntimeRecoversRunningTasksWithoutReplay(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store, err := taskruntime.NewFileStore(filepath.Join(root, "tasks"))
	require.NoError(t, err)
	running, err := store.Create(context.Background(), taskruntime.Task{
		ID:         "task-running-at-crash",
		ComputerID: DefaultLocalComputerID,
		State:      taskruntime.StateRunning,
		Request:    computer.ExecRequest{Command: "non-idempotent-operation"},
		Attempt:    1,
	})
	require.NoError(t, err)

	runtime, err := newComputerRuntime(context.Background(), root)
	require.NoError(t, err)
	require.Len(t, runtime.Recovered, 1)
	require.Equal(t, running.ID, runtime.Recovered[0].ID)
	require.Equal(t, taskruntime.StateInterrupted, runtime.Recovered[0].State)

	persisted, err := runtime.Tasks.Get(context.Background(), running.ID)
	require.NoError(t, err)
	require.Equal(t, taskruntime.StateInterrupted, persisted.State)

	machine, err := runtime.Computers.Get(DefaultLocalComputerID)
	require.NoError(t, err)
	require.Equal(t, computer.BackendLocal, machine.Backend())
	defaultWorkspace, err := runtime.Workspaces.Get(context.Background(), DefaultWorkspaceID)
	require.NoError(t, err)
	require.DirExists(t, defaultWorkspace.Root)

	restarted, err := newComputerRuntime(context.Background(), root)
	require.NoError(t, err)
	restartedWorkspace, err := restarted.Workspaces.Get(context.Background(), DefaultWorkspaceID)
	require.NoError(t, err)
	require.Equal(t, defaultWorkspace.Root, restartedWorkspace.Root)
}
