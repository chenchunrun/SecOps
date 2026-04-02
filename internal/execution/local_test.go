package execution

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalExecutorExecuteCompletesSynchronously(t *testing.T) {
	executor := NewLocalExecutor()
	result, err := executor.Execute(context.Background(), LocalRequest{
		Command:    "echo done",
		WorkingDir: t.TempDir(),
	})
	require.NoError(t, err)
	require.False(t, result.Background)
	require.Contains(t, result.Output, "done")
}

func TestLocalExecutorExecuteRunsInBackgroundWhenRequested(t *testing.T) {
	executor := NewLocalExecutor()
	result, err := executor.Execute(context.Background(), LocalRequest{
		Command:         "sleep 2",
		WorkingDir:      t.TempDir(),
		RunInBackground: true,
	})
	require.NoError(t, err)
	require.True(t, result.Background)
	require.NotEmpty(t, result.ShellID)
}
