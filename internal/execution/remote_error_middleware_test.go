package execution

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyRemoteError_Timeout(t *testing.T) {
	t.Parallel()

	err := classifyRemoteError(context.DeadlineExceeded)
	require.True(t, IsRemoteErrorKind(err, RemoteErrorKindTimeout))
}

func TestClassifyRemoteError_Cancelled(t *testing.T) {
	t.Parallel()

	err := classifyRemoteError(context.Canceled)
	require.True(t, IsRemoteErrorKind(err, RemoteErrorKindCancelled))
}

func TestClassifyRemoteError_Execution(t *testing.T) {
	t.Parallel()

	err := classifyRemoteError(errors.New("boom"))
	require.True(t, IsRemoteErrorKind(err, RemoteErrorKindExecution))
}

func TestErrorClassificationRemoteMiddlewarePreservesPolicyErrors(t *testing.T) {
	t.Parallel()

	handler := ErrorClassificationRemoteMiddleware()(func(ctx context.Context, req RemoteRequest) (RemoteResult, error) {
		return RemoteResult{}, &RemoteExecutionError{
			Kind:  RemoteErrorKindPolicy,
			Cause: errors.New("denied"),
		}
	})

	_, err := handler(context.Background(), RemoteRequest{})
	require.Error(t, err)
	require.True(t, IsRemoteErrorKind(err, RemoteErrorKindPolicy))
}

func TestRemoteExecutorStartErrorIsClassified(t *testing.T) {
	t.Parallel()

	executor := NewRemoteExecutor()
	_, err := executor.Execute(context.Background(), RemoteRequest{
		Command: "hostname",
	})
	require.Error(t, err)
	require.True(t, IsRemoteErrorKind(err, RemoteErrorKindStart))
}
