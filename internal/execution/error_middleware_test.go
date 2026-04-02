package execution

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyLocalError_Timeout(t *testing.T) {
	t.Parallel()

	err := classifyLocalError(context.DeadlineExceeded)
	require.True(t, IsLocalErrorKind(err, LocalErrorKindTimeout))
}

func TestClassifyLocalError_Cancelled(t *testing.T) {
	t.Parallel()

	err := classifyLocalError(context.Canceled)
	require.True(t, IsLocalErrorKind(err, LocalErrorKindCancelled))
}

func TestClassifyLocalError_Execution(t *testing.T) {
	t.Parallel()

	err := classifyLocalError(errors.New("boom"))
	require.True(t, IsLocalErrorKind(err, LocalErrorKindExecution))
}

func TestErrorClassificationMiddlewarePreservesStartErrors(t *testing.T) {
	t.Parallel()

	handler := ErrorClassificationMiddleware()(func(ctx context.Context, req LocalRequest) (LocalResult, error) {
		return LocalResult{}, &LocalExecutionError{
			Kind:  LocalErrorKindStart,
			Cause: errors.New("start failed"),
		}
	})

	_, err := handler(context.Background(), LocalRequest{})
	require.Error(t, err)
	require.True(t, IsLocalErrorKind(err, LocalErrorKindStart))
}
