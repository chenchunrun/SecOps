package execution

import (
	"context"
	"errors"

	"github.com/chenchunrun/SecOps/internal/shell"
)

func ErrorClassificationRemoteMiddleware() RemoteMiddleware {
	return func(next RemoteHandler) RemoteHandler {
		return func(ctx context.Context, req RemoteRequest) (RemoteResult, error) {
			result, err := next(ctx, req)
			if err == nil {
				return result, nil
			}
			return result, classifyRemoteError(err)
		}
	}
}

func classifyRemoteError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.DeadlineExceeded):
		return &RemoteExecutionError{Kind: RemoteErrorKindTimeout, Cause: err}
	case errors.Is(err, context.Canceled), shell.IsInterrupt(err):
		return &RemoteExecutionError{Kind: RemoteErrorKindCancelled, Cause: err}
	default:
		var remoteErr *RemoteExecutionError
		if errors.As(err, &remoteErr) {
			return err
		}
		return &RemoteExecutionError{Kind: RemoteErrorKindExecution, Cause: err}
	}
}
