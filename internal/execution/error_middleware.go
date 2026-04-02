package execution

import (
	"context"
	"errors"

	"github.com/chenchunrun/SecOps/internal/shell"
)

func ErrorClassificationMiddleware() LocalMiddleware {
	return func(next LocalHandler) LocalHandler {
		return func(ctx context.Context, req LocalRequest) (LocalResult, error) {
			result, err := next(ctx, req)
			if err == nil {
				return result, nil
			}
			return result, classifyLocalError(err)
		}
	}
}

func classifyLocalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.DeadlineExceeded):
		return &LocalExecutionError{Kind: LocalErrorKindTimeout, Cause: err}
	case errors.Is(err, context.Canceled), shell.IsInterrupt(err):
		return &LocalExecutionError{Kind: LocalErrorKindCancelled, Cause: err}
	default:
		var localErr *LocalExecutionError
		if errors.As(err, &localErr) {
			return err
		}
		return &LocalExecutionError{Kind: LocalErrorKindExecution, Cause: err}
	}
}
