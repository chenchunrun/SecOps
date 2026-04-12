package execution

import (
	"context"
	"errors"
)

func PolicyLocalMiddleware() LocalMiddleware {
	return func(next LocalHandler) LocalHandler {
		return func(ctx context.Context, req LocalRequest) (LocalResult, error) {
			if req.Decision != nil && !req.Decision.Allowed {
				reason := req.Decision.Reason
				if reason == "" {
					reason = "local execution denied by policy"
				}
				return LocalResult{}, &LocalExecutionError{
					Kind:  LocalErrorKindPolicy,
					Cause: errors.New(reason),
				}
			}
			return next(ctx, req)
		}
	}
}
