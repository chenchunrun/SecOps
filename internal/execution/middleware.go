package execution

import "context"

func ChainLocalMiddlewares(base LocalHandler, middlewares ...LocalMiddleware) LocalHandler {
	if len(middlewares) == 0 {
		return base
	}

	handler := base
	for i := len(middlewares) - 1; i >= 0; i-- {
		if middlewares[i] == nil {
			continue
		}
		handler = middlewares[i](handler)
	}
	return handler
}

func NoopLocalMiddleware() LocalMiddleware {
	return func(next LocalHandler) LocalHandler {
		return func(ctx context.Context, req LocalRequest) (LocalResult, error) {
			return next(ctx, req)
		}
	}
}
