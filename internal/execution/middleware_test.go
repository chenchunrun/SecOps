package execution

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChainLocalMiddlewaresExecutesInOrder(t *testing.T) {
	t.Parallel()

	var order []string
	base := func(ctx context.Context, req LocalRequest) (LocalResult, error) {
		order = append(order, "base")
		return LocalResult{Output: req.Command}, nil
	}

	m1 := func(next LocalHandler) LocalHandler {
		return func(ctx context.Context, req LocalRequest) (LocalResult, error) {
			order = append(order, "m1-before")
			res, err := next(ctx, req)
			order = append(order, "m1-after")
			return res, err
		}
	}
	m2 := func(next LocalHandler) LocalHandler {
		return func(ctx context.Context, req LocalRequest) (LocalResult, error) {
			order = append(order, "m2-before")
			res, err := next(ctx, req)
			order = append(order, "m2-after")
			return res, err
		}
	}

	handler := ChainLocalMiddlewares(base, m1, m2)
	res, err := handler(context.Background(), LocalRequest{Command: "echo hello"})
	require.NoError(t, err)
	require.Equal(t, "echo hello", res.Output)
	require.Equal(t, []string{"m1-before", "m2-before", "base", "m2-after", "m1-after"}, order)
}

func TestNewLocalExecutorAppliesMiddleware(t *testing.T) {
	t.Parallel()

	var seen string
	executor := NewLocalExecutor(func(next LocalHandler) LocalHandler {
		return func(ctx context.Context, req LocalRequest) (LocalResult, error) {
			seen = req.Description
			return next(ctx, req)
		}
	})

	_, err := executor.Execute(context.Background(), LocalRequest{
		Command:     "echo done",
		Description: "tracked",
		WorkingDir:  t.TempDir(),
	})
	require.NoError(t, err)
	require.Equal(t, "tracked", seen)
}
