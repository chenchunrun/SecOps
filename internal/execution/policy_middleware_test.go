package execution

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyLocalMiddlewareBlocksDeniedRequests(t *testing.T) {
	t.Parallel()

	handler := PolicyLocalMiddleware()(func(ctx context.Context, req LocalRequest) (LocalResult, error) {
		return LocalResult{Output: "should not run"}, nil
	})

	_, err := handler(context.Background(), LocalRequest{
		Decision: &Decision{
			Allowed: false,
			Reason:  "denied by policy",
		},
	})
	require.Error(t, err)
	require.True(t, IsLocalErrorKind(err, LocalErrorKindPolicy))
	require.EqualError(t, err, "denied by policy")
}

func TestPolicyLocalMiddlewareAllowsApprovedRequests(t *testing.T) {
	t.Parallel()

	handler := PolicyLocalMiddleware()(func(ctx context.Context, req LocalRequest) (LocalResult, error) {
		return LocalResult{Output: "ok"}, nil
	})

	result, err := handler(context.Background(), LocalRequest{
		Decision: &Decision{Allowed: true},
	})
	require.NoError(t, err)
	require.Equal(t, "ok", result.Output)
}
