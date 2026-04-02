package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type stubBashEvaluator struct {
	decision Decision
	err      error
}

func (s stubBashEvaluator) EvaluateBash(ctx context.Context, req Request) (Decision, error) {
	return s.decision, s.err
}

type stubSecOpsEvaluator struct {
	decision Decision
	err      error
}

func (s stubSecOpsEvaluator) EvaluateSecOps(ctx context.Context, req Request) (Decision, error) {
	return s.decision, s.err
}

func TestDefaultDeciderRoutesBashRequests(t *testing.T) {
	t.Parallel()

	decider := NewDefaultDecider(stubBashEvaluator{
		decision: Decision{Allowed: true, Reason: "bash"},
	}, nil)

	decision, err := decider.Decide(context.Background(), Request{PolicyKind: "bash", ToolName: "bash"})
	require.NoError(t, err)
	require.True(t, decision.Allowed)
	require.Equal(t, "bash", decision.Reason)
}

func TestDefaultDeciderRoutesSecOpsRequests(t *testing.T) {
	t.Parallel()

	decider := NewDefaultDecider(nil, stubSecOpsEvaluator{
		decision: Decision{Allowed: false, Reason: "secops"},
	})

	decision, err := decider.Decide(context.Background(), Request{PolicyKind: "secops", ToolName: "compliance_check"})
	require.NoError(t, err)
	require.False(t, decision.Allowed)
	require.Equal(t, "secops", decision.Reason)
}

func TestMergeAuditFields(t *testing.T) {
	t.Parallel()

	merged := MergeAuditFields(
		map[string]any{"tool_name": "bash", "policy": "old"},
		map[string]any{"policy": "new", "policy_result": "allow"},
	)

	require.Equal(t, "bash", merged["tool_name"])
	require.Equal(t, "new", merged["policy"])
	require.Equal(t, "allow", merged["policy_result"])
}
