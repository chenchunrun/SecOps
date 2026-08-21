package collaboration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlannerBuildsLeastPrivilegeMakerCheckerGraph(t *testing.T) {
	t.Parallel()
	graph, err := (Planner{}).Build(PlanRequest{
		TaskID: "response-task", Objective: "Investigate, remediate, and verify.",
		RequiresOperator: true, RequiresCoder: true, HighRisk: true,
	})
	require.NoError(t, err)
	require.NoError(t, graph.Validate())
	require.Len(t, graph.Nodes, 5)

	byID := make(map[string]TaskNode, len(graph.Nodes))
	for _, node := range graph.Nodes {
		byID[node.ID] = node
	}
	require.Equal(t, RoleSecurity, byID["security-maker"].Role)
	require.NotContains(t, byID["security-maker"].RequiredCapabilities, "computer:exec")
	require.Equal(t, []string{"security-maker"}, byID["operator"].Dependencies)
	require.Equal(t, []string{"coder"}, byID["independent-checker"].Dependencies)
	require.Contains(t, byID["independent-checker"].RequiredCapabilities, "high_risk:verify")
	require.NotEqual(t, byID["security-maker"].ID, byID["independent-checker"].ID)
	require.Equal(t, []string{"independent-checker"}, byID["reporter"].Dependencies)
}

func TestPlannerOmitsUnneededWriteRoles(t *testing.T) {
	t.Parallel()
	graph, err := (Planner{}).Build(PlanRequest{TaskID: "read-only-task", Objective: "Investigate evidence."})
	require.NoError(t, err)
	require.Len(t, graph.Nodes, 3)
	for _, node := range graph.Nodes {
		require.NotEqual(t, RoleOperator, node.Role)
		require.NotEqual(t, RoleCoder, node.Role)
	}
}
