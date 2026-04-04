package tools

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildJobToolSetReturnsDatasetTools(t *testing.T) {
	t.Parallel()

	tools := BuildJobToolSet()
	require.Len(t, tools, len(jobToolNames()))

	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Info().Name)
	}

	require.ElementsMatch(t, jobToolNames(), names)
}

func TestJobToolDatasetNamesAreUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, len(jobToolNames()))
	for _, name := range jobToolNames() {
		_, exists := seen[name]
		require.Falsef(t, exists, "duplicate job tool name %s", name)
		seen[name] = struct{}{}
	}
}
