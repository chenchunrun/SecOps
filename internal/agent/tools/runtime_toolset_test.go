package tools

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildRuntimeToolSetReturnsDatasetTools(t *testing.T) {
	t.Parallel()

	tools := BuildRuntimeToolSet(nil, nil, nil, nil, ".", nil)
	require.Len(t, tools, len(runtimeToolNames()))

	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Info().Name)
	}

	require.ElementsMatch(t, runtimeToolNames(), names)
}

func TestRuntimeToolDatasetNamesAreUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, len(runtimeToolNames()))
	for _, name := range runtimeToolNames() {
		_, exists := seen[name]
		require.Falsef(t, exists, "duplicate runtime tool name %s", name)
		seen[name] = struct{}{}
	}
}
