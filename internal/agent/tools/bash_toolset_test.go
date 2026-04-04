package tools

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildBashToolSetReturnsDatasetTools(t *testing.T) {
	t.Parallel()

	tools := BuildBashToolSet(nil, ".", nil, "", nil)
	require.Len(t, tools, len(bashToolNames()))

	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Info().Name)
	}

	require.ElementsMatch(t, bashToolNames(), names)
}

func TestBashToolDatasetNamesAreUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, len(bashToolNames()))
	for _, name := range bashToolNames() {
		_, exists := seen[name]
		require.Falsef(t, exists, "duplicate bash tool name %s", name)
		seen[name] = struct{}{}
	}
}
