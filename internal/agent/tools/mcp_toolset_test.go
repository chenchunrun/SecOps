package tools

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildMCPToolSetReturnsDatasetTools(t *testing.T) {
	t.Parallel()

	tools := BuildMCPToolSet(nil, nil)
	require.Len(t, tools, len(mcpToolNames()))

	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Info().Name)
	}

	require.ElementsMatch(t, mcpToolNames(), names)
}

func TestMCPToolDatasetNamesAreUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, len(mcpToolNames()))
	for _, name := range mcpToolNames() {
		_, exists := seen[name]
		require.Falsef(t, exists, "duplicate MCP tool name %s", name)
		seen[name] = struct{}{}
	}
}
