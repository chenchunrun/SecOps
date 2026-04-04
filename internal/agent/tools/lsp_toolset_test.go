package tools

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildLSPToolSetReturnsDatasetTools(t *testing.T) {
	t.Parallel()

	tools := BuildLSPToolSet(nil)
	require.Len(t, tools, len(lspToolNames()))

	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Info().Name)
	}

	require.ElementsMatch(t, lspToolNames(), names)
}

func TestLSPToolDatasetNamesAreUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, len(lspToolNames()))
	for _, name := range lspToolNames() {
		_, exists := seen[name]
		require.Falsef(t, exists, "duplicate LSP tool name %s", name)
		seen[name] = struct{}{}
	}
}
