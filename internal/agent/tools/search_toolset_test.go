package tools

import (
	"testing"

	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/stretchr/testify/require"
)

func TestBuildSearchToolSetReturnsDatasetTools(t *testing.T) {
	t.Parallel()

	tools := BuildSearchToolSet(nil, ".", config.ToolGrep{}, config.ToolLs{})
	require.Len(t, tools, len(searchToolNames()))

	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Info().Name)
	}

	require.ElementsMatch(t, searchToolNames(), names)
}

func TestSearchToolDatasetNamesAreUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, len(searchToolNames()))
	for _, name := range searchToolNames() {
		_, exists := seen[name]
		require.Falsef(t, exists, "duplicate search tool name %s", name)
		seen[name] = struct{}{}
	}
}
