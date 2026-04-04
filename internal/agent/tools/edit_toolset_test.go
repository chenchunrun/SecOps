package tools

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildEditToolSetReturnsDatasetTools(t *testing.T) {
	t.Parallel()

	tools := BuildEditToolSet(nil, nil, nil, nil, ".")
	require.Len(t, tools, len(editToolNames()))

	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Info().Name)
	}

	require.ElementsMatch(t, editToolNames(), names)
}

func TestEditToolDatasetNamesAreUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, len(editToolNames()))
	for _, name := range editToolNames() {
		_, exists := seen[name]
		require.Falsef(t, exists, "duplicate edit tool name %s", name)
		seen[name] = struct{}{}
	}
}
