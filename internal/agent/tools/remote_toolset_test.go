package tools

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildRemoteToolSetReturnsDatasetTools(t *testing.T) {
	t.Parallel()

	tools := BuildRemoteToolSet(nil, ".", nil)
	require.Len(t, tools, len(remoteToolNames()))

	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Info().Name)
	}

	require.ElementsMatch(t, remoteToolNames(), names)
}

func TestRemoteToolDatasetNamesAreUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, len(remoteToolNames()))
	for _, name := range remoteToolNames() {
		_, exists := seen[name]
		require.Falsef(t, exists, "duplicate remote tool name %s", name)
		seen[name] = struct{}{}
	}
}
