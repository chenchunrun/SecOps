package registry

import (
	"testing"

	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
	"github.com/stretchr/testify/require"
)

func TestToolDecodeRejectsUnknownAndInvalidParameters(t *testing.T) {
	t.Parallel()
	registry := NewSecOpsRegistry()
	for _, input := range []string{`null`, `[]`, `{"scanner":"trivy","target":"filesystem","target_path":"/tmp","fix_vulns_typo":true}`, `{} {}`, `{"full":"yes"}`} {
		_, err := registry.Decode("security_scan", []byte(input))
		require.Error(t, err, input)
	}
	_, err := registry.Decode("security_scan", []byte(`{"scanner":"trivy","target":"filesystem","target_path":"/tmp"}`))
	require.NoError(t, err)
}

func TestRegisteredToolDatasetRequiresCancelableExecution(t *testing.T) {
	t.Parallel()
	tools := secops.NewSecOpsToolRegistry()
	require.NoError(t, RegisterSecOpsToolSet(tools))
	for _, tool := range tools.List() {
		_, ok := tool.(secops.ContextTool)
		require.True(t, ok, "registered tool %s must propagate cancellation", tool.Type())
	}
}
