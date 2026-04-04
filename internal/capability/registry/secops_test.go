package registry

import (
	"encoding/json"
	"testing"

	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
	"github.com/stretchr/testify/require"
)

func TestNewSecOpsRegistry_CoversAllRegisteredToolTypes(t *testing.T) {
	t.Parallel()

	reg := NewSecOpsRegistry()

	for _, spec := range secOpsSpecs() {
		_, ok := reg.Get(spec.Key)
		require.Truef(t, ok, "missing descriptor for %s", spec.Key)
	}
}

func TestNewSecOpsRegistry_DecodeNetworkDiagnosticParams(t *testing.T) {
	t.Parallel()

	reg := NewSecOpsRegistry()
	desc, ok := reg.Get(string(secops.ToolTypeNetworkDiagnostic))
	require.True(t, ok)

	decoded, err := desc.Decode(json.RawMessage(`{"type":"ping","target":"8.8.8.8"}`))
	require.NoError(t, err)

	params, ok := decoded.(*secops.NetworkDiagnosticParams)
	require.True(t, ok)
	require.Equal(t, secops.DiagnosticPing, params.Type)
	require.Equal(t, "8.8.8.8", params.Target)
}

func TestNewSecOpsRegistry_ProvidesCapabilityMetadata(t *testing.T) {
	t.Parallel()

	reg := NewSecOpsRegistry()

	networkDesc, ok := reg.Get(string(secops.ToolTypeNetworkDiagnostic))
	require.True(t, ok)
	require.Contains(t, networkDesc.Metadata.RequiredCapabilities, "network:scan")
	require.Equal(t, ExecutionProfileRemoteCapable, networkDesc.Metadata.ExecutionProfile)
	require.Contains(t, networkDesc.Metadata.PolicyTags, "active_probe")

	logDesc, ok := reg.Get(string(secops.ToolTypeLogAnalyze))
	require.True(t, ok)
	require.NotEmpty(t, logDesc.Metadata.RequiredCapabilities)
	require.Equal(t, ExecutionProfileRemoteCapable, logDesc.Metadata.ExecutionProfile)
	require.Contains(t, logDesc.Metadata.PolicyTags, "environment_inspection")

	attackDesc, ok := reg.Get(string(secops.ToolTypeAttackReason))
	require.True(t, ok)
	require.Equal(t, ExecutionProfileLocalOnly, attackDesc.Metadata.ExecutionProfile)
	require.Contains(t, attackDesc.Metadata.PolicyTags, "investigation_reasoning")
}

func TestSecOpsDescriptors_CoversAllSpecs(t *testing.T) {
	t.Parallel()

	descs := secOpsDescriptors()

	expected := make([]string, 0, len(secOpsSpecs()))
	for _, spec := range secOpsSpecs() {
		expected = append(expected, spec.Key)
	}

	requireDescriptorKeysMatch(t, descs, expected)
}

func TestSecOpsDescriptorSpec_AllowsMetadataOverrides(t *testing.T) {
	t.Parallel()

	desc := secOpsDescriptorForTest[secops.SecurityScanParams](secops.NewSecurityScanTool, ExecutionProfileLocalOnly, "custom_tag")

	require.Equal(t, string(secops.ToolTypeSecurityScan), desc.Key)
	require.Equal(t, ExecutionProfileLocalOnly, desc.Metadata.ExecutionProfile)
	require.Equal(t, []string{"custom_tag"}, desc.Metadata.PolicyTags)
	require.NotEmpty(t, desc.Metadata.RequiredCapabilities)
}

func TestRegisterSecOpsToolSetMatchesDescriptorDataset(t *testing.T) {
	t.Parallel()

	toolRegistry := secops.NewSecOpsToolRegistry()
	require.NoError(t, RegisterSecOpsToolSet(toolRegistry))

	toolKeys := make([]string, 0, len(toolRegistry.GetAll()))
	for key := range toolRegistry.GetAll() {
		toolKeys = append(toolKeys, key)
	}

	expected := make([]string, 0, len(secOpsSpecs()))
	for _, spec := range secOpsSpecs() {
		expected = append(expected, spec.Key)
	}

	require.ElementsMatch(t, expected, toolKeys)
}
