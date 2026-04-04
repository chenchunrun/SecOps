package registry

import (
	"encoding/json"
	"testing"

	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
	"github.com/stretchr/testify/require"
)

func TestRegistryDecodeUsesRegisteredDescriptor(t *testing.T) {
	t.Parallel()

	reg := New()
	err := reg.Register(Descriptor{
		Key: "sample",
		Metadata: Metadata{
			RequiredCapabilities: []string{"cap:a"},
			ExecutionProfile:     ExecutionProfileRemoteCapable,
			PolicyTags:           []string{"tag:a"},
		},
		Decode: decodeJSONInto[struct {
			Name string `json:"name"`
		}],
	})
	require.NoError(t, err)

	decoded, err := reg.Decode("sample", json.RawMessage(`{"name":"demo"}`))
	require.NoError(t, err)

	params, ok := decoded.(*struct {
		Name string `json:"name"`
	})
	require.True(t, ok)
	require.Equal(t, "demo", params.Name)
}

func TestRegistryMetadataAccessorsReturnCopies(t *testing.T) {
	t.Parallel()

	reg := New()
	err := reg.Register(Descriptor{
		Key: "sample",
		Metadata: Metadata{
			RequiredCapabilities: []string{"cap:a"},
			ExecutionProfile:     ExecutionProfileLocalOnly,
			PolicyTags:           []string{"tag:a"},
		},
		Decode: decodeJSONInto[struct{}],
	})
	require.NoError(t, err)

	metadata, ok := reg.MetadataFor("sample")
	require.True(t, ok)
	require.Equal(t, ExecutionProfileLocalOnly, metadata.ExecutionProfile)

	metadata.RequiredCapabilities[0] = "changed"
	metadata.PolicyTags[0] = "changed"

	require.Equal(t, []string{"cap:a"}, reg.RequiredCapabilities("sample"))
	require.Equal(t, []string{"tag:a"}, reg.PolicyTags("sample"))

	profile, ok := reg.ExecutionProfileFor("sample")
	require.True(t, ok)
	require.Equal(t, ExecutionProfileLocalOnly, profile)
}

func TestRegistryDecodeMissingDescriptor(t *testing.T) {
	t.Parallel()

	reg := New()

	_, err := reg.Decode("missing", json.RawMessage(`{}`))
	require.EqualError(t, err, "unsupported descriptor key: missing")
}

func TestRegistryRegisterAllAndMustNew(t *testing.T) {
	t.Parallel()

	descs := []Descriptor{
		{
			Key:    "one",
			Decode: decodeJSONInto[struct{}],
		},
		{
			Key: "two",
			Metadata: Metadata{
				PolicyTags: []string{"tag:two"},
			},
			Decode: decodeJSONInto[struct{}],
		},
	}

	reg := New()
	require.NoError(t, reg.RegisterAll(descs...))
	require.Len(t, reg.List(), 2)

	mustReg := MustNew(descs...)
	require.Len(t, mustReg.List(), 2)
	require.Equal(t, []string{"tag:two"}, mustReg.PolicyTags("two"))
}

func TestSpecDescriptorAndSpecsToDescriptorsCloneMetadata(t *testing.T) {
	t.Parallel()

	spec := Spec{
		Key: "sample",
		Metadata: Metadata{
			RequiredCapabilities: []string{"cap:a"},
			ExecutionProfile:     ExecutionProfileRemoteCapable,
			PolicyTags:           []string{"tag:a"},
		},
		Decode: decodeJSONInto[struct{}],
	}

	desc := spec.Descriptor()
	desc.Metadata.RequiredCapabilities[0] = "changed"
	desc.Metadata.PolicyTags[0] = "changed"

	descs := SpecsToDescriptors(spec)
	require.Len(t, descs, 1)
	require.Equal(t, []string{"cap:a"}, descs[0].Metadata.RequiredCapabilities)
	require.Equal(t, []string{"tag:a"}, descs[0].Metadata.PolicyTags)
}

func TestNewToolSpecBuildsMetadataFromTool(t *testing.T) {
	t.Parallel()

	spec := NewToolSpec[secops.SecurityScanParams](secops.NewSecurityScanTool(nil), ExecutionProfileRemoteCapable, "active_probe")

	require.Equal(t, string(secops.ToolTypeSecurityScan), spec.Key)
	require.Equal(t, ExecutionProfileRemoteCapable, spec.Metadata.ExecutionProfile)
	require.Equal(t, []string{"active_probe"}, spec.Metadata.PolicyTags)
	require.NotEmpty(t, spec.Metadata.RequiredCapabilities)
}

func TestNewToolDatasetEntryBuildsSpecAndTool(t *testing.T) {
	t.Parallel()

	entry := NewToolDatasetEntry[secops.SecurityScanParams](secops.NewSecurityScanTool, ExecutionProfileRemoteCapable, "active_probe")

	spec := entry.Spec()
	require.Equal(t, string(secops.ToolTypeSecurityScan), spec.Key)
	require.Equal(t, []string{"active_probe"}, spec.Metadata.PolicyTags)

	tool, ok := entry.NewTool(nil).(secops.SecOpsTool)
	require.True(t, ok)
	require.Equal(t, secops.ToolTypeSecurityScan, tool.Type())
}

func TestRegisterToolDatasetRegistersAllEntries(t *testing.T) {
	t.Parallel()

	registry := secops.NewSecOpsToolRegistry()
	entry := NewToolDatasetEntry[secops.SecurityScanParams](secops.NewSecurityScanTool, ExecutionProfileRemoteCapable, "active_probe")

	err := RegisterToolDataset(registry, func(reg *secops.SecOpsToolRegistry, tool secops.SecOpsTool) error {
		return reg.Register(tool)
	}, entry)
	require.NoError(t, err)

	registered, ok := registry.Get(secops.ToolTypeSecurityScan)
	require.True(t, ok)
	require.Equal(t, secops.ToolTypeSecurityScan, registered.Type())
}

func TestRequireDescriptorKeysMatchAcceptsExactSet(t *testing.T) {
	t.Parallel()

	descs := []Descriptor{
		{Key: "one", Decode: decodeJSONInto[struct{}]},
		{Key: "two", Decode: decodeJSONInto[struct{}]},
	}

	requireDescriptorKeysMatch(t, descs, []string{"one", "two"})
}

func TestSecOpsCompatibilityAliasesAreConsistent(t *testing.T) {
	t.Parallel()

	flatNames := SecOpsCompatibilityAliasNames()
	require.NotEmpty(t, flatNames)

	seen := make(map[string]struct{}, len(flatNames))
	for _, name := range flatNames {
		_, exists := seen[name]
		require.Falsef(t, exists, "duplicate secops alias %q", name)
		seen[name] = struct{}{}
	}

	aliasMap := SecOpsCompatibilityAliases()
	var mapNames []string
	for _, aliases := range aliasMap {
		mapNames = append(mapNames, aliases...)
	}

	require.ElementsMatch(t, flatNames, mapNames)
}
