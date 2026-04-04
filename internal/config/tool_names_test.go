package config

import (
	"testing"

	capregistry "github.com/chenchunrun/SecOps/internal/capability/registry"
	"github.com/stretchr/testify/require"
)

func requireUniqueStrings(t *testing.T, values []string) {
	t.Helper()

	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		_, exists := seen[value]
		require.Falsef(t, exists, "duplicate value %q", value)
		seen[value] = struct{}{}
	}
}

func TestFixedBuiltInToolNamesAreUnique(t *testing.T) {
	t.Parallel()

	requireUniqueStrings(t, fixedBuiltInToolNames())
}

func TestAllToolNamesAreUnique(t *testing.T) {
	t.Parallel()

	requireUniqueStrings(t, allToolNames())
}

func TestReadOnlyToolNamesAreSubsetOfAllToolNames(t *testing.T) {
	t.Parallel()

	all := allToolNames()
	for _, name := range readOnlyToolNames() {
		require.Contains(t, all, name)
	}
}

func TestSecOpsRuntimeSupportToolNamesAreSubsetOfAllToolNames(t *testing.T) {
	t.Parallel()

	all := allToolNames()
	for _, name := range secOpsRuntimeSupportToolNames() {
		require.Contains(t, all, name)
	}
}

func TestSecOpsRuntimeToolNamesIncludeRegistryToolNamesAndAliases(t *testing.T) {
	t.Parallel()

	runtimeNames := secOpsRuntimeToolNames()
	for _, name := range capregistry.SecOpsToolNames() {
		require.Contains(t, runtimeNames, name)
	}
	for _, name := range capregistry.SecOpsCompatibilityAliasNames() {
		require.Contains(t, runtimeNames, name)
	}
}
