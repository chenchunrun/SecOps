package tools

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func requireUniqueToolNames(t *testing.T, values []string) {
	t.Helper()

	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		_, exists := seen[value]
		require.Falsef(t, exists, "duplicate tool name %q", value)
		seen[value] = struct{}{}
	}
}

func TestFixedBuiltInToolNamesAreUnique(t *testing.T) {
	t.Parallel()

	requireUniqueToolNames(t, FixedBuiltInToolNames())
}

func TestReadOnlyBuiltInToolNamesAreUnique(t *testing.T) {
	t.Parallel()

	requireUniqueToolNames(t, ReadOnlyBuiltInToolNames())
}

func TestSecOpsRuntimeSupportToolNamesAreUnique(t *testing.T) {
	t.Parallel()

	requireUniqueToolNames(t, SecOpsRuntimeSupportToolNames())
}

func TestReadOnlyBuiltInToolNamesAreSubsetOfFixedBuiltIns(t *testing.T) {
	t.Parallel()

	all := FixedBuiltInToolNames()
	for _, name := range ReadOnlyBuiltInToolNames() {
		require.Contains(t, all, name)
	}
}

func TestSecOpsRuntimeSupportToolNamesAreSubsetOfFixedBuiltIns(t *testing.T) {
	t.Parallel()

	all := FixedBuiltInToolNames()
	for _, name := range SecOpsRuntimeSupportToolNames() {
		require.Contains(t, all, name)
	}
}
