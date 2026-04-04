package registry

import "testing"

import "github.com/stretchr/testify/require"

func requireDescriptorKeysMatch(t *testing.T, descs []Descriptor, expected []string) {
	t.Helper()

	actual := make([]string, 0, len(descs))
	seen := make(map[string]struct{}, len(descs))
	for _, desc := range descs {
		_, exists := seen[desc.Key]
		require.Falsef(t, exists, "duplicate descriptor key %s", desc.Key)
		seen[desc.Key] = struct{}{}
		actual = append(actual, desc.Key)
	}

	require.ElementsMatch(t, expected, actual)
}
