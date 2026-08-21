package hyper

import (
	"testing"

	"charm.land/catwalk/pkg/catwalk"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedGLM52UsesSupportedReasoningLevels(t *testing.T) {
	t.Parallel()

	provider := Embedded()
	for _, model := range provider.Models {
		if model.ID != "glm-5.2" {
			continue
		}
		require.Equal(t, []string{"high"}, model.ReasoningLevels)
		require.Equal(t, "high", model.DefaultReasoningEffort)
		return
	}
	t.Fatal("glm-5.2 model not found in embedded Hyper provider")
}

func TestNormalizeProviderCapabilitiesDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	provider := catwalk.Provider{Models: []catwalk.Model{
		{
			ID:                     "glm-5.2",
			ReasoningLevels:        []string{"high", "xhigh"},
			DefaultReasoningEffort: "xhigh",
		},
	}}

	normalized := NormalizeProviderCapabilities(provider)

	require.Equal(t, []string{"high"}, normalized.Models[0].ReasoningLevels)
	require.Equal(t, "high", normalized.Models[0].DefaultReasoningEffort)
	require.Equal(t, []string{"high", "xhigh"}, provider.Models[0].ReasoningLevels)
	require.Equal(t, "xhigh", provider.Models[0].DefaultReasoningEffort)
}
