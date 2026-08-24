package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExplicitThemeConfigured(t *testing.T) {
	t.Parallel()

	require.True(t, explicitThemeConfigured("dark"))
	require.True(t, explicitThemeConfigured(" LIGHT "))
	require.False(t, explicitThemeConfigured(""))
	require.False(t, explicitThemeConfigured("auto"))
	require.False(t, explicitThemeConfigured("invalid"))
}
