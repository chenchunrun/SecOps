package config

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecurityExpertUsesLeastPrivilegeSupportTools(t *testing.T) {
	t.Parallel()
	cfg := &Config{Options: &Options{}}
	cfg.SetupAgents()

	securityTools := cfg.Agents[AgentSecurityExpertAgent].AllowedTools
	opsTools := cfg.Agents[AgentOpsAgent].AllowedTools

	for _, denied := range []string{"bash", "fetch", "download"} {
		require.False(t, slices.Contains(securityTools, denied), "security expert must not expose %s by default", denied)
	}
	require.True(t, slices.Contains(securityTools, "view"))
	require.True(t, slices.Contains(securityTools, "security_scan"))
	require.True(t, slices.Contains(opsTools, "bash"), "OpsAgent compatibility must be preserved")
}
