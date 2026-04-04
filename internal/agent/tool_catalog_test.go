package agent

import (
	"testing"

	"github.com/chenchunrun/SecOps/internal/agent/tools"
	capregistry "github.com/chenchunrun/SecOps/internal/capability/registry"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/stretchr/testify/require"
)

func TestConfigAgentToolDefaultsStayInSyncWithRuntimeCatalog(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Options: &config.Options{
			DisabledTools: []string{},
		},
	}
	cfg.SetupAgents()

	coderAgent := cfg.Agents[config.AgentCoder]
	expectedCoderTools := []string{AgentToolName}
	expectedCoderTools = append(expectedCoderTools, tools.FixedBuiltInToolNames()...)
	expectedCoderTools = append(expectedCoderTools, capregistry.SecOpsToolNames()...)
	expectedCoderTools = append(expectedCoderTools, capregistry.SecOpsCompatibilityAliasNames()...)
	require.ElementsMatch(t, expectedCoderTools, coderAgent.AllowedTools)

	taskAgent := cfg.Agents[config.AgentTask]
	require.ElementsMatch(t, tools.ReadOnlyBuiltInToolNames(), taskAgent.AllowedTools)

	expectedSecOpsTools := append([]string(nil), tools.SecOpsRuntimeSupportToolNames()...)
	expectedSecOpsTools = append(expectedSecOpsTools, capregistry.SecOpsToolNames()...)
	expectedSecOpsTools = append(expectedSecOpsTools, capregistry.SecOpsCompatibilityAliasNames()...)

	opsAgent := cfg.Agents[config.AgentOpsAgent]
	require.ElementsMatch(t, expectedSecOpsTools, opsAgent.AllowedTools)

	securityAgent := cfg.Agents[config.AgentSecurityExpertAgent]
	require.ElementsMatch(t, expectedSecOpsTools, securityAgent.AllowedTools)
}
