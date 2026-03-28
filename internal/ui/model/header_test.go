package model

import (
	"testing"

	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/stretchr/testify/require"
)

func TestHeaderAgentModeLabel(t *testing.T) {
	t.Parallel()

	require.Equal(t, "OPS", headerAgentModeLabel(config.AgentOpsAgent))
	require.Equal(t, "SEC", headerAgentModeLabel(config.AgentSecurityExpertAgent))
	require.Equal(t, "CODE", headerAgentModeLabel(config.AgentCoder))
	require.Equal(t, "AUTO", headerAgentModeLabel(""))
	require.Equal(t, "AUTO", headerAgentModeLabel("unknown"))
}
