package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanCommandsAreHandledBeforeLLMRouting(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"/scan", "/scan authorize /tmp/my project", "/scan run /tmp/project", "/scan review task passed Checked packages", "/scan cancel task", "/scan list"} {
		command, matched := parseSlashControlCommand(input)
		require.True(t, matched)
		require.NotNil(t, command.scan)
		require.Nil(t, command.agentMode)
	}
}
