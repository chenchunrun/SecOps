//go:build windows

package service

import (
	"context"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigureServiceProcessCreatesWindowsProcessGroup(t *testing.T) {
	t.Parallel()

	command := exec.CommandContext(context.Background(), "cmd.exe", "/C", "exit 0")
	configureServiceProcess(command)
	require.NotNil(t, command.SysProcAttr)
	require.NotZero(t, command.SysProcAttr.CreationFlags&windowsCreateNewProcessGroup)
}
