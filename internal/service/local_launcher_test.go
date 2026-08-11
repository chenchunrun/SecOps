package service

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
)

func TestLocalLauncherCapturesServiceLogsOutsideProcess(t *testing.T) {
	t.Parallel()

	launcher, err := NewLocalLauncher(t.TempDir())
	require.NoError(t, err)
	machine, err := computer.NewLocalComputer("local-service-test")
	require.NoError(t, err)
	command := "printf service-ready"
	if runtime.GOOS == "windows" {
		command = "echo service-ready"
	}

	process, err := launcher.Start(context.Background(), machine, Spec{Command: command})
	require.NoError(t, err)
	require.Positive(t, process.PID())
	require.NoError(t, process.Wait())

	stdout, err := os.ReadFile(process.Logs().Stdout)
	require.NoError(t, err)
	require.Contains(t, string(stdout), "service-ready")
	require.FileExists(t, process.Logs().Stderr)
}

func TestLocalLauncherRejectsNonLocalComputer(t *testing.T) {
	t.Parallel()

	launcher, err := NewLocalLauncher(t.TempDir())
	require.NoError(t, err)
	machine, err := computer.NewDockerComputer("docker-service-test")
	require.NoError(t, err)

	process, err := launcher.Start(context.Background(), machine, Spec{Command: "serve"})
	require.ErrorIs(t, err, ErrBackendUnsupported)
	require.Nil(t, process)
}
