package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
)

type recordingLauncher struct {
	calls int
}

func (l *recordingLauncher) Start(context.Context, computer.Computer, Spec) (Process, error) {
	l.calls++
	return newFakeProcess(9000 + l.calls), nil
}

func TestBackendLauncherDispatchesByComputerBackend(t *testing.T) {
	t.Parallel()

	local := &recordingLauncher{}
	docker := &recordingLauncher{}
	launcher, err := NewBackendLauncher(map[computer.Backend]Launcher{
		computer.BackendLocal:  local,
		computer.BackendDocker: docker,
	})
	require.NoError(t, err)
	dockerComputer, err := computer.NewDockerComputer("docker-service")
	require.NoError(t, err)

	process, err := launcher.Start(context.Background(), dockerComputer, Spec{Command: "serve"})
	require.NoError(t, err)
	require.NotNil(t, process)
	require.Equal(t, 0, local.calls)
	require.Equal(t, 1, docker.calls)
}

func TestBackendLauncherFailsClosedForUnregisteredBackend(t *testing.T) {
	t.Parallel()

	launcher, err := NewBackendLauncher(map[computer.Backend]Launcher{
		computer.BackendLocal: &recordingLauncher{},
	})
	require.NoError(t, err)
	sshComputer, err := computer.NewSSHComputer("ssh-service", "ops", "/tmp/key")
	require.NoError(t, err)

	process, err := launcher.Start(context.Background(), sshComputer, Spec{Command: "serve"})
	require.ErrorIs(t, err, ErrBackendUnsupported)
	require.Nil(t, process)
}
