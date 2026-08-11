package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/config"
)

func TestComputerRuntimeRegistersConfiguredDockerServiceBackend(t *testing.T) {
	t.Parallel()

	runtime, err := newComputerRuntimeWithConfig(context.Background(), t.TempDir(), &config.Config{
		Sandbox: &config.Sandbox{
			Mode:    "docker",
			Image:   "alpine:3.20",
			Network: "none",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, runtime.Services)

	machine, err := runtime.Computers.Get(DefaultDockerComputerID)
	require.NoError(t, err)
	require.Equal(t, computer.BackendDocker, machine.Backend())
}
