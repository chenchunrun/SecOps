package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/config"
)

func TestComputerRuntimeRegistersConfiguredSSHServiceBackend(t *testing.T) {
	t.Parallel()

	runtime, err := newComputerRuntimeWithConfig(context.Background(), t.TempDir(), &config.Config{
		Sandbox: &config.Sandbox{
			Mode:    "ssh",
			Host:    "build.example.com",
			User:    "ops",
			KeyPath: "/keys/build_ed25519",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, runtime.Services)

	machine, err := runtime.Computers.Get(DefaultSSHComputerID)
	require.NoError(t, err)
	require.Equal(t, computer.BackendSSH, machine.Backend())
}

func TestComputerRuntimeDoesNotRegisterIncompleteSSHServiceBackend(t *testing.T) {
	t.Parallel()

	runtime, err := newComputerRuntimeWithConfig(context.Background(), t.TempDir(), &config.Config{
		Sandbox: &config.Sandbox{Mode: "ssh", User: "ops"},
	})
	require.NoError(t, err)

	_, err = runtime.Computers.Get(DefaultSSHComputerID)
	require.ErrorIs(t, err, computer.ErrNotFound)
}
