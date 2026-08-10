package computer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagerKeepsStableDestroyedIdentityFailClosed(t *testing.T) {
	t.Parallel()

	manager := NewManager()
	machine, err := NewLocalComputer("computer-local-1")
	require.NoError(t, err)
	require.NoError(t, manager.Register(machine))

	resolved, err := manager.Get(machine.ID())
	require.NoError(t, err)
	require.Same(t, machine, resolved)

	require.NoError(t, manager.Destroy(context.Background(), machine.ID()))
	require.NoError(t, manager.Destroy(context.Background(), machine.ID()))
	require.Equal(t, StateDestroyed, machine.State())

	resolved, err = manager.Get(machine.ID())
	require.NoError(t, err)
	_, err = resolved.Exec(context.Background(), ExecRequest{Command: "echo must-not-run"})
	require.ErrorIs(t, err, ErrDestroyed)
}

func TestManagerRejectsDuplicateAndUnknownIdentity(t *testing.T) {
	t.Parallel()

	manager := NewManager()
	first, err := NewLocalComputer("computer-local-1")
	require.NoError(t, err)
	duplicate, err := NewLocalComputer("computer-local-1")
	require.NoError(t, err)
	require.NoError(t, manager.Register(first))
	require.ErrorIs(t, manager.Register(duplicate), ErrAlreadyRegistered)

	_, err = manager.Get("missing")
	require.ErrorIs(t, err, ErrNotFound)
	require.ErrorIs(t, manager.Destroy(context.Background(), "missing"), ErrNotFound)
}
