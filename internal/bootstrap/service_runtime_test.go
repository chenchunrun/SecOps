package bootstrap

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/service"
)

func TestComputerRuntimeRecoversInterruptedServices(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store, err := service.NewFileStore(filepath.Join(root, "services"))
	require.NoError(t, err)
	running, err := store.Create(context.Background(), service.Service{
		ID:         "service-running-at-crash",
		ComputerID: DefaultLocalComputerID,
		State:      service.StateRunning,
		Spec: service.Spec{
			Command: "non-idempotent-server",
			Ports:   []service.Port{{Name: "http", Protocol: service.ProtocolTCP, Number: 8080}},
		},
	})
	require.NoError(t, err)

	runtime, err := newComputerRuntime(context.Background(), root)
	require.NoError(t, err)
	require.NotNil(t, runtime.Services)
	require.Len(t, runtime.RecoveredServices, 1)
	require.Equal(t, running.ID, runtime.RecoveredServices[0].ID)
	require.Equal(t, service.StateInterrupted, runtime.RecoveredServices[0].State)
}
