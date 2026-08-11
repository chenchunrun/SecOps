package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/admission"
	"github.com/chenchunrun/SecOps/internal/config"
)

func TestComputerRuntimeReleasesOrphanedAdmissionLeaseOnRestart(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	runtime, err := newComputerRuntime(context.Background(), root)
	require.NoError(t, err)
	_, err = runtime.Admission.Acquire(context.Background(), admission.Request{
		LeaseID:    "lease-before-crash",
		TaskID:     "task-before-crash",
		ComputerID: DefaultLocalComputerID,
		Demand:     defaultAdmissionCapacity(),
	})
	require.NoError(t, err)

	restarted, err := newComputerRuntime(context.Background(), root)
	require.NoError(t, err)
	lease, err := restarted.Admission.Acquire(context.Background(), admission.Request{
		LeaseID:    "lease-after-restart",
		TaskID:     "task-after-restart",
		ComputerID: DefaultLocalComputerID,
		Demand:     defaultAdmissionCapacity(),
	})
	require.NoError(t, err)
	_, err = restarted.Admission.Release(context.Background(), lease.ID)
	require.NoError(t, err)
}

func TestComputerRuntimeUsesConfiguredAdmissionCapacity(t *testing.T) {
	t.Parallel()

	runtime, err := newComputerRuntimeWithConfig(context.Background(), t.TempDir(), &config.Config{
		Sandbox: &config.Sandbox{
			Mode:             "local",
			CapacitySlots:    4,
			CapacityCPUUnits: 8,
			CapacityMemoryMB: 8192,
		},
	})
	require.NoError(t, err)
	lease, err := runtime.Admission.Acquire(context.Background(), admission.Request{
		LeaseID:    "lease-configured-capacity",
		TaskID:     "task-configured-capacity",
		ComputerID: DefaultLocalComputerID,
		Demand:     admission.Resources{Slots: 4, CPUUnits: 8, MemoryMB: 8192},
	})
	require.NoError(t, err)
	_, err = runtime.Admission.Release(context.Background(), lease.ID)
	require.NoError(t, err)
}
