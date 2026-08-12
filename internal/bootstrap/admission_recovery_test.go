package bootstrap

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/admission"
	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
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

func TestComputerRuntimeRecoversTaskAdmissionLeaseBinding(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	root := t.TempDir()
	taskStore, err := taskruntime.NewFileStore(filepath.Join(root, "tasks"))
	require.NoError(t, err)
	_, err = taskStore.Create(ctx, taskruntime.Task{
		ID:               "task-crashed-with-lease",
		ComputerID:       DefaultLocalComputerID,
		State:            taskruntime.StateRunning,
		Request:          computer.ExecRequest{Command: "run"},
		Attempt:          1,
		AdmissionLeaseID: "lease-crashed-task",
	})
	require.NoError(t, err)
	leaseStore, err := admission.NewFileStore(filepath.Join(root, "admission"))
	require.NoError(t, err)
	manager, err := admission.NewManager(leaseStore, []admission.Profile{{
		ComputerID: DefaultLocalComputerID,
		Capacity:   defaultAdmissionCapacity(),
	}})
	require.NoError(t, err)
	_, err = manager.Acquire(ctx, admission.Request{
		LeaseID:    "lease-crashed-task",
		TaskID:     "task-crashed-with-lease",
		ComputerID: DefaultLocalComputerID,
		Demand:     admission.Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	})
	require.NoError(t, err)

	restarted, err := newComputerRuntime(ctx, root)
	require.NoError(t, err)
	recovered, err := restarted.Tasks.Get(ctx, "task-crashed-with-lease")
	require.NoError(t, err)
	require.Equal(t, taskruntime.StateInterrupted, recovered.State)
	require.Equal(t, admission.ID("lease-crashed-task"), recovered.AdmissionLeaseID)
	require.NotZero(t, recovered.AdmissionReleasedAt)
	lease, err := restarted.AdmissionStore.Get(ctx, "lease-crashed-task")
	require.NoError(t, err)
	require.Equal(t, admission.StateReleased, lease.State)
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
