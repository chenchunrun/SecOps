package admission

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
)

func TestManagerEnforcesComputerResourceCapacity(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	manager, err := NewManager(store, []Profile{{
		ComputerID: "docker-build",
		Capacity:   Resources{Slots: 2, CPUUnits: 4, MemoryMB: 4096},
	}})
	require.NoError(t, err)

	first, err := manager.Acquire(context.Background(), Request{
		LeaseID:    "lease-1",
		TaskID:     "task-1",
		ComputerID: "docker-build",
		Demand:     Resources{Slots: 1, CPUUnits: 2, MemoryMB: 2048},
	})
	require.NoError(t, err)
	require.Equal(t, StateActive, first.State)
	_, err = manager.Acquire(context.Background(), Request{
		LeaseID:    "lease-2",
		TaskID:     "task-2",
		ComputerID: "docker-build",
		Demand:     Resources{Slots: 1, CPUUnits: 3, MemoryMB: 2048},
	})
	require.ErrorIs(t, err, ErrCapacityExceeded)

	released, err := manager.Release(context.Background(), first.ID)
	require.NoError(t, err)
	require.Equal(t, StateReleased, released.State)
	second, err := manager.Acquire(context.Background(), Request{
		LeaseID:    "lease-2",
		TaskID:     "task-2",
		ComputerID: "docker-build",
		Demand:     Resources{Slots: 1, CPUUnits: 3, MemoryMB: 2048},
	})
	require.NoError(t, err)
	require.Equal(t, StateActive, second.State)
}

func TestManagerAcquireIsAtomicUnderConcurrency(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	manager, err := NewManager(store, []Profile{{
		ComputerID: "local-default",
		Capacity:   Resources{Slots: 3, CPUUnits: 3, MemoryMB: 768},
	}})
	require.NoError(t, err)

	const contenders = 20
	var wait sync.WaitGroup
	results := make(chan error, contenders)
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, acquireErr := manager.Acquire(context.Background(), Request{
				LeaseID:    ID("lease-concurrent-" + string(rune('a'+index))),
				TaskID:     ID("task-concurrent-" + string(rune('a'+index))),
				ComputerID: "local-default",
				Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
			})
			results <- acquireErr
		}(index)
	}
	wait.Wait()
	close(results)

	var admitted, rejected int
	for acquireErr := range results {
		if acquireErr == nil {
			admitted++
			continue
		}
		require.ErrorIs(t, acquireErr, ErrCapacityExceeded)
		rejected++
	}
	require.Equal(t, 3, admitted)
	require.Equal(t, contenders-3, rejected)
}

func TestManagerRestoresActiveLeasesAfterRestart(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	profile := Profile{ComputerID: "ssh-default", Capacity: Resources{Slots: 1, CPUUnits: 2, MemoryMB: 1024}}
	store, err := NewFileStore(root)
	require.NoError(t, err)
	manager, err := NewManager(store, []Profile{profile})
	require.NoError(t, err)
	lease, err := manager.Acquire(context.Background(), Request{
		LeaseID:    "lease-remote",
		TaskID:     "task-remote",
		ComputerID: "ssh-default",
		Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 512},
	})
	require.NoError(t, err)

	reopened, err := NewFileStore(root)
	require.NoError(t, err)
	restarted, err := NewManager(reopened, []Profile{profile})
	require.NoError(t, err)
	_, err = restarted.Acquire(context.Background(), Request{
		LeaseID:    "lease-blocked",
		TaskID:     "task-blocked",
		ComputerID: "ssh-default",
		Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 512},
	})
	require.ErrorIs(t, err, ErrCapacityExceeded)

	released, err := restarted.Release(context.Background(), lease.ID)
	require.NoError(t, err)
	again, err := restarted.Release(context.Background(), lease.ID)
	require.NoError(t, err)
	require.Equal(t, released, again)
}

func TestManagerAcquireIsIdempotentAndRejectsLeaseReuse(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	manager, err := NewManager(store, []Profile{{ComputerID: "docker-a", Capacity: Resources{Slots: 2, CPUUnits: 2, MemoryMB: 512}}})
	require.NoError(t, err)
	request := Request{
		LeaseID:    "lease-idempotent",
		TaskID:     "task-a",
		ComputerID: "docker-a",
		Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	}

	first, err := manager.Acquire(context.Background(), request)
	require.NoError(t, err)
	again, err := manager.Acquire(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, first, again)
	request.TaskID = "task-b"
	_, err = manager.Acquire(context.Background(), request)
	require.ErrorIs(t, err, ErrLeaseConflict)
}

func TestManagerRejectsUnknownComputerAndInvalidDemand(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	manager, err := NewManager(store, []Profile{{ComputerID: computer.ID("local-default"), Capacity: Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256}}})
	require.NoError(t, err)

	_, err = manager.Acquire(context.Background(), Request{
		LeaseID:    "lease-unknown",
		TaskID:     "task-unknown",
		ComputerID: "unknown",
		Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	})
	require.ErrorIs(t, err, ErrUnknownComputer)
	_, err = manager.Acquire(context.Background(), Request{
		LeaseID:    "lease-invalid",
		TaskID:     "task-invalid",
		ComputerID: "local-default",
		Demand:     Resources{Slots: 0, CPUUnits: 1, MemoryMB: 256},
	})
	require.ErrorIs(t, err, ErrInvalidRequest)
}

func TestManagerReconcileReleasesOnlyOrphanedLeases(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	manager, err := NewManager(store, []Profile{{
		ComputerID: "local-default",
		Capacity:   Resources{Slots: 2, CPUUnits: 2, MemoryMB: 512},
	}})
	require.NoError(t, err)
	keep, err := manager.Acquire(context.Background(), Request{
		LeaseID:    "lease-keep",
		TaskID:     "task-keep",
		ComputerID: "local-default",
		Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	})
	require.NoError(t, err)
	orphan, err := manager.Acquire(context.Background(), Request{
		LeaseID:    "lease-orphan",
		TaskID:     "task-orphan",
		ComputerID: "local-default",
		Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	})
	require.NoError(t, err)

	released, err := manager.Reconcile(context.Background(), map[ID]struct{}{"task-keep": {}})
	require.NoError(t, err)
	require.Len(t, released, 1)
	require.Equal(t, orphan.ID, released[0].ID)
	persistedKeep, err := store.Get(context.Background(), keep.ID)
	require.NoError(t, err)
	require.Equal(t, StateActive, persistedKeep.State)
	persistedOrphan, err := store.Get(context.Background(), orphan.ID)
	require.NoError(t, err)
	require.Equal(t, StateReleased, persistedOrphan.State)
}
