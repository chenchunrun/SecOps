package admission

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagersSharingStoreRootDoNotOversubscribe(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	storeA, err := NewFileStore(root)
	require.NoError(t, err)
	storeB, err := NewFileStore(root)
	require.NoError(t, err)
	profile := Profile{ComputerID: "shared-computer", Capacity: Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256}}
	managerA, err := NewManager(storeA, []Profile{profile})
	require.NoError(t, err)
	managerB, err := NewManager(storeB, []Profile{profile})
	require.NoError(t, err)

	const contenders = 64
	start := make(chan struct{})
	var wait sync.WaitGroup
	var admitted atomic.Int64
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			manager := managerA
			if index%2 == 1 {
				manager = managerB
			}
			_, acquireErr := manager.Acquire(context.Background(), Request{
				LeaseID:    ID(fmt.Sprintf("shared-lease-%03d", index)),
				TaskID:     ID(fmt.Sprintf("shared-task-%03d", index)),
				ComputerID: "shared-computer",
				Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
			})
			if acquireErr == nil {
				admitted.Add(1)
				return
			}
			require.ErrorIs(t, acquireErr, ErrCapacityExceeded)
		}(index)
	}
	close(start)
	wait.Wait()
	require.Equal(t, int64(1), admitted.Load())

	active, err := storeA.List(context.Background(), StateActive)
	require.NoError(t, err)
	require.Len(t, active, 1)
}

func TestCorruptedLatestLeaseFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store, err := NewFileStore(root)
	require.NoError(t, err)
	profile := Profile{ComputerID: "corrupt-computer", Capacity: Resources{Slots: 2, CPUUnits: 2, MemoryMB: 512}}
	manager, err := NewManager(store, []Profile{profile})
	require.NoError(t, err)
	lease, err := manager.Acquire(context.Background(), Request{
		LeaseID:    "lease-corrupt",
		TaskID:     "task-corrupt",
		ComputerID: "corrupt-computer",
		Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, versionName(lease.ID, lease.Version)), []byte("{"), 0o600))

	reopened, err := NewFileStore(root)
	require.NoError(t, err)
	restarted, err := NewManager(reopened, []Profile{profile})
	require.NoError(t, err)
	_, err = restarted.Acquire(context.Background(), Request{
		LeaseID:    "lease-after-corruption",
		TaskID:     "task-after-corruption",
		ComputerID: "corrupt-computer",
		Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	})
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrCapacityExceeded)
	_, getErr := reopened.Get(context.Background(), "lease-after-corruption")
	require.ErrorIs(t, getErr, ErrNotFound)
}
