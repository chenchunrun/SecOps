package admission

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func TestSQLiteStoreContractAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admission.db")
	db := openAdmissionSQLite(t, path)
	store, err := NewSQLiteStore(t.Context(), db, path+".lock")
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Millisecond)
	created, err := store.Create(t.Context(), Lease{
		ID:         ID("lease-1"),
		TaskID:     ID("task-1"),
		ComputerID: computer.ID("local"),
		Demand:     Resources{Slots: 1, CPUUnits: 2, MemoryMB: 256},
		State:      StateActive,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	require.NoError(t, err)
	require.Equal(t, uint64(1), created.Version)

	_, err = store.Create(t.Context(), created)
	require.ErrorIs(t, err, ErrAlreadyExists)
	loaded, err := store.Get(t.Context(), created.ID)
	require.NoError(t, err)
	require.Equal(t, created, loaded)
	active, err := store.List(t.Context(), StateActive)
	require.NoError(t, err)
	require.Equal(t, []Lease{created}, active)

	stale := created
	created.State = StateReleased
	created.UpdatedAt = now.Add(time.Second)
	created.ReleasedAt = created.UpdatedAt
	released, err := store.Update(t.Context(), created)
	require.NoError(t, err)
	require.Equal(t, uint64(2), released.Version)
	_, err = store.Update(t.Context(), stale)
	require.ErrorIs(t, err, ErrVersionConflict)

	require.NoError(t, db.Close())
	reopened := openAdmissionSQLite(t, path)
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	restarted, err := NewSQLiteStore(t.Context(), reopened, path+".lock")
	require.NoError(t, err)
	loaded, err = restarted.Get(t.Context(), created.ID)
	require.NoError(t, err)
	require.Equal(t, released, loaded)
	active, err = restarted.List(t.Context(), StateActive)
	require.NoError(t, err)
	require.Empty(t, active)
}

func TestSQLiteManagersAcrossConnectionsDoNotOversubscribe(t *testing.T) {
	const contenders = 64

	path := filepath.Join(t.TempDir(), "admission.db")
	dbOne := openAdmissionSQLite(t, path)
	t.Cleanup(func() { require.NoError(t, dbOne.Close()) })
	dbTwo := openAdmissionSQLite(t, path)
	t.Cleanup(func() { require.NoError(t, dbTwo.Close()) })
	storeOne, err := NewSQLiteStore(t.Context(), dbOne, path+".lock")
	require.NoError(t, err)
	storeTwo, err := NewSQLiteStore(t.Context(), dbTwo, path+".lock")
	require.NoError(t, err)
	profile := []Profile{{
		ComputerID: computer.ID("local"),
		Capacity:   Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	}}
	managerOne, err := NewManager(storeOne, profile)
	require.NoError(t, err)
	managerTwo, err := NewManager(storeTwo, profile)
	require.NoError(t, err)

	start := make(chan struct{})
	var admitted atomic.Int64
	errorsFound := make(chan error, contenders)
	var wait sync.WaitGroup
	wait.Add(contenders)
	for index := range contenders {
		go func() {
			defer wait.Done()
			<-start
			manager := managerOne
			if index%2 == 1 {
				manager = managerTwo
			}
			_, err := manager.Acquire(context.Background(), Request{
				LeaseID:    ID(fmt.Sprintf("lease-%d", index)),
				TaskID:     ID(fmt.Sprintf("task-%d", index)),
				ComputerID: computer.ID("local"),
				Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
			})
			if err == nil {
				admitted.Add(1)
				return
			}
			if !errors.Is(err, ErrCapacityExceeded) {
				errorsFound <- err
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		require.NoError(t, err)
	}
	require.Equal(t, int64(1), admitted.Load())
	active, err := storeOne.List(t.Context(), StateActive)
	require.NoError(t, err)
	require.Len(t, active, 1)
}

func openAdmissionSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 30000;`)
	require.NoError(t, err)
	return db
}
