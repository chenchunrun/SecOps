package bootstrap

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/admission"
)

func TestInitializeAdmissionStoreDefaultsToFile(t *testing.T) {
	t.Parallel()

	store, err := initializeAdmissionStore(context.Background(), t.TempDir(), "")
	require.NoError(t, err)
	require.IsType(t, &admission.FileStore{}, store)
}

func TestInitializeAdmissionStoreMigratesToSQLiteIdempotently(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	root := t.TempDir()
	fileStore, err := admission.NewFileStore(admissionStorePath(root))
	require.NoError(t, err)
	manager, err := admission.NewManager(fileStore, []admission.Profile{{
		ComputerID: DefaultLocalComputerID,
		Capacity:   defaultAdmissionCapacity(),
	}})
	require.NoError(t, err)
	lease, err := manager.Acquire(ctx, admission.Request{
		LeaseID:    "lease-migrate",
		TaskID:     "task-migrate",
		ComputerID: DefaultLocalComputerID,
		Demand:     defaultAdmissionCapacity(),
	})
	require.NoError(t, err)
	released, err := manager.Release(ctx, lease.ID)
	require.NoError(t, err)

	store, err := initializeAdmissionStore(ctx, root, "sqlite")
	require.NoError(t, err)
	require.IsType(t, &admission.SQLiteStore{}, store)
	sqliteStore := store.(*admission.SQLiteStore)
	t.Cleanup(func() { require.NoError(t, sqliteStore.Close()) })
	migrated, err := sqliteStore.Get(ctx, lease.ID)
	require.NoError(t, err)
	require.Equal(t, released.ID, migrated.ID)
	require.Equal(t, released.TaskID, migrated.TaskID)
	require.Equal(t, released.ComputerID, migrated.ComputerID)
	require.Equal(t, released.Demand, migrated.Demand)
	require.Equal(t, released.State, migrated.State)
	require.Equal(t, released.Version, migrated.Version)
	require.Equal(t, released.CreatedAt.Truncate(time.Millisecond), migrated.CreatedAt)
	require.Equal(t, released.UpdatedAt.Truncate(time.Millisecond), migrated.UpdatedAt)
	require.Equal(t, released.ReleasedAt.Truncate(time.Millisecond), migrated.ReleasedAt)

	restarted, err := initializeAdmissionStore(ctx, root, "SQLITE")
	require.NoError(t, err)
	require.IsType(t, &admission.SQLiteStore{}, restarted)
	restartedSQLite := restarted.(*admission.SQLiteStore)
	t.Cleanup(func() { require.NoError(t, restartedSQLite.Close()) })
	migrated, err = restartedSQLite.Get(ctx, lease.ID)
	require.NoError(t, err)
	require.Equal(t, released.ID, migrated.ID)
	require.Equal(t, released.Version, migrated.Version)

	sourceLease, err := fileStore.Get(ctx, lease.ID)
	require.NoError(t, err)
	require.Equal(t, released, sourceLease)
}

func TestInitializeAdmissionStoreRejectsUnknownBackend(t *testing.T) {
	t.Parallel()

	store, err := initializeAdmissionStore(context.Background(), t.TempDir(), "redis")
	require.ErrorContains(t, err, "unsupported admission store")
	require.Nil(t, store)
}
