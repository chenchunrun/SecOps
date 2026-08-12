package admission

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func TestMigrateFileStoreToSQLitePreservesLatestLeases(t *testing.T) {
	source, target := migrationStores(t)
	active := migrationLease("active", StateActive, 3)
	released := migrationLease("released", StateReleased, 7)
	seedFileLeaseVersion(t, source, active)
	seedFileLeaseVersion(t, source, released)

	result, err := MigrateFileStoreToSQLite(t.Context(), source, target)
	require.NoError(t, err)
	require.Equal(t, MigrationResult{Migrated: 2}, result)

	loaded, err := target.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, []Lease{active, released}, loaded)
	sourceLeases, err := source.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, []Lease{active, released}, sourceLeases)
}

func TestMigrateFileStoreToSQLiteResumesIdempotently(t *testing.T) {
	source, target := migrationStores(t)
	first := migrationLease("first", StateReleased, 4)
	second := migrationLease("second", StateActive, 2)
	seedFileLeaseVersion(t, source, first)
	seedFileLeaseVersion(t, source, second)
	require.NoError(t, target.importLease(t.Context(), first))

	result, err := MigrateFileStoreToSQLite(t.Context(), source, target)
	require.NoError(t, err)
	require.Equal(t, MigrationResult{Migrated: 1, Skipped: 1}, result)
	result, err = MigrateFileStoreToSQLite(t.Context(), source, target)
	require.NoError(t, err)
	require.Equal(t, MigrationResult{Skipped: 2}, result)
}

func TestMigrateFileStoreToSQLiteFailsClosedOnConflict(t *testing.T) {
	source, target := migrationStores(t)
	lease := migrationLease("conflict", StateActive, 1)
	seedFileLeaseVersion(t, source, lease)
	conflicting := lease
	conflicting.TaskID = ID("different-task")
	require.NoError(t, target.importLease(t.Context(), conflicting))

	result, err := MigrateFileStoreToSQLite(t.Context(), source, target)
	require.ErrorIs(t, err, ErrLeaseConflict)
	require.Equal(t, MigrationResult{}, result)
	loaded, err := target.Get(t.Context(), lease.ID)
	require.NoError(t, err)
	require.Equal(t, conflicting, loaded)
}

func migrationStores(t *testing.T) (*FileStore, *SQLiteStore) {
	t.Helper()
	root := t.TempDir()
	source, err := NewFileStore(filepath.Join(root, "files"))
	require.NoError(t, err)
	db, err := sql.Open("sqlite", filepath.Join(root, "admission.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	target, err := NewSQLiteStore(t.Context(), db, filepath.Join(root, "admission.db.lock"))
	require.NoError(t, err)
	return source, target
}

func migrationLease(id string, state State, version uint64) Lease {
	now := time.Date(2026, time.August, 12, 1, 2, 3, 0, time.UTC)
	lease := Lease{
		ID:         ID(id),
		TaskID:     ID("task-" + id),
		ComputerID: computer.ID("local"),
		Demand:     Resources{Slots: 1, CPUUnits: 2, MemoryMB: 256},
		State:      state,
		CreatedAt:  now,
		UpdatedAt:  now.Add(time.Duration(version) * time.Second),
		Version:    version,
	}
	if state == StateReleased {
		lease.ReleasedAt = lease.UpdatedAt
	}
	return lease
}

func seedFileLeaseVersion(t *testing.T, store *FileStore, lease Lease) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	require.NoError(t, store.writeLocked(lease))
}
