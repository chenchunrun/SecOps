package admission

import (
	"context"
	"errors"
	"fmt"
)

// MigrationResult reports copied and already-identical leases.
type MigrationResult struct {
	Migrated int
	Skipped  int
}

// MigrateFileStoreToSQLite copies the latest lease versions without deleting
// source data. Repeated calls skip identical records and reject conflicts.
func MigrateFileStoreToSQLite(ctx context.Context, source *FileStore, target *SQLiteStore) (MigrationResult, error) {
	if source == nil || target == nil {
		return MigrationResult{}, ErrInvalidRequest
	}
	leases, err := source.List(ctx)
	if err != nil {
		return MigrationResult{}, fmt.Errorf("list file admission leases for migration: %w", err)
	}

	result := MigrationResult{}
	err = target.Coordinate(ctx, func() error {
		for _, lease := range leases {
			existing, err := target.Get(ctx, lease.ID)
			if err == nil {
				if !sqliteLeasesEqual(existing, lease) {
					return fmt.Errorf("%w: migration target lease %q differs", ErrLeaseConflict, lease.ID)
				}
				result.Skipped++
				continue
			}
			if !errors.Is(err, ErrNotFound) {
				return fmt.Errorf("load sqlite admission migration target: %w", err)
			}
			if err := target.importLease(ctx, lease); err != nil {
				return fmt.Errorf("import admission lease %q: %w", lease.ID, err)
			}
			result.Migrated++
		}
		return nil
	})
	return result, err
}
