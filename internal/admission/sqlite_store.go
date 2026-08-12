package admission

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/gofrs/flock"
)

const sqliteStoreSchema = `
CREATE TABLE IF NOT EXISTS admission_leases (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    computer_id TEXT NOT NULL,
    slots INTEGER NOT NULL,
    cpu_units INTEGER NOT NULL,
    memory_mb INTEGER NOT NULL,
    state TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    released_at_ms INTEGER,
    version INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS admission_leases_state_computer
    ON admission_leases(state, computer_id);
`

// SQLiteStore persists admission leases with indexed state lookups.
type SQLiteStore struct {
	db          *sql.DB
	lockPath    string
	coordinator chan struct{}
}

var _ Store = (*SQLiteStore)(nil)

// OpenSQLiteStore opens an independently managed SQLite admission database.
func OpenSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("open sqlite admission store: path is required")
	}
	canonicalPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve sqlite admission database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(canonicalPath), 0o700); err != nil {
		return nil, fmt.Errorf("create sqlite admission database directory: %w", err)
	}
	db, err := openSQLiteAdmissionDatabase(ctx, canonicalPath)
	if err != nil {
		return nil, err
	}
	store, err := NewSQLiteStore(ctx, db, canonicalPath+".lock")
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the underlying SQLite database.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// NewSQLiteStore initializes an admission store on an existing database.
func NewSQLiteStore(ctx context.Context, db *sql.DB, coordinationPath string) (*SQLiteStore, error) {
	if db == nil {
		return nil, fmt.Errorf("initialize sqlite admission store: database is required")
	}
	if coordinationPath == "" {
		return nil, fmt.Errorf("initialize sqlite admission store: coordination path is required")
	}
	canonicalPath, err := filepath.Abs(coordinationPath)
	if err != nil {
		return nil, fmt.Errorf("resolve sqlite admission coordination path: %w", err)
	}
	if _, err := db.ExecContext(ctx, sqliteStoreSchema); err != nil {
		return nil, fmt.Errorf("initialize sqlite admission schema: %w", err)
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	coordinator, _ := storeCoordinators.LoadOrStore(filepath.Clean(canonicalPath), gate)
	return &SQLiteStore{
		db:          db,
		lockPath:    canonicalPath,
		coordinator: coordinator.(chan struct{}),
	}, nil
}

func (s *SQLiteStore) Coordinate(ctx context.Context, action func() error) (err error) {
	select {
	case <-s.coordinator:
		defer func() { s.coordinator <- struct{}{} }()
	case <-ctx.Done():
		return fmt.Errorf("acquire local sqlite admission lock: %w", context.Cause(ctx))
	}

	lock := flock.New(s.lockPath)
	locked, err := lock.TryLockContext(ctx, coordinationRetryInterval)
	if err != nil {
		return fmt.Errorf("acquire sqlite admission store lock: %w", err)
	}
	if !locked {
		return fmt.Errorf("acquire sqlite admission store lock: %w", context.Cause(ctx))
	}
	defer func() {
		if unlockErr := lock.Unlock(); unlockErr != nil {
			err = errors.Join(err, fmt.Errorf("release sqlite admission store lock: %w", unlockErr))
		}
	}()
	return action()
}

func (s *SQLiteStore) Create(ctx context.Context, lease Lease) (Lease, error) {
	if !validLeaseIdentity(lease) || lease.State != StateActive {
		return Lease{}, ErrInvalidRequest
	}
	lease.Version = 1
	result, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO admission_leases (
        id, task_id, computer_id, slots, cpu_units, memory_mb, state,
        created_at_ms, updated_at_ms, released_at_ms, version
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
		lease.ID, lease.TaskID, lease.ComputerID,
		lease.Demand.Slots, lease.Demand.CPUUnits, lease.Demand.MemoryMB,
		lease.State, lease.CreatedAt.UnixMilli(), lease.UpdatedAt.UnixMilli(), lease.Version,
	)
	if err != nil {
		return Lease{}, fmt.Errorf("create sqlite admission lease: %w", err)
	}
	written, err := result.RowsAffected()
	if err != nil {
		return Lease{}, fmt.Errorf("inspect sqlite admission create: %w", err)
	}
	if written == 0 {
		return Lease{}, ErrAlreadyExists
	}
	return lease, nil
}

func (s *SQLiteStore) importLease(ctx context.Context, lease Lease) error {
	if !validLeaseIdentity(lease) || lease.Version < 1 || (lease.State != StateActive && lease.State != StateReleased) {
		return ErrInvalidRequest
	}
	var releasedAt any
	if !lease.ReleasedAt.IsZero() {
		releasedAt = lease.ReleasedAt.UnixMilli()
	}
	result, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO admission_leases (
        id, task_id, computer_id, slots, cpu_units, memory_mb, state,
        created_at_ms, updated_at_ms, released_at_ms, version
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		lease.ID, lease.TaskID, lease.ComputerID,
		lease.Demand.Slots, lease.Demand.CPUUnits, lease.Demand.MemoryMB,
		lease.State, lease.CreatedAt.UnixMilli(), lease.UpdatedAt.UnixMilli(), releasedAt, lease.Version,
	)
	if err != nil {
		return fmt.Errorf("import sqlite admission lease: %w", err)
	}
	written, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect sqlite admission import: %w", err)
	}
	if written == 1 {
		return nil
	}
	existing, err := s.Get(ctx, lease.ID)
	if err != nil {
		return err
	}
	if !sqliteLeasesEqual(existing, lease) {
		return ErrLeaseConflict
	}
	return nil
}

func sqliteLeasesEqual(left, right Lease) bool {
	return left.ID == right.ID &&
		left.TaskID == right.TaskID &&
		left.ComputerID == right.ComputerID &&
		left.Demand == right.Demand &&
		left.State == right.State &&
		left.CreatedAt.UnixMilli() == right.CreatedAt.UnixMilli() &&
		left.UpdatedAt.UnixMilli() == right.UpdatedAt.UnixMilli() &&
		left.ReleasedAt.UnixMilli() == right.ReleasedAt.UnixMilli() &&
		left.Version == right.Version
}

func (s *SQLiteStore) Get(ctx context.Context, id ID) (Lease, error) {
	if !idPattern.MatchString(string(id)) {
		return Lease{}, ErrInvalidRequest
	}
	lease, err := scanSQLiteLease(s.db.QueryRowContext(ctx, sqliteLeaseSelect+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Lease{}, ErrNotFound
	}
	if err != nil {
		return Lease{}, fmt.Errorf("get sqlite admission lease: %w", err)
	}
	return lease, nil
}

func (s *SQLiteStore) Update(ctx context.Context, lease Lease) (Lease, error) {
	if !validLeaseIdentity(lease) || (lease.State != StateActive && lease.State != StateReleased) || lease.Version < 1 {
		return Lease{}, ErrInvalidRequest
	}
	nextVersion := lease.Version + 1
	var releasedAt any
	if !lease.ReleasedAt.IsZero() {
		releasedAt = lease.ReleasedAt.UnixMilli()
	}
	result, err := s.db.ExecContext(ctx, `UPDATE admission_leases SET
        task_id = ?, computer_id = ?, slots = ?, cpu_units = ?, memory_mb = ?,
        state = ?, created_at_ms = ?, updated_at_ms = ?, released_at_ms = ?, version = ?
        WHERE id = ? AND version = ?`,
		lease.TaskID, lease.ComputerID,
		lease.Demand.Slots, lease.Demand.CPUUnits, lease.Demand.MemoryMB,
		lease.State, lease.CreatedAt.UnixMilli(), lease.UpdatedAt.UnixMilli(), releasedAt, nextVersion,
		lease.ID, lease.Version,
	)
	if err != nil {
		return Lease{}, fmt.Errorf("update sqlite admission lease: %w", err)
	}
	written, err := result.RowsAffected()
	if err != nil {
		return Lease{}, fmt.Errorf("inspect sqlite admission update: %w", err)
	}
	if written == 0 {
		if _, err := s.Get(ctx, lease.ID); errors.Is(err, ErrNotFound) {
			return Lease{}, ErrNotFound
		} else if err != nil {
			return Lease{}, err
		}
		return Lease{}, ErrVersionConflict
	}
	lease.Version = nextVersion
	return lease, nil
}

func (s *SQLiteStore) List(ctx context.Context, states ...State) ([]Lease, error) {
	query := sqliteLeaseSelect
	args := make([]any, 0, len(states))
	if len(states) > 0 {
		placeholders := make([]string, len(states))
		for index, state := range states {
			if state != StateActive && state != StateReleased {
				return nil, ErrInvalidRequest
			}
			placeholders[index] = "?"
			args = append(args, state)
		}
		query += ` WHERE state IN (` + strings.Join(placeholders, ",") + `)`
	}
	query += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list sqlite admission leases: %w", err)
	}
	defer rows.Close()

	leases := make([]Lease, 0)
	for rows.Next() {
		lease, err := scanSQLiteLease(rows)
		if err != nil {
			return nil, fmt.Errorf("scan sqlite admission lease: %w", err)
		}
		leases = append(leases, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sqlite admission leases: %w", err)
	}
	return leases, nil
}

const sqliteLeaseSelect = `SELECT
    id, task_id, computer_id, slots, cpu_units, memory_mb, state,
    created_at_ms, updated_at_ms, released_at_ms, version
    FROM admission_leases`

type sqliteScanner interface {
	Scan(dest ...any) error
}

func scanSQLiteLease(scanner sqliteScanner) (Lease, error) {
	var lease Lease
	var computerID string
	var createdAt int64
	var updatedAt int64
	var releasedAt sql.NullInt64
	err := scanner.Scan(
		&lease.ID, &lease.TaskID, &computerID,
		&lease.Demand.Slots, &lease.Demand.CPUUnits, &lease.Demand.MemoryMB,
		&lease.State, &createdAt, &updatedAt, &releasedAt, &lease.Version,
	)
	if err != nil {
		return Lease{}, err
	}
	lease.ComputerID = computer.ID(computerID)
	lease.CreatedAt = time.UnixMilli(createdAt).UTC()
	lease.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	if releasedAt.Valid {
		lease.ReleasedAt = time.UnixMilli(releasedAt.Int64).UTC()
	}
	return lease, nil
}
