package admission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
)

var (
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]{0,127})\.v([0-9]{20})\.json$`)
)

type Store interface {
	Create(ctx context.Context, lease Lease) (Lease, error)
	Get(ctx context.Context, id ID) (Lease, error)
	Update(ctx context.Context, lease Lease) (Lease, error)
	List(ctx context.Context, states ...State) ([]Lease, error)
}

type FileStore struct {
	root string
	mu   sync.Mutex
}

func NewFileStore(root string) (*FileStore, error) {
	if root == "" {
		return nil, fmt.Errorf("initialize admission store: root is empty")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create admission store: %w", err)
	}
	return &FileStore{root: root}, nil
}

func (s *FileStore) Create(ctx context.Context, lease Lease) (Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := contextErr(ctx); err != nil {
		return Lease{}, err
	}
	if !validLeaseIdentity(lease) || lease.State != StateActive {
		return Lease{}, ErrInvalidRequest
	}
	if _, err := s.getLocked(lease.ID); err == nil {
		return Lease{}, ErrAlreadyExists
	} else if !errors.Is(err, ErrNotFound) {
		return Lease{}, err
	}
	lease.Version = 1
	if err := s.writeLocked(lease); err != nil {
		return Lease{}, err
	}
	return lease, nil
}

func (s *FileStore) Get(ctx context.Context, id ID) (Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := contextErr(ctx); err != nil {
		return Lease{}, err
	}
	return s.getLocked(id)
}

func (s *FileStore) Update(ctx context.Context, lease Lease) (Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := contextErr(ctx); err != nil {
		return Lease{}, err
	}
	current, err := s.getLocked(lease.ID)
	if err != nil {
		return Lease{}, err
	}
	if current.Version != lease.Version {
		return Lease{}, ErrVersionConflict
	}
	lease.Version++
	if err := s.writeLocked(lease); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			return Lease{}, ErrVersionConflict
		}
		return Lease{}, err
	}
	return lease, nil
}

func (s *FileStore) List(ctx context.Context, states ...State) ([]Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("list admission leases: %w", err)
	}
	latest := make(map[ID]uint64)
	for _, entry := range entries {
		id, version, ok := parseVersionName(entry.Name())
		if ok && version > latest[id] {
			latest[id] = version
		}
	}
	wanted := make(map[State]struct{}, len(states))
	for _, state := range states {
		wanted[state] = struct{}{}
	}
	leases := make([]Lease, 0, len(latest))
	for id, version := range latest {
		lease, err := s.readLocked(id, version)
		if err != nil {
			return nil, err
		}
		if len(wanted) > 0 {
			if _, ok := wanted[lease.State]; !ok {
				continue
			}
		}
		leases = append(leases, lease)
	}
	sort.Slice(leases, func(i, j int) bool { return leases[i].ID < leases[j].ID })
	return leases, nil
}

func (s *FileStore) getLocked(id ID) (Lease, error) {
	if !idPattern.MatchString(string(id)) {
		return Lease{}, ErrNotFound
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return Lease{}, fmt.Errorf("list admission lease versions: %w", err)
	}
	var latest uint64
	for _, entry := range entries {
		entryID, version, ok := parseVersionName(entry.Name())
		if ok && entryID == id && version > latest {
			latest = version
		}
	}
	if latest == 0 {
		return Lease{}, ErrNotFound
	}
	return s.readLocked(id, latest)
}

func (s *FileStore) readLocked(id ID, version uint64) (Lease, error) {
	data, err := os.ReadFile(filepath.Join(s.root, versionName(id, version)))
	if err != nil {
		return Lease{}, fmt.Errorf("read admission lease: %w", err)
	}
	var lease Lease
	if err := json.Unmarshal(data, &lease); err != nil {
		return Lease{}, fmt.Errorf("decode admission lease: %w", err)
	}
	if lease.ID != id || lease.Version != version || !validLeaseIdentity(lease) {
		return Lease{}, fmt.Errorf("decode admission lease: identity or version mismatch")
	}
	return lease, nil
}

func (s *FileStore) writeLocked(lease Lease) error {
	data, err := json.Marshal(lease)
	if err != nil {
		return fmt.Errorf("encode admission lease: %w", err)
	}
	path := filepath.Join(s.root, versionName(lease.ID, lease.Version))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("create admission lease version: %w", err)
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write admission lease version: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync admission lease version: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close admission lease version: %w", err)
	}
	remove = false
	return nil
}

func versionName(id ID, version uint64) string {
	return fmt.Sprintf("%s.v%020d.json", id, version)
}

func parseVersionName(name string) (ID, uint64, bool) {
	matches := versionPattern.FindStringSubmatch(name)
	if len(matches) != 3 {
		return "", 0, false
	}
	version, err := strconv.ParseUint(matches[2], 10, 64)
	if err != nil || version == 0 {
		return "", 0, false
	}
	return ID(matches[1]), version, true
}

func validLeaseIdentity(lease Lease) bool {
	return idPattern.MatchString(string(lease.ID)) && idPattern.MatchString(string(lease.TaskID)) && idPattern.MatchString(string(lease.ComputerID))
}

func contextErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
