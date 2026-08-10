package taskruntime

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
	"strings"
	"sync"
)

var validIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Store interface {
	Create(ctx context.Context, task Task) (Task, error)
	Get(ctx context.Context, id ID) (Task, error)
	Update(ctx context.Context, task Task) (Task, error)
	List(ctx context.Context, states ...State) ([]Task, error)
}

// FileStore keeps task state in a host-owned directory. Each transition is a
// new immutable version, so recovery never depends on replacing a live file or
// on the continued existence of the execution backend.
type FileStore struct {
	mu   sync.RWMutex
	root string
}

func NewFileStore(root string) (*FileStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("%w: store root is required", ErrInvalidTask)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create durable task store: %w", err)
	}
	return &FileStore{root: root}, nil
}

func (s *FileStore) Create(ctx context.Context, task Task) (Task, error) {
	if err := ctx.Err(); err != nil {
		return Task{}, err
	}
	if err := validateStoredTask(task); err != nil {
		return Task{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.getLocked(task.ID); err == nil {
		return Task{}, fmt.Errorf("%w: %s", ErrAlreadyExists, task.ID)
	} else if !errors.Is(err, ErrNotFound) {
		return Task{}, err
	}

	task.Version = 1
	if err := s.writeVersionLocked(task); err != nil {
		return Task{}, err
	}
	return task, nil
}

func (s *FileStore) Get(ctx context.Context, id ID) (Task, error) {
	if err := ctx.Err(); err != nil {
		return Task{}, err
	}
	if err := validateID(id); err != nil {
		return Task{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getLocked(id)
}

func (s *FileStore) Update(ctx context.Context, task Task) (Task, error) {
	if err := ctx.Err(); err != nil {
		return Task{}, err
	}
	if err := validateStoredTask(task); err != nil {
		return Task{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.getLocked(task.ID)
	if err != nil {
		return Task{}, err
	}
	if task.Version != current.Version {
		return Task{}, fmt.Errorf("%w: task %s has version %d, current version is %d", ErrConflict, task.ID, task.Version, current.Version)
	}

	task.Version++
	if err := s.writeVersionLocked(task); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Task{}, fmt.Errorf("%w: task %s version %d already exists", ErrConflict, task.ID, task.Version)
		}
		return Task{}, err
	}
	return task, nil
}

func (s *FileStore) List(ctx context.Context, states ...State) ([]Task, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	wanted := make(map[State]struct{}, len(states))
	for _, state := range states {
		if !state.valid() {
			return nil, fmt.Errorf("%w: unknown state %q", ErrInvalidTask, state)
		}
		wanted[state] = struct{}{}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("read durable task store: %w", err)
	}
	ids := make(map[ID]struct{})
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		id, _, ok := parseVersionName(entry.Name())
		if ok {
			ids[id] = struct{}{}
		}
	}

	tasks := make([]Task, 0, len(ids))
	for id := range ids {
		task, err := s.getLocked(id)
		if err != nil {
			return nil, err
		}
		if len(wanted) > 0 {
			if _, ok := wanted[task.State]; !ok {
				continue
			}
		}
		tasks = append(tasks, task)
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID < tasks[j].ID })
	return tasks, nil
}

func (s *FileStore) getLocked(id ID) (Task, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return Task{}, fmt.Errorf("read durable task store: %w", err)
	}
	var latestVersion uint64
	var latestPath string
	for _, entry := range entries {
		entryID, version, ok := parseVersionName(entry.Name())
		if !ok || entryID != id || version <= latestVersion {
			continue
		}
		latestVersion = version
		latestPath = filepath.Join(s.root, entry.Name())
	}
	if latestPath == "" {
		return Task{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}

	data, err := os.ReadFile(latestPath)
	if err != nil {
		return Task{}, fmt.Errorf("read durable task %s: %w", id, err)
	}
	var task Task
	if err := json.Unmarshal(data, &task); err != nil {
		return Task{}, fmt.Errorf("decode durable task %s version %d: %w", id, latestVersion, err)
	}
	if task.ID != id || task.Version != latestVersion {
		return Task{}, fmt.Errorf("%w: task record identity mismatch", ErrInvalidTask)
	}
	return task, nil
}

func (s *FileStore) writeVersionLocked(task Task) error {
	data, err := json.MarshalIndent(task, "", "  ")
	if err != nil {
		return fmt.Errorf("encode durable task %s: %w", task.ID, err)
	}
	path := filepath.Join(s.root, versionName(task.ID, task.Version))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create durable task %s version %d: %w", task.ID, task.Version, err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write durable task %s version %d: %w", task.ID, task.Version, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync durable task %s version %d: %w", task.ID, task.Version, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close durable task %s version %d: %w", task.ID, task.Version, err)
	}
	remove = false
	return nil
}

func validateStoredTask(task Task) error {
	if err := validateID(task.ID); err != nil {
		return err
	}
	if !task.State.valid() {
		return fmt.Errorf("%w: unknown state %q", ErrInvalidTask, task.State)
	}
	return nil
}

func validateID(id ID) error {
	if !validIDPattern.MatchString(string(id)) {
		return fmt.Errorf("%w: invalid id %q", ErrInvalidTask, id)
	}
	return nil
}

func versionName(id ID, version uint64) string {
	return fmt.Sprintf("%s.%020d.json", id, version)
}

func parseVersionName(name string) (ID, uint64, bool) {
	if !strings.HasSuffix(name, ".json") {
		return "", 0, false
	}
	base := strings.TrimSuffix(name, ".json")
	separator := strings.LastIndexByte(base, '.')
	if separator <= 0 {
		return "", 0, false
	}
	id := ID(base[:separator])
	if validateID(id) != nil {
		return "", 0, false
	}
	version, err := strconv.ParseUint(base[separator+1:], 10, 64)
	if err != nil || version == 0 {
		return "", 0, false
	}
	return id, version, true
}
