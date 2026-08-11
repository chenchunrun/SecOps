package service

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
	Create(ctx context.Context, service Service) (Service, error)
	Get(ctx context.Context, id ID) (Service, error)
	Update(ctx context.Context, service Service) (Service, error)
	List(ctx context.Context, states ...State) ([]Service, error)
}

// FileStore persists immutable service versions outside runtime backends.
type FileStore struct {
	mu   sync.RWMutex
	root string
}

func NewFileStore(root string) (*FileStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("%w: store root is required", ErrInvalidService)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create durable service store: %w", err)
	}
	return &FileStore{root: root}, nil
}

func (s *FileStore) Create(ctx context.Context, service Service) (Service, error) {
	if err := ctx.Err(); err != nil {
		return Service{}, err
	}
	if err := validateStoredService(service); err != nil {
		return Service{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.getLocked(service.ID); err == nil {
		return Service{}, fmt.Errorf("%w: %s", ErrAlreadyExists, service.ID)
	} else if !errors.Is(err, ErrNotFound) {
		return Service{}, err
	}
	service.Version = 1
	if err := s.writeVersionLocked(service); err != nil {
		return Service{}, err
	}
	return service, nil
}

func (s *FileStore) Get(ctx context.Context, id ID) (Service, error) {
	if err := ctx.Err(); err != nil {
		return Service{}, err
	}
	if err := validateID(id); err != nil {
		return Service{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getLocked(id)
}

func (s *FileStore) Update(ctx context.Context, service Service) (Service, error) {
	if err := ctx.Err(); err != nil {
		return Service{}, err
	}
	if err := validateStoredService(service); err != nil {
		return Service{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.getLocked(service.ID)
	if err != nil {
		return Service{}, err
	}
	if service.Version != current.Version {
		return Service{}, fmt.Errorf("%w: service %s has version %d, current version is %d", ErrConflict, service.ID, service.Version, current.Version)
	}
	service.Version++
	if err := s.writeVersionLocked(service); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Service{}, fmt.Errorf("%w: service %s version %d already exists", ErrConflict, service.ID, service.Version)
		}
		return Service{}, err
	}
	return service, nil
}

func (s *FileStore) List(ctx context.Context, states ...State) ([]Service, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	wanted := make(map[State]struct{}, len(states))
	for _, state := range states {
		if !state.valid() {
			return nil, fmt.Errorf("%w: unknown state %q", ErrInvalidService, state)
		}
		wanted[state] = struct{}{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("read durable service store: %w", err)
	}
	ids := make(map[ID]struct{})
	for _, entry := range entries {
		id, _, ok := parseVersionName(entry.Name())
		if ok {
			ids[id] = struct{}{}
		}
	}
	services := make([]Service, 0, len(ids))
	for id := range ids {
		service, err := s.getLocked(id)
		if err != nil {
			return nil, err
		}
		if len(wanted) > 0 {
			if _, exists := wanted[service.State]; !exists {
				continue
			}
		}
		services = append(services, service)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].ID < services[j].ID })
	return services, nil
}

func (s *FileStore) getLocked(id ID) (Service, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return Service{}, fmt.Errorf("read durable service store: %w", err)
	}
	var latest uint64
	var path string
	for _, entry := range entries {
		entryID, version, ok := parseVersionName(entry.Name())
		if ok && entryID == id && version > latest {
			latest = version
			path = filepath.Join(s.root, entry.Name())
		}
	}
	if path == "" {
		return Service{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Service{}, fmt.Errorf("read durable service %s: %w", id, err)
	}
	var service Service
	if err := json.Unmarshal(data, &service); err != nil {
		return Service{}, fmt.Errorf("decode durable service %s: %w", id, err)
	}
	if service.ID != id || service.Version != latest {
		return Service{}, fmt.Errorf("%w: record identity mismatch", ErrInvalidService)
	}
	return service, nil
}

func (s *FileStore) writeVersionLocked(service Service) error {
	data, err := json.MarshalIndent(service, "", "  ")
	if err != nil {
		return fmt.Errorf("encode durable service %s: %w", service.ID, err)
	}
	path := filepath.Join(s.root, versionName(service.ID, service.Version))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create durable service %s version %d: %w", service.ID, service.Version, err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write durable service %s: %w", service.ID, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync durable service %s: %w", service.ID, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close durable service %s: %w", service.ID, err)
	}
	remove = false
	return nil
}

func validateStoredService(service Service) error {
	if err := validateID(service.ID); err != nil {
		return err
	}
	if strings.TrimSpace(string(service.ComputerID)) == "" || !service.State.valid() {
		return ErrInvalidService
	}
	return validateSpec(service.Spec)
}

func validateSpec(spec Spec) error {
	if strings.TrimSpace(spec.Command) == "" {
		return ErrInvalidService
	}
	names := make(map[string]struct{}, len(spec.Ports))
	claims := make(map[string]struct{}, len(spec.Ports))
	for _, port := range spec.Ports {
		name := strings.TrimSpace(port.Name)
		if name == "" || (port.Protocol != ProtocolTCP && port.Protocol != ProtocolUDP) || port.Number < 1 || port.Number > 65535 {
			return ErrInvalidService
		}
		claim := fmt.Sprintf("%s:%d", port.Protocol, port.Number)
		if _, exists := names[name]; exists {
			return ErrInvalidService
		}
		if _, exists := claims[claim]; exists {
			return ErrInvalidService
		}
		names[name] = struct{}{}
		claims[claim] = struct{}{}
	}
	if spec.Readiness != nil {
		probePort := strings.TrimSpace(spec.Readiness.Port)
		if probePort == "" || spec.Readiness.Timeout <= 0 || spec.Readiness.Interval <= 0 ||
			strings.ContainsAny(strings.TrimSpace(spec.Readiness.Host), " /\\") {
			return ErrInvalidService
		}
		found := false
		for _, port := range spec.Ports {
			if strings.TrimSpace(port.Name) == probePort && port.Protocol == ProtocolTCP {
				found = true
				break
			}
		}
		if !found {
			return ErrInvalidService
		}
	}
	return nil
}

func validateID(id ID) error {
	if !validIDPattern.MatchString(string(id)) {
		return fmt.Errorf("%w: invalid id %q", ErrInvalidService, id)
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
	return id, version, err == nil && version > 0
}
