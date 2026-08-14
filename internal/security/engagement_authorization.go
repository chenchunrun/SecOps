package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrEngagementAuthorizationDenied = errors.New("engagement authorization denied")

var (
	globalEngagementAuthorizationMu    sync.RWMutex
	globalEngagementAuthorizationStore EngagementAuthorizationStore = NewInMemoryEngagementAuthorizationStore()
)

// EngagementAuthorization is a time-bound, target-scoped grant for active security work.
type EngagementAuthorization struct {
	ID           string    `json:"id"`
	Capability   string    `json:"capability"`
	Targets      []string  `json:"targets"`
	Restrictions []string  `json:"restrictions,omitempty"`
	AuthorizedBy string    `json:"authorized_by"`
	NotBefore    time.Time `json:"not_before"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Validate checks capability, time window, and exact target scope.
func (a EngagementAuthorization) Validate(capability, target string, now time.Time) error {
	if strings.TrimSpace(a.ID) == "" || strings.TrimSpace(a.AuthorizedBy) == "" {
		return fmt.Errorf("%w: incomplete authorization", ErrEngagementAuthorizationDenied)
	}
	if a.Capability != capability {
		return fmt.Errorf("%w: capability mismatch", ErrEngagementAuthorizationDenied)
	}
	if a.NotBefore.IsZero() || a.ExpiresAt.IsZero() || now.Before(a.NotBefore) || !now.Before(a.ExpiresAt) {
		return fmt.Errorf("%w: authorization is outside its validity window", ErrEngagementAuthorizationDenied)
	}
	for _, allowed := range a.Targets {
		if targetInEngagementScope(target, allowed) {
			return nil
		}
	}
	return fmt.Errorf("%w: target is outside authorized scope", ErrEngagementAuthorizationDenied)
}

type EngagementAuthorizationStore interface {
	Put(EngagementAuthorization) error
	Get(string) (EngagementAuthorization, error)
}

func SetGlobalEngagementAuthorizationStore(store EngagementAuthorizationStore) {
	globalEngagementAuthorizationMu.Lock()
	defer globalEngagementAuthorizationMu.Unlock()
	if store == nil {
		store = NewInMemoryEngagementAuthorizationStore()
	}
	globalEngagementAuthorizationStore = store
}

func ValidateGlobalEngagementAuthorization(id, capability, target string, now time.Time) error {
	globalEngagementAuthorizationMu.RLock()
	store := globalEngagementAuthorizationStore
	globalEngagementAuthorizationMu.RUnlock()
	auth, err := store.Get(id)
	if err != nil {
		return err
	}
	return auth.Validate(capability, target, now)
}

type InMemoryEngagementAuthorizationStore struct {
	mu    sync.RWMutex
	items map[string]EngagementAuthorization
}

func NewInMemoryEngagementAuthorizationStore() *InMemoryEngagementAuthorizationStore {
	return &InMemoryEngagementAuthorizationStore{items: make(map[string]EngagementAuthorization)}
}

func (s *InMemoryEngagementAuthorizationStore) Put(auth EngagementAuthorization) error {
	if strings.TrimSpace(auth.ID) == "" {
		return fmt.Errorf("authorization id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[auth.ID] = auth
	return nil
}

func (s *InMemoryEngagementAuthorizationStore) Get(id string) (EngagementAuthorization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	auth, ok := s.items[id]
	if !ok {
		return EngagementAuthorization{}, fmt.Errorf("%w: unknown authorization id", ErrEngagementAuthorizationDenied)
	}
	return auth, nil
}

type FileEngagementAuthorizationStore struct {
	mu    sync.RWMutex
	path  string
	items map[string]EngagementAuthorization
}

func NewFileEngagementAuthorizationStore(path string) (*FileEngagementAuthorizationStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("authorization store path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create authorization directory: %w", err)
	}
	s := &FileEngagementAuthorizationStore{path: path, items: make(map[string]EngagementAuthorization)}
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read authorization store: %w", err)
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &s.items); err != nil {
			return nil, fmt.Errorf("decode authorization store: %w", err)
		}
	}
	return s, nil
}

func (s *FileEngagementAuthorizationStore) Put(auth EngagementAuthorization) error {
	if strings.TrimSpace(auth.ID) == "" {
		return fmt.Errorf("authorization id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[auth.ID] = auth
	b, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return fmt.Errorf("encode authorization store: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write authorization store: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("commit authorization store: %w", err)
	}
	return nil
}

func (s *FileEngagementAuthorizationStore) Get(id string) (EngagementAuthorization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	auth, ok := s.items[id]
	if !ok {
		return EngagementAuthorization{}, fmt.Errorf("%w: unknown authorization id", ErrEngagementAuthorizationDenied)
	}
	return auth, nil
}

func targetInEngagementScope(target, allowed string) bool {
	target = normalizeEngagementTarget(target)
	allowed = normalizeEngagementTarget(allowed)
	if target == "" || allowed == "" {
		return false
	}
	if prefix, err := netip.ParsePrefix(allowed); err == nil {
		addr, err := netip.ParseAddr(target)
		return err == nil && prefix.Contains(addr)
	}
	if strings.HasPrefix(allowed, "*.") {
		suffix := strings.TrimPrefix(allowed, "*")
		return strings.HasSuffix(target, suffix) && target != strings.TrimPrefix(suffix, ".")
	}
	return target == allowed
}

func normalizeEngagementTarget(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	}
	if at := strings.LastIndex(value, "@"); at >= 0 {
		value = value[at+1:]
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return strings.Trim(value, "[]")
}
