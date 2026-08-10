package computer

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
)

var (
	ErrNotFound          = errors.New("computer not found")
	ErrAlreadyRegistered = errors.New("computer already registered")
)

// Manager owns stable Computer identities. Destroyed computers remain in the
// registry so an identifier cannot silently be rebound to a different backend.
type Manager struct {
	mu        sync.RWMutex
	computers map[ID]Computer
}

func NewManager() *Manager {
	return &Manager{computers: make(map[ID]Computer)}
}

func (m *Manager) Register(machine Computer) error {
	if machine == nil {
		return fmt.Errorf("%w: computer is nil", ErrBackendUnavailable)
	}
	id := machine.ID()
	if id == "" {
		return ErrInvalidID
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.computers[id]; exists {
		return fmt.Errorf("%w: %s", ErrAlreadyRegistered, id)
	}
	m.computers[id] = machine
	return nil
}

func (m *Manager) Get(id ID) (Computer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	machine, exists := m.computers[id]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return machine, nil
}

func (m *Manager) List() []Computer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]ID, 0, len(m.computers))
	for id := range m.computers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	result := make([]Computer, 0, len(ids))
	for _, id := range ids {
		result = append(result, m.computers[id])
	}
	return result
}

func (m *Manager) Destroy(ctx context.Context, id ID) error {
	machine, err := m.Get(id)
	if err != nil {
		return err
	}
	if err := machine.Destroy(ctx); err != nil {
		return fmt.Errorf("destroy computer %s: %w", id, err)
	}
	return nil
}

func (m *Manager) DestroyAll(ctx context.Context) error {
	var errs []error
	for _, machine := range m.List() {
		if err := machine.Destroy(ctx); err != nil {
			errs = append(errs, fmt.Errorf("destroy computer %s: %w", machine.ID(), err))
		}
	}
	return errors.Join(errs...)
}
