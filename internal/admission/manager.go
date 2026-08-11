package admission

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
)

type Manager struct {
	store       Store
	profiles    map[computer.ID]Profile
	coordinator coordinatedStore
	mu          sync.Mutex
}

type coordinatedStore interface {
	Coordinate(ctx context.Context, action func() error) error
}

func (m *Manager) CanAcquire(ctx context.Context, computerID computer.ID, demand Resources) (bool, error) {
	if !idPattern.MatchString(string(computerID)) || !validResources(demand) {
		return false, ErrInvalidRequest
	}
	available := false
	err := m.coordinate(ctx, func() error {
		profile, configured := m.profiles[computerID]
		if !configured {
			return fmt.Errorf("%w: %s", ErrUnknownComputer, computerID)
		}
		active, err := m.store.List(ctx, StateActive)
		if err != nil {
			return fmt.Errorf("list active admission leases: %w", err)
		}
		used := Resources{}
		for _, lease := range active {
			if lease.ComputerID == computerID {
				used.Slots += lease.Demand.Slots
				used.CPUUnits += lease.Demand.CPUUnits
				used.MemoryMB += lease.Demand.MemoryMB
			}
		}
		available = fits(used, demand, profile.Capacity)
		return nil
	})
	return available, err
}

func (m *Manager) RegisterProfile(profile Profile) error {
	if !idPattern.MatchString(string(profile.ComputerID)) || !validResources(profile.Capacity) {
		return fmt.Errorf("%w: invalid capacity profile", ErrInvalidRequest)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, exists := m.profiles[profile.ComputerID]; exists {
		if current.Capacity != profile.Capacity {
			return fmt.Errorf("%w: computer profile %q already has different capacity", ErrLeaseConflict, profile.ComputerID)
		}
		return nil
	}
	m.profiles[profile.ComputerID] = profile
	return nil
}

func NewManager(store Store, profiles []Profile) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidRequest)
	}
	indexed := make(map[computer.ID]Profile, len(profiles))
	for _, profile := range profiles {
		if !idPattern.MatchString(string(profile.ComputerID)) || !validResources(profile.Capacity) {
			return nil, fmt.Errorf("%w: invalid capacity profile", ErrInvalidRequest)
		}
		if _, exists := indexed[profile.ComputerID]; exists {
			return nil, fmt.Errorf("%w: duplicate computer profile %q", ErrInvalidRequest, profile.ComputerID)
		}
		indexed[profile.ComputerID] = profile
	}
	manager := &Manager{store: store, profiles: indexed}
	manager.coordinator, _ = store.(coordinatedStore)
	return manager, nil
}

func (m *Manager) Acquire(ctx context.Context, request Request) (Lease, error) {
	if err := validateRequest(request); err != nil {
		return Lease{}, err
	}
	acquired := Lease{}
	err := m.coordinate(ctx, func() error {
		profile, configured := m.profiles[request.ComputerID]
		if !configured {
			return fmt.Errorf("%w: %s", ErrUnknownComputer, request.ComputerID)
		}
		if !fits(Resources{}, request.Demand, profile.Capacity) {
			return ErrCapacityExceeded
		}
		existing, err := m.store.Get(ctx, request.LeaseID)
		if err == nil {
			if existing.TaskID != request.TaskID || existing.ComputerID != request.ComputerID || existing.Demand != request.Demand {
				return ErrLeaseConflict
			}
			if existing.State == StateReleased {
				return ErrLeaseReleased
			}
			acquired = existing
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("load admission lease: %w", err)
		}

		active, err := m.store.List(ctx, StateActive)
		if err != nil {
			return fmt.Errorf("list active admission leases: %w", err)
		}
		used := Resources{}
		for _, lease := range active {
			if lease.ComputerID == request.ComputerID {
				used.Slots += lease.Demand.Slots
				used.CPUUnits += lease.Demand.CPUUnits
				used.MemoryMB += lease.Demand.MemoryMB
			}
		}
		if !fits(used, request.Demand, profile.Capacity) {
			return ErrCapacityExceeded
		}
		now := time.Now().UTC()
		lease := Lease{
			ID:         request.LeaseID,
			TaskID:     request.TaskID,
			ComputerID: request.ComputerID,
			Demand:     request.Demand,
			State:      StateActive,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		acquired, err = m.store.Create(ctx, lease)
		if err != nil {
			return fmt.Errorf("persist admission lease: %w", err)
		}
		return nil
	})
	return acquired, err
}

func (m *Manager) Release(ctx context.Context, id ID) (Lease, error) {
	released := Lease{}
	err := m.coordinate(ctx, func() error {
		lease, err := m.store.Get(ctx, id)
		if err != nil {
			return fmt.Errorf("load admission lease for release: %w", err)
		}
		if lease.State == StateReleased {
			released = lease
			return nil
		}
		now := time.Now().UTC()
		lease.State = StateReleased
		lease.UpdatedAt = now
		lease.ReleasedAt = now
		released, err = m.store.Update(ctx, lease)
		if err != nil {
			return fmt.Errorf("persist released admission lease: %w", err)
		}
		return nil
	})
	return released, err
}

func (m *Manager) Reconcile(ctx context.Context, activeTaskIDs map[ID]struct{}) ([]Lease, error) {
	released := make([]Lease, 0)
	err := m.coordinate(ctx, func() error {
		active, err := m.store.List(ctx, StateActive)
		if err != nil {
			return fmt.Errorf("list admission leases for reconciliation: %w", err)
		}
		for _, lease := range active {
			if _, keep := activeTaskIDs[lease.TaskID]; keep {
				continue
			}
			now := time.Now().UTC()
			lease.State = StateReleased
			lease.UpdatedAt = now
			lease.ReleasedAt = now
			lease, err = m.store.Update(ctx, lease)
			if err != nil {
				return fmt.Errorf("reconcile admission lease %s: %w", lease.ID, err)
			}
			released = append(released, lease)
		}
		return nil
	})
	return released, err
}

func (m *Manager) coordinate(ctx context.Context, action func() error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.coordinator != nil {
		return m.coordinator.Coordinate(ctx, action)
	}
	return action()
}

func validateRequest(request Request) error {
	if !idPattern.MatchString(string(request.LeaseID)) || !idPattern.MatchString(string(request.TaskID)) ||
		!idPattern.MatchString(string(request.ComputerID)) || !validResources(request.Demand) {
		return ErrInvalidRequest
	}
	return nil
}

func validResources(resources Resources) bool {
	return resources.Slots > 0 && resources.CPUUnits > 0 && resources.MemoryMB > 0
}

func fits(used, demand, capacity Resources) bool {
	if used.Slots > capacity.Slots || used.CPUUnits > capacity.CPUUnits || used.MemoryMB > capacity.MemoryMB {
		return false
	}
	return demand.Slots <= capacity.Slots-used.Slots &&
		demand.CPUUnits <= capacity.CPUUnits-used.CPUUnits &&
		demand.MemoryMB <= capacity.MemoryMB-used.MemoryMB
}
