package service

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Manager owns service state, process handles, and logical port claims.
type Manager struct {
	mu        sync.Mutex
	store     Store
	computers ComputerResolver
	launcher  Launcher
	processes map[ID]Process
}

func NewManager(store Store, computers ComputerResolver, launcher Launcher) (*Manager, error) {
	if store == nil || computers == nil || launcher == nil {
		return nil, ErrInvalidService
	}
	return &Manager{
		store:     store,
		computers: computers,
		launcher:  launcher,
		processes: make(map[ID]Process),
	}, nil
}

func (m *Manager) Start(ctx context.Context, submission Submission) (Service, error) {
	if err := ctx.Err(); err != nil {
		return Service{}, err
	}
	service := Service{
		ID:         submission.ID,
		ComputerID: submission.ComputerID,
		State:      StateProvisioning,
		Spec:       submission.Spec,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	if err := validateStoredService(service); err != nil {
		return Service{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensurePortsAvailable(ctx, service); err != nil {
		return Service{}, err
	}
	created, err := m.store.Create(ctx, service)
	if err != nil {
		return Service{}, err
	}
	machine, err := m.computers.Get(service.ComputerID)
	if err != nil {
		return m.fail(ctx, created, err)
	}
	created.State = StateStarting
	created.UpdatedAt = time.Now().UTC()
	created, err = m.store.Update(ctx, created)
	if err != nil {
		return Service{}, err
	}
	process, err := m.launcher.Start(ctx, machine, created.Spec)
	if err != nil {
		return m.fail(ctx, created, err)
	}
	created.State = StateRunning
	created.ProcessID = process.PID()
	created.Logs = process.Logs()
	created.StartedAt = time.Now().UTC()
	created.UpdatedAt = created.StartedAt
	created, err = m.store.Update(ctx, created)
	if err != nil {
		_ = process.Stop(context.Background())
		return Service{}, err
	}
	m.processes[created.ID] = process
	go m.monitor(created.ID, process)
	return created, nil
}

func (m *Manager) Get(ctx context.Context, id ID) (Service, error) {
	return m.store.Get(ctx, id)
}

func (m *Manager) Stop(ctx context.Context, id ID) (Service, error) {
	if err := ctx.Err(); err != nil {
		return Service{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	service, err := m.store.Get(ctx, id)
	if err != nil {
		return Service{}, err
	}
	return m.stopLocked(ctx, service)
}

func (m *Manager) Destroy(ctx context.Context, id ID) (Service, error) {
	if err := ctx.Err(); err != nil {
		return Service{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	service, err := m.store.Get(ctx, id)
	if err != nil {
		return Service{}, err
	}
	if service.State == StateDestroyed {
		return service, nil
	}
	if _, exists := m.processes[id]; exists {
		service, err = m.stopLocked(ctx, service)
		if err != nil {
			return service, err
		}
	}
	service.State = StateDestroyed
	service.UpdatedAt = time.Now().UTC()
	service.FinishedAt = service.UpdatedAt
	service, err = m.store.Update(ctx, service)
	if err != nil {
		return Service{}, err
	}
	return service, nil
}

// Recover marks services that lost their process handle as interrupted. Their
// port claims remain reserved until explicit operator reconciliation.
func (m *Manager) Recover(ctx context.Context) ([]Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	services, err := m.store.List(ctx, StateProvisioning, StateStarting, StateRunning, StateStopping)
	if err != nil {
		return nil, err
	}
	recovered := make([]Service, 0, len(services))
	for _, service := range services {
		service.State = StateInterrupted
		service.Error = "Service process requires backend reconciliation after runtime restart."
		service.UpdatedAt = time.Now().UTC()
		service, err = m.store.Update(ctx, service)
		if err != nil {
			return nil, err
		}
		recovered = append(recovered, service)
	}
	return recovered, nil
}

func (m *Manager) stopLocked(ctx context.Context, service Service) (Service, error) {
	if service.State == StateStopped || service.State == StateDestroyed {
		return service, nil
	}
	process, exists := m.processes[service.ID]
	if !exists {
		return service, nil
	}
	service.State = StateStopping
	service.UpdatedAt = time.Now().UTC()
	updated, err := m.store.Update(ctx, service)
	if err != nil {
		return Service{}, err
	}
	if err := process.Stop(ctx); err != nil {
		return m.fail(ctx, updated, err)
	}
	delete(m.processes, service.ID)
	updated.State = StateStopped
	updated.Error = ""
	updated.UpdatedAt = time.Now().UTC()
	updated.FinishedAt = updated.UpdatedAt
	return m.store.Update(ctx, updated)
}

func (m *Manager) monitor(id ID, process Process) {
	err := process.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.processes[id] != process {
		return
	}
	service, getErr := m.store.Get(context.Background(), id)
	if getErr != nil || service.State != StateRunning {
		return
	}
	delete(m.processes, id)
	service.UpdatedAt = time.Now().UTC()
	service.FinishedAt = service.UpdatedAt
	if err != nil {
		service.State = StateFailed
		service.Error = err.Error()
	} else {
		service.State = StateStopped
		service.Error = ""
	}
	_, _ = m.store.Update(context.Background(), service)
}

func (m *Manager) fail(ctx context.Context, service Service, cause error) (Service, error) {
	service.State = StateFailed
	service.Error = cause.Error()
	service.UpdatedAt = time.Now().UTC()
	service.FinishedAt = service.UpdatedAt
	updated, err := m.store.Update(ctx, service)
	if err != nil {
		return Service{}, err
	}
	return updated, fmt.Errorf("start durable service %s: %w", service.ID, cause)
}

func (m *Manager) ensurePortsAvailable(ctx context.Context, candidate Service) error {
	services, err := m.store.List(ctx)
	if err != nil {
		return err
	}
	claims := make(map[string]ID)
	for _, service := range services {
		if !service.State.claimsPorts() {
			continue
		}
		for _, port := range service.Spec.Ports {
			claims[fmt.Sprintf("%s:%d", port.Protocol, port.Number)] = service.ID
		}
	}
	for _, port := range candidate.Spec.Ports {
		key := fmt.Sprintf("%s:%d", port.Protocol, port.Number)
		if owner, exists := claims[key]; exists {
			return fmt.Errorf("%w: %s is claimed by %s", ErrPortConflict, key, owner)
		}
	}
	return nil
}
