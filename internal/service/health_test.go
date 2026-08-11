package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
)

type sequenceHealthVerifier struct {
	mu      sync.Mutex
	results []error
	calls   int
}

func (v *sequenceHealthVerifier) CheckHealth(context.Context, computer.Computer, Service) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	index := v.calls
	v.calls++
	if index >= len(v.results) {
		return nil
	}
	return v.results[index]
}

func (v *sequenceHealthVerifier) callCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

func TestManagerStopsServiceAfterConsecutiveHealthFailures(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	launcher := &fakeLauncher{}
	unhealthy := errors.New("endpoint unhealthy")
	verifier := &sequenceHealthVerifier{results: []error{unhealthy, unhealthy}}
	manager, err := NewManager(
		store,
		newTestComputers(t),
		launcher,
		WithHealthVerifier(verifier),
	)
	require.NoError(t, err)
	service, err := manager.Start(context.Background(), healthSubmission("unhealthy-service", 2))
	require.NoError(t, err)
	require.Equal(t, StateRunning, service.State)

	require.Eventually(t, func() bool {
		persisted, getErr := manager.Get(context.Background(), service.ID)
		return getErr == nil && persisted.State == StateFailed
	}, time.Second, 10*time.Millisecond)
	persisted, err := manager.Get(context.Background(), service.ID)
	require.NoError(t, err)
	require.Contains(t, persisted.Error, unhealthy.Error())
	require.GreaterOrEqual(t, verifier.callCount(), 2)
	require.NoError(t, launcher.processes[0].Wait())
}

func TestManagerResetsConsecutiveHealthFailuresAfterSuccess(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	launcher := &fakeLauncher{}
	unhealthy := errors.New("transient failure")
	verifier := &sequenceHealthVerifier{results: []error{unhealthy, nil, unhealthy, nil}}
	manager, err := NewManager(
		store,
		newTestComputers(t),
		launcher,
		WithHealthVerifier(verifier),
	)
	require.NoError(t, err)
	service, err := manager.Start(context.Background(), healthSubmission("recovering-service", 2))
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return verifier.callCount() >= 4
	}, time.Second, 10*time.Millisecond)
	persisted, err := manager.Get(context.Background(), service.ID)
	require.NoError(t, err)
	require.Equal(t, StateRunning, persisted.State)
	_, err = manager.Stop(context.Background(), service.ID)
	require.NoError(t, err)
}

func TestServiceRejectsInvalidHealthCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*HealthCheck)
	}{
		{name: "undeclared port", mutate: func(check *HealthCheck) { check.Probe.Port = "admin" }},
		{name: "zero period", mutate: func(check *HealthCheck) { check.Period = 0 }},
		{name: "zero threshold", mutate: func(check *HealthCheck) { check.FailureThreshold = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			submission := healthSubmission(ID("invalid-"+tt.name), 2)
			tt.mutate(submission.Spec.Health)
			store, err := NewFileStore(t.TempDir())
			require.NoError(t, err)
			_, err = store.Create(context.Background(), Service{
				ID:         submission.ID,
				ComputerID: submission.ComputerID,
				State:      StateProvisioning,
				Spec:       submission.Spec,
			})
			require.ErrorIs(t, err, ErrInvalidService)
		})
	}
}

func healthSubmission(id ID, threshold int) Submission {
	return Submission{
		ID:         id,
		ComputerID: "local-test",
		Spec: Spec{
			Command: "serve",
			Ports:   []Port{{Name: "http", Protocol: ProtocolTCP, Number: 8082}},
			Health: &HealthCheck{
				Probe: ReadinessProbe{
					Port:     "http",
					Timeout:  10 * time.Millisecond,
					Interval: time.Millisecond,
				},
				Period:           5 * time.Millisecond,
				FailureThreshold: threshold,
			},
		},
	}
}
