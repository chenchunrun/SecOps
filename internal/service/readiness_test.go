package service

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
)

func TestTCPReadinessVerifierWaitsForDeclaredPort(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	port := listener.Addr().(*net.TCPAddr).Port
	verifier := NewTCPReadinessVerifier()

	err = verifier.WaitReady(context.Background(), nil, Service{Spec: Spec{
		Command: "serve",
		Ports:   []Port{{Name: "http", Protocol: ProtocolTCP, Number: port}},
		Readiness: &ReadinessProbe{
			Port:     "http",
			Host:     "127.0.0.1",
			Timeout:  time.Second,
			Interval: 10 * time.Millisecond,
		},
	}})
	require.NoError(t, err)
}

func TestTCPReadinessVerifierFailsClosedOnTimeout(t *testing.T) {
	t.Parallel()

	const port = 65000
	const host = "192.0.2.1"
	verifier := NewTCPReadinessVerifier()

	err := verifier.WaitReady(context.Background(), nil, Service{Spec: Spec{
		Command: "serve",
		Ports:   []Port{{Name: "http", Protocol: ProtocolTCP, Number: port}},
		Readiness: &ReadinessProbe{
			Port:     "http",
			Host:     host,
			Timeout:  50 * time.Millisecond,
			Interval: 5 * time.Millisecond,
		},
	}})
	require.ErrorIs(t, err, ErrReadinessFailed)
	require.Contains(t, err.Error(), net.JoinHostPort(host, strconv.Itoa(port)))
}

type failingReadinessVerifier struct {
	store Store
	err   error
	saw   Service
}

func (v *failingReadinessVerifier) WaitReady(ctx context.Context, _ computer.Computer, service Service) error {
	persisted, err := v.store.Get(ctx, service.ID)
	if err != nil {
		return err
	}
	v.saw = persisted
	return v.err
}

func TestManagerFailsAndStopsProcessWhenReadinessFails(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	launcher := &fakeLauncher{}
	readinessFailure := errors.New("service never became ready")
	verifier := &failingReadinessVerifier{store: store, err: readinessFailure}
	manager, err := NewManager(
		store,
		newTestComputers(t),
		launcher,
		WithReadinessVerifier(verifier),
	)
	require.NoError(t, err)

	service, err := manager.Start(context.Background(), Submission{
		ID:         "unready-service",
		ComputerID: "local-test",
		Spec: Spec{
			Command: "serve",
			Ports:   []Port{{Name: "http", Protocol: ProtocolTCP, Number: 8081}},
			Readiness: &ReadinessProbe{
				Port:     "http",
				Timeout:  time.Second,
				Interval: time.Millisecond,
			},
		},
	})
	require.ErrorIs(t, err, readinessFailure)
	require.Equal(t, StateFailed, service.State)
	require.Equal(t, StateStarting, verifier.saw.State)
	require.Positive(t, verifier.saw.ProcessID)
	require.Equal(t, 1, launcher.count())
	require.NoError(t, launcher.processes[0].Wait())

	persisted, err := manager.Get(context.Background(), service.ID)
	require.NoError(t, err)
	require.Equal(t, StateFailed, persisted.State)
	require.Equal(t, readinessFailure.Error(), persisted.Error)
}

func TestServiceRejectsReadinessForUndeclaredPort(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	_, err = store.Create(context.Background(), Service{
		ID:         "invalid-readiness",
		ComputerID: "local-test",
		State:      StateProvisioning,
		Spec: Spec{
			Command: "serve",
			Ports:   []Port{{Name: "metrics", Protocol: ProtocolTCP, Number: 9090}},
			Readiness: &ReadinessProbe{
				Port:     "http",
				Timeout:  time.Second,
				Interval: time.Millisecond,
			},
		},
	})
	require.ErrorIs(t, err, ErrInvalidService)
}
