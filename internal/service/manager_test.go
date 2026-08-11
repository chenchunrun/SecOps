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

type fakeLauncher struct {
	mu        sync.Mutex
	processes []*fakeProcess
}

func (l *fakeLauncher) Start(context.Context, computer.Computer, Spec) (Process, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	process := newFakeProcess(1000 + len(l.processes))
	l.processes = append(l.processes, process)
	return process, nil
}

func (l *fakeLauncher) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.processes)
}

type fakeProcess struct {
	pid      int
	done     chan struct{}
	mu       sync.Mutex
	err      error
	stopOnce sync.Once
}

func newFakeProcess(pid int) *fakeProcess {
	return &fakeProcess{pid: pid, done: make(chan struct{})}
}

func (p *fakeProcess) PID() int       { return p.pid }
func (p *fakeProcess) Logs() LogPaths { return LogPaths{} }
func (p *fakeProcess) Wait() error {
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *fakeProcess) Stop(context.Context) error {
	p.complete(nil)
	return nil
}

func (p *fakeProcess) complete(err error) {
	p.stopOnce.Do(func() {
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		close(p.done)
	})
}

func TestManagerOwnsServiceLifecycleAndPortClaims(t *testing.T) {
	t.Parallel()

	manager, launcher := newTestManager(t)
	service, err := manager.Start(context.Background(), Submission{
		ID:         "api-service",
		ComputerID: "local-test",
		Spec: Spec{
			Command: "serve-api",
			Ports:   []Port{{Name: "http", Protocol: ProtocolTCP, Number: 8080}},
		},
	})
	require.NoError(t, err)
	require.Equal(t, StateRunning, service.State)
	require.Equal(t, 1000, service.ProcessID)

	_, err = manager.Start(context.Background(), Submission{
		ID:         "conflicting-service",
		ComputerID: "local-test",
		Spec: Spec{
			Command: "serve-other",
			Ports:   []Port{{Name: "http", Protocol: ProtocolTCP, Number: 8080}},
		},
	})
	require.ErrorIs(t, err, ErrPortConflict)
	require.Equal(t, 1, launcher.count())

	stopped, err := manager.Stop(context.Background(), service.ID)
	require.NoError(t, err)
	require.Equal(t, StateStopped, stopped.State)
	stoppedAgain, err := manager.Stop(context.Background(), service.ID)
	require.NoError(t, err)
	require.Equal(t, StateStopped, stoppedAgain.State)

	replacement, err := manager.Start(context.Background(), Submission{
		ID:         "replacement-service",
		ComputerID: "local-test",
		Spec: Spec{
			Command: "serve-replacement",
			Ports:   []Port{{Name: "http", Protocol: ProtocolTCP, Number: 8080}},
		},
	})
	require.NoError(t, err)
	destroyed, err := manager.Destroy(context.Background(), replacement.ID)
	require.NoError(t, err)
	require.Equal(t, StateDestroyed, destroyed.State)
	destroyedAgain, err := manager.Destroy(context.Background(), replacement.ID)
	require.NoError(t, err)
	require.Equal(t, StateDestroyed, destroyedAgain.State)
}

func TestManagerPersistsUnexpectedProcessFailure(t *testing.T) {
	t.Parallel()

	manager, launcher := newTestManager(t)
	service, err := manager.Start(context.Background(), Submission{
		ID:         "failing-service",
		ComputerID: "local-test",
		Spec:       Spec{Command: "fail-later"},
	})
	require.NoError(t, err)
	process := launcher.processes[0]
	process.complete(errors.New("process crashed"))

	require.Eventually(t, func() bool {
		persisted, getErr := manager.Get(context.Background(), service.ID)
		return getErr == nil && persisted.State == StateFailed && persisted.Error == "process crashed"
	}, time.Second, 10*time.Millisecond)
}

func TestManagerRecoveryInterruptsServicesAndRetainsPortClaims(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	running, err := store.Create(context.Background(), Service{
		ID:         "service-at-crash",
		ComputerID: "local-test",
		State:      StateRunning,
		Spec: Spec{
			Command: "non-idempotent-server",
			Ports:   []Port{{Name: "http", Protocol: ProtocolTCP, Number: 9090}},
		},
	})
	require.NoError(t, err)
	computers := newTestComputers(t)
	manager, err := NewManager(store, computers, &fakeLauncher{})
	require.NoError(t, err)

	recovered, err := manager.Recover(context.Background())
	require.NoError(t, err)
	require.Len(t, recovered, 1)
	require.Equal(t, running.ID, recovered[0].ID)
	require.Equal(t, StateInterrupted, recovered[0].State)

	_, err = manager.Start(context.Background(), Submission{
		ID:         "unsafe-port-reuse",
		ComputerID: "local-test",
		Spec: Spec{
			Command: "serve",
			Ports:   []Port{{Name: "http", Protocol: ProtocolTCP, Number: 9090}},
		},
	})
	require.ErrorIs(t, err, ErrPortConflict)

	destroyed, err := manager.Destroy(context.Background(), running.ID)
	require.NoError(t, err)
	require.Equal(t, StateDestroyed, destroyed.State)
}

func newTestManager(t *testing.T) (*Manager, *fakeLauncher) {
	t.Helper()
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	launcher := &fakeLauncher{}
	manager, err := NewManager(store, newTestComputers(t), launcher)
	require.NoError(t, err)
	return manager, launcher
}

func newTestComputers(t *testing.T) *computer.Manager {
	t.Helper()
	computers := computer.NewManager()
	machine, err := computer.NewLocalComputer("local-test")
	require.NoError(t, err)
	require.NoError(t, computers.Register(machine))
	return computers
}
