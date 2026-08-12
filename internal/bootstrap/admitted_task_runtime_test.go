package bootstrap

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/admission"
	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/scheduler"
	"github.com/chenchunrun/SecOps/internal/security"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
)

type admittedComputer struct {
	id     computer.ID
	result *computer.ExecutionResult
	err    error
	calls  int
	onExec func()
}

func (c *admittedComputer) ID() computer.ID           { return c.id }
func (c *admittedComputer) Backend() computer.Backend { return computer.BackendLocal }
func (c *admittedComputer) State() computer.State     { return computer.StateActive }
func (c *admittedComputer) Exec(_ context.Context, _ computer.ExecRequest) (*computer.ExecutionResult, error) {
	c.calls++
	if c.onExec != nil {
		c.onExec()
	}
	return c.result, c.err
}
func (c *admittedComputer) Suspend(context.Context) error { return nil }
func (c *admittedComputer) Resume(context.Context) error  { return nil }
func (c *admittedComputer) Destroy(context.Context) error { return nil }

type admittedResolver struct{ machine *admittedComputer }

func (r admittedResolver) Get(id computer.ID) (computer.Computer, error) {
	if r.machine == nil || r.machine.id != id {
		return nil, computer.ErrNotFound
	}
	return r.machine, nil
}

func TestComputerRuntimeRejectsTaskBeforeExecutionWhenCapacityIsFull(t *testing.T) {
	t.Parallel()

	runtime, err := newComputerRuntime(context.Background(), t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, runtime.Admission)
	capacity := defaultAdmissionCapacity()
	blocking, err := runtime.Admission.Acquire(context.Background(), admission.Request{
		LeaseID:    "lease-blocking",
		TaskID:     "task-blocking",
		ComputerID: DefaultLocalComputerID,
		Demand:     capacity,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = runtime.Admission.Release(context.Background(), blocking.ID) })
	task, err := runtime.Tasks.Submit(context.Background(), taskruntime.Submission{
		ID:             "task-capacity-blocked",
		ComputerID:     DefaultLocalComputerID,
		Request:        computer.ExecRequest{Command: "run"},
		ResourceDemand: admission.Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	})
	require.NoError(t, err)
	machine := &admittedComputer{id: DefaultLocalComputerID, result: &computer.ExecutionResult{ExitCode: 0}}

	unchanged, err := runtime.RunTaskAdmitted(context.Background(), task.ID, admittedResolver{machine: machine})
	require.ErrorIs(t, err, admission.ErrCapacityExceeded)
	require.Equal(t, taskruntime.StatePending, unchanged.State)
	require.Zero(t, machine.calls)
}

func TestComputerRuntimeReleasesLeaseAfterExecutionFailure(t *testing.T) {
	t.Parallel()

	runtime, err := newComputerRuntime(context.Background(), t.TempDir())
	require.NoError(t, err)
	demand := admission.Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256}
	task, err := runtime.Tasks.Submit(context.Background(), taskruntime.Submission{
		ID:             "task-admitted-failure",
		ComputerID:     DefaultLocalComputerID,
		Request:        computer.ExecRequest{Command: "fail"},
		ResourceDemand: demand,
	})
	require.NoError(t, err)
	executionErr := errors.New("backend failed")
	machine := &admittedComputer{id: DefaultLocalComputerID, err: executionErr}

	failed, err := runtime.RunTaskAdmitted(context.Background(), task.ID, admittedResolver{machine: machine})
	require.ErrorIs(t, err, executionErr)
	require.Equal(t, taskruntime.StateFailed, failed.State)
	require.Equal(t, 1, machine.calls)
	lease, err := runtime.Admission.Acquire(context.Background(), admission.Request{
		LeaseID:    "lease-after-failure",
		TaskID:     "task-after-failure",
		ComputerID: DefaultLocalComputerID,
		Demand:     defaultAdmissionCapacity(),
	})
	require.NoError(t, err)
	_, err = runtime.Admission.Release(context.Background(), lease.ID)
	require.NoError(t, err)
}

func TestComputerRuntimePersistsAdmissionLeaseLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	runtime, err := newComputerRuntime(ctx, t.TempDir())
	require.NoError(t, err)
	task, err := runtime.Tasks.Submit(ctx, taskruntime.Submission{
		ID:             "task-admission-lifecycle",
		ComputerID:     DefaultLocalComputerID,
		Request:        computer.ExecRequest{Command: "run"},
		ResourceDemand: admission.Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	})
	require.NoError(t, err)
	machine := &admittedComputer{
		id:     DefaultLocalComputerID,
		result: &computer.ExecutionResult{ExitCode: 0},
		onExec: func() {
			running, getErr := runtime.Tasks.Get(ctx, task.ID)
			require.NoError(t, getErr)
			require.Equal(t, taskruntime.StateRunning, running.State)
			require.NotEmpty(t, running.AdmissionLeaseID)
			require.Zero(t, running.AdmissionReleasedAt)
		},
	}

	completed, err := runtime.RunTaskAdmitted(ctx, task.ID, admittedResolver{machine: machine})
	require.NoError(t, err)
	require.Equal(t, taskruntime.StateSucceeded, completed.State)
	require.NotEmpty(t, completed.AdmissionLeaseID)
	require.NotZero(t, completed.AdmissionReleasedAt)
	lease, err := runtime.AdmissionStore.Get(ctx, completed.AdmissionLeaseID)
	require.NoError(t, err)
	require.Equal(t, admission.StateReleased, lease.State)
}

func TestRuntimeSchedulerExcludesComputerWithoutAdmissionCapacity(t *testing.T) {
	t.Parallel()

	runtime, err := newComputerRuntime(context.Background(), t.TempDir())
	require.NoError(t, err)
	lease, err := runtime.Admission.Acquire(context.Background(), admission.Request{
		LeaseID:    "lease-scheduler-full",
		TaskID:     "task-scheduler-full",
		ComputerID: DefaultLocalComputerID,
		Demand:     defaultAdmissionCapacity(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = runtime.Admission.Release(context.Background(), lease.ID) })
	runtimeScheduler, err := NewRuntimeScheduler(runtime, filepath.Join(t.TempDir(), "scheduler.jsonl"))
	require.NoError(t, err)
	scheduled, err := NewScheduledTaskRuntime(runtime, runtimeScheduler)
	require.NoError(t, err)

	task, decision, err := scheduled.Submit(context.Background(), ScheduledSubmission{
		ID:             "task-scheduler-capacity",
		Request:        computer.ExecRequest{Command: "run"},
		Capabilities:   []string{security.CapabilityShellReadOnly},
		Scope:          scheduler.ScopeWorkspace,
		Authorization:  scheduler.Authorization{Decision: permission.DecisionAutoApprove, Approved: true},
		Risk:           lowSchedulerRisk(),
		ResourceDemand: admission.Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	})
	require.ErrorIs(t, err, scheduler.ErrNoCandidate)
	require.Equal(t, scheduler.OutcomeNoCandidate, decision.Outcome)
	require.Empty(t, task.ID)
}
