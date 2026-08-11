package bootstrap

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/scheduler"
	"github.com/chenchunrun/SecOps/internal/security"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
	"github.com/chenchunrun/SecOps/internal/workspace"
)

func TestScheduledTaskRuntimePersistsAssignmentBeforeExecution(t *testing.T) {
	t.Parallel()

	computerRuntime, err := newComputerRuntime(context.Background(), t.TempDir())
	require.NoError(t, err)
	runtimeScheduler, err := NewRuntimeScheduler(
		computerRuntime,
		filepath.Join(t.TempDir(), "audit", "scheduler.jsonl"),
	)
	require.NoError(t, err)
	scheduledRuntime, err := NewScheduledTaskRuntime(computerRuntime, runtimeScheduler)
	require.NoError(t, err)

	task, decision, err := scheduledRuntime.Submit(context.Background(), ScheduledSubmission{
		ID:           taskruntime.ID("scheduled-pending"),
		WorkspaceID:  DefaultWorkspaceID,
		Request:      computer.ExecRequest{Command: "echo scheduled"},
		Capabilities: []string{security.CapabilityShellReadOnly},
		Scope:        scheduler.ScopeWorkspace,
		Authorization: scheduler.Authorization{
			Decision: permission.DecisionAutoApprove,
			Approved: true,
		},
		Risk: lowSchedulerRisk(),
	})
	require.NoError(t, err)
	require.Equal(t, scheduler.OutcomeSelected, decision.Outcome)
	require.Equal(t, computer.ID(DefaultLocalComputerID), decision.ComputerID)
	require.Equal(t, taskruntime.StatePending, task.State)
	require.Equal(t, decision.ComputerID, task.ComputerID)
	require.Equal(t, workspace.ID(DefaultWorkspaceID), task.WorkspaceID)

	stored, err := computerRuntime.Tasks.Get(context.Background(), task.ID)
	require.NoError(t, err)
	require.Equal(t, task.ComputerID, stored.ComputerID)
}

func TestScheduledTaskRuntimeSubmitsAndRunsAssignedComputer(t *testing.T) {
	t.Parallel()

	computerRuntime, err := newComputerRuntime(context.Background(), t.TempDir())
	require.NoError(t, err)
	runtimeScheduler, err := NewRuntimeScheduler(
		computerRuntime,
		filepath.Join(t.TempDir(), "audit", "scheduler.jsonl"),
	)
	require.NoError(t, err)
	scheduledRuntime, err := NewScheduledTaskRuntime(computerRuntime, runtimeScheduler)
	require.NoError(t, err)

	task, decision, err := scheduledRuntime.SubmitAndRun(context.Background(), ScheduledSubmission{
		ID:           taskruntime.ID("scheduled-run"),
		WorkspaceID:  DefaultWorkspaceID,
		Request:      computer.ExecRequest{Command: "echo scheduled"},
		Capabilities: []string{security.CapabilityShellReadOnly},
		Scope:        scheduler.ScopeWorkspace,
		Authorization: scheduler.Authorization{
			Decision: permission.DecisionAutoApprove,
			Approved: true,
		},
		Risk: lowSchedulerRisk(),
	})
	require.NoError(t, err)
	require.Equal(t, computer.ID(DefaultLocalComputerID), decision.ComputerID)
	require.Equal(t, taskruntime.StateSucceeded, task.State)
	require.NotNil(t, task.Result)
	require.Contains(t, task.Result.Output, "scheduled")
}

func TestScheduledTaskRuntimeDoesNotPersistRejectedRequest(t *testing.T) {
	t.Parallel()

	computerRuntime, err := newComputerRuntime(context.Background(), t.TempDir())
	require.NoError(t, err)
	runtimeScheduler, err := NewRuntimeScheduler(
		computerRuntime,
		filepath.Join(t.TempDir(), "audit", "scheduler.jsonl"),
	)
	require.NoError(t, err)
	scheduledRuntime, err := NewScheduledTaskRuntime(computerRuntime, runtimeScheduler)
	require.NoError(t, err)

	const taskID taskruntime.ID = "scheduled-denied"
	task, decision, err := scheduledRuntime.Submit(context.Background(), ScheduledSubmission{
		ID:           taskID,
		WorkspaceID:  DefaultWorkspaceID,
		Request:      computer.ExecRequest{Command: "echo denied"},
		Capabilities: []string{security.CapabilityShellReadOnly},
		Scope:        scheduler.ScopeWorkspace,
		Authorization: scheduler.Authorization{
			Decision: permission.DecisionDeny,
		},
		Risk: lowSchedulerRisk(),
	})
	require.ErrorIs(t, err, scheduler.ErrPermissionDenied)
	require.Equal(t, scheduler.OutcomeDenied, decision.Outcome)
	require.Empty(t, task.ID)

	_, err = computerRuntime.Tasks.Get(context.Background(), taskID)
	require.ErrorIs(t, err, taskruntime.ErrNotFound)
}

func TestNewScheduledTaskRuntimeRejectsMissingDependencies(t *testing.T) {
	t.Parallel()

	runtimeScheduler, err := scheduler.New(emptyInventory{}, nil, nil)
	require.NoError(t, err)

	tests := []struct {
		name            string
		computerRuntime *ComputerRuntime
		scheduler       *scheduler.Scheduler
		wantError       error
	}{
		{
			name:      "runtime",
			scheduler: runtimeScheduler,
			wantError: ErrComputerRuntimeRequired,
		},
		{
			name:            "scheduler",
			computerRuntime: &ComputerRuntime{},
			wantError:       ErrRuntimeSchedulerRequired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, createErr := NewScheduledTaskRuntime(tt.computerRuntime, tt.scheduler)
			require.ErrorIs(t, createErr, tt.wantError)
			require.Nil(t, result)
		})
	}
}

type emptyInventory struct{}

func (emptyInventory) List() []computer.Computer { return nil }

func lowSchedulerRisk() *security.RiskAssessment {
	return &security.RiskAssessment{
		Score:  10,
		Level:  security.RiskLevelLow,
		Action: security.RiskActionAutoApprove,
	}
}
