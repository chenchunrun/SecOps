package bootstrap

import (
	"context"
	"errors"
	"fmt"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/scheduler"
	"github.com/chenchunrun/SecOps/internal/security"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
	"github.com/chenchunrun/SecOps/internal/workspace"
)

var ErrRuntimeSchedulerRequired = errors.New("runtime scheduler is required")

// ScheduledSubmission declares task requirements without exposing a Computer
// ID or backend preference to the caller.
type ScheduledSubmission struct {
	ID            taskruntime.ID
	WorkspaceID   workspace.ID
	Request       computer.ExecRequest
	Capabilities  []string
	Scope         scheduler.Scope
	Authorization scheduler.Authorization
	Risk          *security.RiskAssessment
}

// ScheduledTaskRuntime composes deterministic scheduling with durable task
// persistence and execution.
type ScheduledTaskRuntime struct {
	runtime   *ComputerRuntime
	scheduler *scheduler.Scheduler
}

// NewScheduledTaskRuntime creates the backend-neutral durable execution entry
// point.
func NewScheduledTaskRuntime(
	runtime *ComputerRuntime,
	runtimeScheduler *scheduler.Scheduler,
) (*ScheduledTaskRuntime, error) {
	if runtimeScheduler == nil {
		return nil, ErrRuntimeSchedulerRequired
	}
	if runtime == nil || runtime.Computers == nil || runtime.Tasks == nil {
		return nil, ErrComputerRuntimeRequired
	}
	return &ScheduledTaskRuntime{runtime: runtime, scheduler: runtimeScheduler}, nil
}

// Submit schedules the request and persists the selected stable Computer ID in
// a pending durable task before any command can execute.
func (r *ScheduledTaskRuntime) Submit(
	ctx context.Context,
	submission ScheduledSubmission,
) (taskruntime.Task, scheduler.Decision, error) {
	decision, err := r.scheduler.Schedule(ctx, scheduler.Request{
		RequestID:     string(submission.ID),
		Capabilities:  submission.Capabilities,
		Scope:         submission.Scope,
		Authorization: submission.Authorization,
		Risk:          submission.Risk,
	})
	if err != nil {
		return taskruntime.Task{}, decision, fmt.Errorf("schedule durable task: %w", err)
	}

	task, err := r.runtime.Tasks.Submit(ctx, taskruntime.Submission{
		ID:          submission.ID,
		ComputerID:  decision.ComputerID,
		WorkspaceID: submission.WorkspaceID,
		Request:     submission.Request,
	})
	if err != nil {
		return taskruntime.Task{}, decision, fmt.Errorf("persist scheduled durable task: %w", err)
	}
	return task, decision, nil
}

// SubmitAndRun persists the assignment and then executes it through the
// Computer Manager resolver.
func (r *ScheduledTaskRuntime) SubmitAndRun(
	ctx context.Context,
	submission ScheduledSubmission,
) (taskruntime.Task, scheduler.Decision, error) {
	task, decision, err := r.Submit(ctx, submission)
	if err != nil {
		return task, decision, err
	}
	task, err = r.runtime.Tasks.RunAssigned(ctx, task.ID, r.runtime.Computers)
	if err != nil {
		return task, decision, fmt.Errorf("run scheduled durable task: %w", err)
	}
	return task, decision, nil
}
