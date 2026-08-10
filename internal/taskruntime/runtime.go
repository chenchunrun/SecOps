package taskruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
)

type Computer interface {
	ID() computer.ID
	Exec(ctx context.Context, request computer.ExecRequest) (*computer.ExecutionResult, error)
}

type Runtime struct {
	store Store
	mu    sync.Mutex
}

func New(store Store) (*Runtime, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidTask)
	}
	return &Runtime{store: store}, nil
}

func (r *Runtime) Submit(ctx context.Context, submission Submission) (Task, error) {
	if err := validateSubmission(submission); err != nil {
		return Task{}, err
	}
	now := time.Now().UTC()
	task := Task{
		ID:         submission.ID,
		ComputerID: submission.ComputerID,
		State:      StatePending,
		Request:    submission.Request,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	created, err := r.store.Create(ctx, task)
	if err != nil {
		return Task{}, fmt.Errorf("persist submitted task: %w", err)
	}
	return created, nil
}

func (r *Runtime) Run(ctx context.Context, id ID, machine Computer) (Task, error) {
	if machine == nil {
		return Task{}, fmt.Errorf("%w: computer is required", ErrInvalidTask)
	}
	if err := ctx.Err(); err != nil {
		return Task{}, err
	}

	r.mu.Lock()
	task, err := r.store.Get(ctx, id)
	if err != nil {
		r.mu.Unlock()
		return Task{}, fmt.Errorf("load runnable task: %w", err)
	}
	if task.State.terminal() {
		r.mu.Unlock()
		return task, nil
	}
	if task.State != StatePending {
		r.mu.Unlock()
		return task, fmt.Errorf("%w: task %s is %s", ErrNotRunnable, id, task.State)
	}
	if machine.ID() != task.ComputerID {
		r.mu.Unlock()
		return task, fmt.Errorf("%w: task %s requires %s, got %s", ErrComputerMismatch, id, task.ComputerID, machine.ID())
	}

	now := time.Now().UTC()
	task.State = StateRunning
	task.Attempt++
	task.StartedAt = now
	task.FinishedAt = time.Time{}
	task.UpdatedAt = now
	task.Result = nil
	task.Error = ""
	task, err = r.store.Update(ctx, task)
	r.mu.Unlock()
	if err != nil {
		return Task{}, fmt.Errorf("persist running task: %w", err)
	}

	executionResult, executionErr := machine.Exec(ctx, task.Request)
	if executionResult == nil && executionErr == nil {
		executionErr = ErrInvalidResult
	}

	finishedAt := time.Now().UTC()
	if executionResult != nil {
		task.Result = &Result{
			Output:    executionResult.Output,
			ExitCode:  executionResult.ExitCode,
			Duration:  executionResult.Duration,
			RiskScore: executionResult.RiskScore,
		}
	}
	task.FinishedAt = finishedAt
	task.UpdatedAt = finishedAt
	if executionErr == nil {
		task.State = StateSucceeded
	} else {
		task.Error = executionErr.Error()
		if errors.Is(executionErr, context.Canceled) {
			task.State = StateCancelled
		} else {
			task.State = StateFailed
		}
	}

	r.mu.Lock()
	persisted, persistErr := r.store.Update(context.WithoutCancel(ctx), task)
	r.mu.Unlock()
	if persistErr != nil {
		return task, fmt.Errorf("persist terminal task: %w", persistErr)
	}
	if executionErr != nil {
		return persisted, executionErr
	}
	return persisted, nil
}

// Recover marks tasks that were running when the runtime stopped as
// interrupted. It intentionally does not replay them because their side-effect
// outcome is unknown.
func (r *Runtime) Recover(ctx context.Context) ([]Task, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	running, err := r.store.List(ctx, StateRunning)
	if err != nil {
		return nil, fmt.Errorf("list running tasks for recovery: %w", err)
	}

	recovered := make([]Task, 0, len(running))
	for _, task := range running {
		now := time.Now().UTC()
		task.State = StateInterrupted
		task.Error = "runtime stopped while task was running; outcome is unknown and automatic replay is disabled"
		task.UpdatedAt = now
		task.FinishedAt = now
		task, err = r.store.Update(ctx, task)
		if err != nil {
			return recovered, fmt.Errorf("persist recovered task %s: %w", task.ID, err)
		}
		recovered = append(recovered, task)
	}
	return recovered, nil
}

func (r *Runtime) Retry(ctx context.Context, id ID) (Task, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	task, err := r.store.Get(ctx, id)
	if err != nil {
		return Task{}, fmt.Errorf("load task for retry: %w", err)
	}
	switch task.State {
	case StateInterrupted, StateFailed, StateCancelled:
	default:
		return task, fmt.Errorf("%w: task %s cannot be retried from %s", ErrNotRunnable, id, task.State)
	}

	task.State = StatePending
	task.Result = nil
	task.Error = ""
	task.StartedAt = time.Time{}
	task.FinishedAt = time.Time{}
	task.UpdatedAt = time.Now().UTC()
	task, err = r.store.Update(ctx, task)
	if err != nil {
		return Task{}, fmt.Errorf("persist retried task: %w", err)
	}
	return task, nil
}

func validateSubmission(submission Submission) error {
	if err := validateID(submission.ID); err != nil {
		return err
	}
	if strings.TrimSpace(string(submission.ComputerID)) == "" {
		return fmt.Errorf("%w: computer id is required", ErrInvalidTask)
	}
	if strings.TrimSpace(submission.Request.Command) == "" {
		return fmt.Errorf("%w: command is required", ErrInvalidTask)
	}
	return nil
}
