package taskruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chenchunrun/SecOps/internal/admission"
	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/workspace"
)

type Computer interface {
	ID() computer.ID
	Exec(ctx context.Context, request computer.ExecRequest) (*computer.ExecutionResult, error)
}

type ComputerResolver interface {
	Get(id computer.ID) (computer.Computer, error)
}

type Runtime struct {
	store          Store
	mu             sync.Mutex
	active         map[ID]context.CancelFunc
	requestedState map[ID]State
}

func New(store Store) (*Runtime, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidTask)
	}
	return &Runtime{store: store, active: make(map[ID]context.CancelFunc), requestedState: make(map[ID]State)}, nil
}

func (r *Runtime) Submit(ctx context.Context, submission Submission) (Task, error) {
	if err := validateSubmission(submission); err != nil {
		return Task{}, err
	}
	now := time.Now().UTC()
	task := Task{
		ID:             submission.ID,
		ComputerID:     submission.ComputerID,
		WorkspaceID:    submission.WorkspaceID,
		State:          StatePending,
		Request:        submission.Request,
		VerificationID: submission.VerificationID,
		ResourceDemand: submission.ResourceDemand,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	created, err := r.store.Create(ctx, task)
	if err != nil {
		return Task{}, fmt.Errorf("persist submitted task: %w", err)
	}
	return created, nil
}

func (r *Runtime) Get(ctx context.Context, id ID) (Task, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	task, err := r.store.Get(ctx, id)
	if err != nil {
		return Task{}, fmt.Errorf("load durable task: %w", err)
	}
	return task, nil
}

// BindAdmissionLease durably associates the next admission attempt with a
// pending task before backend execution begins.
func (r *Runtime) BindAdmissionLease(ctx context.Context, id ID, leaseID admission.ID) (Task, error) {
	if strings.TrimSpace(string(leaseID)) == "" {
		return Task{}, fmt.Errorf("%w: admission lease id is required", ErrInvalidTask)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	task, err := r.store.Get(ctx, id)
	if err != nil {
		return Task{}, fmt.Errorf("load task for admission binding: %w", err)
	}
	if task.State != StatePending {
		return task, fmt.Errorf("%w: task %s cannot bind admission from %s", ErrNotRunnable, id, task.State)
	}
	if task.AdmissionLeaseID != "" && task.AdmissionReleasedAt.IsZero() {
		return task, fmt.Errorf("%w: task %s already has active admission lease %s", ErrConflict, id, task.AdmissionLeaseID)
	}
	task.AdmissionAttempt++
	task.AdmissionLeaseID = leaseID
	task.AdmissionReleasedAt = time.Time{}
	task.UpdatedAt = time.Now().UTC()
	task, err = r.store.Update(ctx, task)
	if err != nil {
		return Task{}, fmt.Errorf("persist task admission binding: %w", err)
	}
	return task, nil
}

// MarkAdmissionReleased records the external lease release on its task.
func (r *Runtime) MarkAdmissionReleased(
	ctx context.Context,
	id ID,
	leaseID admission.ID,
	releasedAt time.Time,
) (Task, error) {
	if strings.TrimSpace(string(leaseID)) == "" || releasedAt.IsZero() {
		return Task{}, fmt.Errorf("%w: released admission lease identity and time are required", ErrInvalidTask)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	task, err := r.store.Get(ctx, id)
	if err != nil {
		return Task{}, fmt.Errorf("load task for admission release: %w", err)
	}
	if task.AdmissionLeaseID != leaseID {
		return task, fmt.Errorf("%w: task %s is bound to admission lease %s, not %s", ErrConflict, id, task.AdmissionLeaseID, leaseID)
	}
	if !task.AdmissionReleasedAt.IsZero() {
		return task, nil
	}
	task.AdmissionReleasedAt = releasedAt.UTC()
	task.UpdatedAt = time.Now().UTC()
	task, err = r.store.Update(ctx, task)
	if err != nil {
		return Task{}, fmt.Errorf("persist task admission release: %w", err)
	}
	return task, nil
}

func (r *Runtime) RunAssigned(ctx context.Context, id ID, resolver ComputerResolver) (Task, error) {
	if resolver == nil {
		return Task{}, fmt.Errorf("%w: computer resolver is required", ErrInvalidTask)
	}
	task, err := r.Get(ctx, id)
	if err != nil {
		return Task{}, err
	}
	machine, err := resolver.Get(task.ComputerID)
	if err != nil {
		return task, fmt.Errorf("resolve assigned computer %s: %w", task.ComputerID, err)
	}
	return r.Run(ctx, id, machine)
}

func (r *Runtime) Run(ctx context.Context, id ID, machine Computer) (Task, error) {
	if machine == nil {
		return Task{}, fmt.Errorf("%w: computer is required", ErrInvalidTask)
	}
	if err := ctx.Err(); err != nil {
		return Task{}, err
	}

	execCtx, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	task, err := r.store.Get(ctx, id)
	if err != nil {
		r.mu.Unlock()
		cancel()
		return Task{}, fmt.Errorf("load runnable task: %w", err)
	}
	if task.State.terminal() {
		r.mu.Unlock()
		cancel()
		return task, nil
	}
	if task.State != StatePending {
		r.mu.Unlock()
		cancel()
		return task, fmt.Errorf("%w: task %s is %s", ErrNotRunnable, id, task.State)
	}
	if machine.ID() != task.ComputerID {
		r.mu.Unlock()
		cancel()
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
	task.VerificationVerdict = ""
	task.VerificationEvidenceIDs = nil
	task.VerificationFindings = nil
	task, err = r.store.Update(ctx, task)
	if err == nil {
		r.active[id] = cancel
		delete(r.requestedState, id)
	}
	r.mu.Unlock()
	if err != nil {
		cancel()
		return Task{}, fmt.Errorf("persist running task: %w", err)
	}

	executionResult, executionErr := machine.Exec(execCtx, task.Request)
	cancel()
	r.mu.Lock()
	requestedState := r.requestedState[id]
	delete(r.active, id)
	delete(r.requestedState, id)
	r.mu.Unlock()
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
	task.UpdatedAt = finishedAt
	if executionErr == nil {
		if task.VerificationID != "" {
			task.State = StateVerifying
			task.FinishedAt = time.Time{}
		} else {
			task.State = StateSucceeded
			task.FinishedAt = finishedAt
		}
	} else {
		task.FinishedAt = finishedAt
		task.Error = executionErr.Error()
		if errors.Is(executionErr, context.Canceled) && requestedState == StatePaused {
			task.State = StatePaused
			task.Error = "task paused by user"
			task.FinishedAt = time.Time{}
			task.Result = nil
		} else if errors.Is(executionErr, context.Canceled) {
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

func (r *Runtime) Pause(ctx context.Context, id ID) (Task, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	task, err := r.store.Get(ctx, id)
	if err != nil {
		return Task{}, fmt.Errorf("load task for pause: %w", err)
	}
	switch task.State {
	case StatePaused:
		return task, nil
	case StatePending:
		task.State = StatePaused
		task.Error = "task paused by user"
		task.UpdatedAt = time.Now().UTC()
		persisted, err := r.store.Update(ctx, task)
		if err != nil {
			return Task{}, fmt.Errorf("persist paused task: %w", err)
		}
		return persisted, nil
	case StateRunning:
		cancel := r.active[id]
		if cancel == nil {
			return task, fmt.Errorf("%w: running task %s has no active execution", ErrConflict, id)
		}
		r.requestedState[id] = StatePaused
		cancel()
		return task, nil
	default:
		return task, fmt.Errorf("%w: task %s cannot pause from %s", ErrNotRunnable, id, task.State)
	}
}

func (r *Runtime) Resume(ctx context.Context, id ID) (Task, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	task, err := r.store.Get(ctx, id)
	if err != nil {
		return Task{}, fmt.Errorf("load task for resume: %w", err)
	}
	if task.State != StatePaused {
		return task, fmt.Errorf("%w: task %s cannot resume from %s", ErrNotRunnable, id, task.State)
	}
	task.State = StatePending
	task.Error = ""
	task.Result = nil
	task.StartedAt = time.Time{}
	task.FinishedAt = time.Time{}
	task.UpdatedAt = time.Now().UTC()
	persisted, err := r.store.Update(ctx, task)
	if err != nil {
		return Task{}, fmt.Errorf("persist resumed task: %w", err)
	}
	return persisted, nil
}

func (r *Runtime) Cancel(ctx context.Context, id ID) (Task, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	task, err := r.store.Get(ctx, id)
	if err != nil {
		return Task{}, fmt.Errorf("load task for cancellation: %w", err)
	}
	if task.State == StateCancelled {
		return task, nil
	}
	if task.State.terminal() {
		return task, fmt.Errorf("%w: terminal task %s cannot be cancelled", ErrNotRunnable, id)
	}
	if task.State == StateRunning {
		cancel := r.active[id]
		if cancel == nil {
			return task, fmt.Errorf("%w: running task %s has no active execution", ErrConflict, id)
		}
		r.requestedState[id] = StateCancelled
		cancel()
		return task, nil
	}
	task.State = StateCancelled
	task.Error = "task cancelled by user"
	task.UpdatedAt = time.Now().UTC()
	task.FinishedAt = task.UpdatedAt
	persisted, err := r.store.Update(ctx, task)
	if err != nil {
		return Task{}, fmt.Errorf("persist cancelled task: %w", err)
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
	task.VerificationVerdict = ""
	task.VerificationEvidenceIDs = nil
	task.VerificationFindings = nil
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
	if submission.WorkspaceID != "" {
		if err := workspace.ValidateID(submission.WorkspaceID); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidTask, err)
		}
	}
	if submission.VerificationID != "" {
		if err := validateID(ID(submission.VerificationID)); err != nil {
			return fmt.Errorf("%w: invalid verification id", ErrInvalidTask)
		}
	}
	return nil
}
