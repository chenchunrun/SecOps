package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/egress"
	"github.com/chenchunrun/SecOps/internal/scheduler"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
)

var (
	ErrEgressPolicyRequired        = errors.New("egress policy is required")
	ErrCredentialBrokerRequired    = errors.New("credential broker is required")
	ErrInvalidProtectedSubmission  = errors.New("invalid protected task submission")
	ErrCredentialReferenceMismatch = errors.New("credential references do not match bindings")
	ErrUnmanagedEnvironment        = errors.New("unmanaged transient environment is denied")
)

// ProtectedSubmission adds outbound destinations and opaque credential
// bindings to a backend-neutral durable task declaration.
type ProtectedSubmission struct {
	Task               ScheduledSubmission
	Destinations       []egress.Request
	CredentialBindings []egress.Binding
	CredentialTTL      time.Duration
}

// ProtectedResult captures both policy decisions and the durable task result.
type ProtectedResult struct {
	Task              taskruntime.Task
	SchedulerDecision scheduler.Decision
	EgressDecisions   []egress.Decision
}

// ProtectedScheduledTaskRuntime composes egress authorization, credential
// brokering, deterministic scheduling, durable persistence, and execution.
type ProtectedScheduledTaskRuntime struct {
	scheduled *ScheduledTaskRuntime
	policy    *egress.Policy
	broker    *egress.Broker
}

// NewProtectedScheduledTaskRuntime creates the fail-closed protected execution
// entry point.
func NewProtectedScheduledTaskRuntime(
	runtime *ComputerRuntime,
	runtimeScheduler *scheduler.Scheduler,
	policy *egress.Policy,
	broker *egress.Broker,
) (*ProtectedScheduledTaskRuntime, error) {
	if policy == nil {
		return nil, ErrEgressPolicyRequired
	}
	if broker == nil {
		return nil, ErrCredentialBrokerRequired
	}
	scheduled, err := NewScheduledTaskRuntime(runtime, runtimeScheduler)
	if err != nil {
		return nil, err
	}
	return &ProtectedScheduledTaskRuntime{scheduled: scheduled, policy: policy, broker: broker}, nil
}

// SubmitAndRun completes every security decision before task persistence, then
// executes with a single-use lease wrapper when credentials are requested.
func (r *ProtectedScheduledTaskRuntime) SubmitAndRun(
	ctx context.Context,
	submission ProtectedSubmission,
) (ProtectedResult, error) {
	result := ProtectedResult{}
	if len(submission.Destinations) == 0 {
		return result, ErrInvalidProtectedSubmission
	}
	if len(submission.Task.Request.Config.Environment) != 0 {
		return result, ErrUnmanagedEnvironment
	}
	if !credentialReferencesMatch(submission.Destinations, submission.CredentialBindings) {
		return result, ErrCredentialReferenceMismatch
	}

	result.EgressDecisions = make([]egress.Decision, 0, len(submission.Destinations))
	for _, destination := range submission.Destinations {
		decision, err := r.policy.Authorize(destination)
		result.EgressDecisions = append(result.EgressDecisions, decision)
		if err != nil {
			return result, fmt.Errorf("authorize protected task egress: %w", err)
		}
	}

	decision, err := r.scheduled.scheduler.Schedule(ctx, scheduler.Request{
		RequestID:     string(submission.Task.ID),
		Capabilities:  submission.Task.Capabilities,
		Scope:         submission.Task.Scope,
		Authorization: submission.Task.Authorization,
		Risk:          submission.Task.Risk,
	})
	result.SchedulerDecision = decision
	if err != nil {
		return result, fmt.Errorf("schedule protected durable task: %w", err)
	}
	machine, err := r.scheduled.runtime.Computers.Get(decision.ComputerID)
	if err != nil {
		return result, fmt.Errorf("resolve protected task computer: %w", err)
	}

	var resolver taskruntime.ComputerResolver = r.scheduled.runtime.Computers
	var lease *egress.Lease
	if len(submission.CredentialBindings) > 0 {
		lease, err = r.broker.Issue(ctx, submission.CredentialBindings, submission.CredentialTTL)
		if err != nil {
			return result, fmt.Errorf("issue protected task credential lease: %w", err)
		}
		defer lease.Revoke()
		wrapped, wrapErr := egress.NewLeaseComputer(machine, lease)
		if wrapErr != nil {
			return result, fmt.Errorf("prepare protected task computer: %w", wrapErr)
		}
		resolver = fixedComputerResolver{id: decision.ComputerID, machine: wrapped}
	}

	task, err := r.scheduled.runtime.Tasks.Submit(ctx, taskruntime.Submission{
		ID:          submission.Task.ID,
		ComputerID:  decision.ComputerID,
		WorkspaceID: submission.Task.WorkspaceID,
		Request:     submission.Task.Request,
	})
	result.Task = task
	if err != nil {
		return result, fmt.Errorf("persist protected durable task: %w", err)
	}
	task, err = r.scheduled.runtime.Tasks.RunAssigned(ctx, task.ID, resolver)
	result.Task = task
	if err != nil {
		return result, fmt.Errorf("run protected durable task: %w", err)
	}
	return result, nil
}

type fixedComputerResolver struct {
	id      computer.ID
	machine computer.Computer
}

func (r fixedComputerResolver) Get(id computer.ID) (computer.Computer, error) {
	if id != r.id {
		return nil, fmt.Errorf("assigned computer %s is unavailable", id)
	}
	return r.machine, nil
}

func credentialReferencesMatch(destinations []egress.Request, bindings []egress.Binding) bool {
	required := make(map[string]struct{})
	for _, destination := range destinations {
		for _, reference := range destination.CredentialRefs {
			reference = strings.TrimSpace(reference)
			if reference == "" {
				return false
			}
			required[reference] = struct{}{}
		}
	}
	bound := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		reference := strings.TrimSpace(binding.Reference)
		if reference == "" {
			return false
		}
		bound[reference] = struct{}{}
	}
	if len(required) != len(bound) {
		return false
	}
	for reference := range required {
		if _, exists := bound[reference]; !exists {
			return false
		}
	}
	return true
}
