package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/chenchunrun/SecOps/internal/taskruntime"
	"github.com/chenchunrun/SecOps/internal/verification"
)

const taskExecutionEvidenceKind = "execution-result"

func (r *ComputerRuntime) VerifyTaskExecution(ctx context.Context, id taskruntime.ID) (taskruntime.Task, error) {
	if r == nil || r.Tasks == nil || r.VerificationStore == nil || r.VerificationMaker == nil || r.VerificationChecker == nil {
		return taskruntime.Task{}, fmt.Errorf("%w: verification runtime is unavailable", taskruntime.ErrInvalidTask)
	}
	task, err := r.Tasks.Get(ctx, id)
	if err != nil {
		return taskruntime.Task{}, err
	}
	if task.State != taskruntime.StateVerifying {
		if task.State == taskruntime.StateSucceeded && task.VerificationVerdict != "" {
			return task, nil
		}
		return task, fmt.Errorf("%w: task %s is %s", taskruntime.ErrNotVerifiable, id, task.State)
	}
	request, artifact, err := taskExecutionEvidence(task)
	if err != nil {
		return task, err
	}
	if _, err := r.VerificationMaker.Make(ctx, request, []verification.Artifact{artifact}); err != nil {
		if !errors.Is(err, verification.ErrAlreadyExists) {
			return task, fmt.Errorf("make task execution evidence: %w", err)
		}
		persisted, loadErr := r.VerificationStore.GetRequest(ctx, request.ID)
		if loadErr != nil {
			return task, fmt.Errorf("load existing task verification request: %w", loadErr)
		}
		if persisted.TaskID != request.TaskID || persisted.ComputerID != request.ComputerID || !reflect.DeepEqual(persisted.Requirements, request.Requirements) {
			return task, fmt.Errorf("%w: verification request %s is bound to another task", taskruntime.ErrInvalidVerificationResult, request.ID)
		}
	}
	return r.Tasks.Verify(ctx, id, r.VerificationChecker)
}

func taskExecutionEvidence(task taskruntime.Task) (verification.Request, verification.Artifact, error) {
	if task.Result == nil {
		return verification.Request{}, verification.Artifact{}, taskruntime.ErrInvalidResult
	}
	payload, err := json.Marshal(struct {
		TaskID     taskruntime.ID     `json:"task_id"`
		ComputerID string             `json:"computer_id"`
		Attempt    int                `json:"attempt"`
		Result     taskruntime.Result `json:"result"`
	}{
		TaskID:     task.ID,
		ComputerID: string(task.ComputerID),
		Attempt:    task.Attempt,
		Result:     *task.Result,
	})
	if err != nil {
		return verification.Request{}, verification.Artifact{}, fmt.Errorf("encode task execution evidence: %w", err)
	}
	request := verification.Request{
		ID:         task.VerificationID,
		TaskID:     string(task.ID),
		ComputerID: task.ComputerID,
		Requirements: []verification.Requirement{{
			Kind:    taskExecutionEvidenceKind,
			Minimum: 1,
		}},
	}
	artifact := verification.Artifact{
		Kind:    taskExecutionEvidenceKind,
		Source:  "durable-task-runtime",
		Payload: payload,
	}
	return request, artifact, nil
}
