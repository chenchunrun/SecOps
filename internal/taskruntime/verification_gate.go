package taskruntime

import (
	"context"
	"fmt"
	"time"

	"github.com/chenchunrun/SecOps/internal/verification"
)

type VerificationChecker interface {
	Check(ctx context.Context, requestID string) (verification.Result, error)
}

func (r *Runtime) Verify(ctx context.Context, id ID, checker VerificationChecker) (Task, error) {
	if checker == nil {
		return Task{}, fmt.Errorf("%w: checker is required", ErrInvalidTask)
	}
	if err := ctx.Err(); err != nil {
		return Task{}, err
	}

	r.mu.Lock()
	task, err := r.store.Get(ctx, id)
	if err != nil {
		r.mu.Unlock()
		return Task{}, fmt.Errorf("load task for verification: %w", err)
	}
	if task.State != StateVerifying {
		r.mu.Unlock()
		if task.State.terminal() && task.VerificationVerdict != "" {
			return task, nil
		}
		return task, fmt.Errorf("%w: task %s is %s", ErrNotVerifiable, id, task.State)
	}
	verificationID := task.VerificationID
	r.mu.Unlock()

	result, checkErr := checker.Check(ctx, verificationID)
	if checkErr != nil {
		return task, fmt.Errorf("check task verification: %w", checkErr)
	}
	if result.RequestID != verificationID {
		return task, fmt.Errorf("%w: task %s requires %s, checker returned %s", ErrInvalidVerificationResult, id, verificationID, result.RequestID)
	}
	if result.Verdict != verification.VerdictPassed && result.Verdict != verification.VerdictFailed {
		return task, fmt.Errorf("%w: unsupported verdict %q", ErrInvalidVerificationResult, result.Verdict)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	task, err = r.store.Get(context.WithoutCancel(ctx), id)
	if err != nil {
		return Task{}, fmt.Errorf("reload task for verification: %w", err)
	}
	if task.State != StateVerifying {
		if task.State.terminal() && task.VerificationVerdict != "" {
			return task, nil
		}
		return task, fmt.Errorf("%w: task %s is %s", ErrNotVerifiable, id, task.State)
	}

	now := time.Now().UTC()
	task.VerificationVerdict = string(result.Verdict)
	task.VerificationEvidenceIDs = append([]string(nil), result.EvidenceIDs...)
	task.VerificationFindings = make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		task.VerificationFindings = append(task.VerificationFindings, fmt.Sprintf("%s: %s", finding.Code, finding.Message))
	}
	task.UpdatedAt = now
	task.FinishedAt = now
	if result.Verdict == verification.VerdictPassed {
		task.State = StateSucceeded
		task.Error = ""
	} else {
		task.State = StateFailed
		task.Error = "verification failed"
	}
	persisted, err := r.store.Update(context.WithoutCancel(ctx), task)
	if err != nil {
		return task, fmt.Errorf("persist task verification: %w", err)
	}
	if result.Verdict == verification.VerdictFailed {
		return persisted, ErrVerificationFailed
	}
	return persisted, nil
}
