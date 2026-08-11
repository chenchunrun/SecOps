package taskruntime

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/verification"
)

type fakeVerificationChecker struct {
	result verification.Result
	err    error
	calls  int
}

func (c *fakeVerificationChecker) Check(_ context.Context, _ string) (verification.Result, error) {
	c.calls++
	return c.result, c.err
}

func TestVerifiedTaskRequiresPassingCheckerBeforeSuccess(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	runtime, err := New(store)
	require.NoError(t, err)
	task, err := runtime.Submit(context.Background(), Submission{
		ID:             "task-verified",
		ComputerID:     "computer-1",
		Request:        computer.ExecRequest{Command: "build"},
		VerificationID: "verify-task-verified",
	})
	require.NoError(t, err)
	machine := &fakeComputer{id: "computer-1", result: &computer.ExecutionResult{Output: "built", ExitCode: 0}}

	executed, err := runtime.Run(context.Background(), task.ID, machine)
	require.NoError(t, err)
	require.Equal(t, StateVerifying, executed.State)
	require.Equal(t, "verify-task-verified", executed.VerificationID)
	require.Zero(t, executed.FinishedAt)

	checker := &fakeVerificationChecker{result: verification.Result{
		RequestID:   "verify-task-verified",
		Verdict:     verification.VerdictPassed,
		EvidenceIDs: []string{"verify-task-verified-0001"},
	}}
	completed, err := runtime.Verify(context.Background(), task.ID, checker)
	require.NoError(t, err)
	require.Equal(t, StateSucceeded, completed.State)
	require.Equal(t, string(verification.VerdictPassed), completed.VerificationVerdict)
	require.Equal(t, []string{"verify-task-verified-0001"}, completed.VerificationEvidenceIDs)
	require.NotZero(t, completed.FinishedAt)
	require.Equal(t, 1, checker.calls)
}

func TestVerifiedTaskFailsWhenCheckerRejectsEvidence(t *testing.T) {
	t.Parallel()

	runtime, task := newVerifyingTask(t, "task-rejected", "verify-task-rejected")
	checker := &fakeVerificationChecker{result: verification.Result{
		RequestID: "verify-task-rejected",
		Verdict:   verification.VerdictFailed,
		Findings: []verification.Finding{{
			Code:    verification.FindingMissingEvidence,
			Message: "required evidence is missing",
		}},
	}}

	failed, err := runtime.Verify(context.Background(), task.ID, checker)
	require.ErrorIs(t, err, ErrVerificationFailed)
	require.Equal(t, StateFailed, failed.State)
	require.Equal(t, string(verification.VerdictFailed), failed.VerificationVerdict)
	require.Equal(t, []string{"missing_evidence: required evidence is missing"}, failed.VerificationFindings)
	require.Contains(t, failed.Error, "verification failed")
}

func TestVerificationCanResumeAfterRuntimeRestart(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store, err := NewFileStore(root)
	require.NoError(t, err)
	runtime, err := New(store)
	require.NoError(t, err)
	task, err := runtime.Submit(context.Background(), Submission{
		ID:             "task-restart-verification",
		ComputerID:     "computer-1",
		Request:        computer.ExecRequest{Command: "deploy"},
		VerificationID: "verify-restart",
	})
	require.NoError(t, err)
	machine := &fakeComputer{id: "computer-1", result: &computer.ExecutionResult{ExitCode: 0}}
	task, err = runtime.Run(context.Background(), task.ID, machine)
	require.NoError(t, err)
	require.Equal(t, StateVerifying, task.State)

	reopened, err := NewFileStore(root)
	require.NoError(t, err)
	restarted, err := New(reopened)
	require.NoError(t, err)
	recovered, err := restarted.Recover(context.Background())
	require.NoError(t, err)
	require.Empty(t, recovered)
	checker := &fakeVerificationChecker{result: verification.Result{RequestID: "verify-restart", Verdict: verification.VerdictPassed}}

	completed, err := restarted.Verify(context.Background(), task.ID, checker)
	require.NoError(t, err)
	require.Equal(t, StateSucceeded, completed.State)
	require.Equal(t, 1, machine.calls)
}

func TestCheckerErrorLeavesTaskVerifying(t *testing.T) {
	t.Parallel()

	runtime, task := newVerifyingTask(t, "task-checker-error", "verify-checker-error")
	checkerErr := errors.New("verification store unavailable")
	checker := &fakeVerificationChecker{err: checkerErr}

	unchanged, err := runtime.Verify(context.Background(), task.ID, checker)
	require.ErrorIs(t, err, checkerErr)
	require.Equal(t, StateVerifying, unchanged.State)
	persisted, err := runtime.Get(context.Background(), task.ID)
	require.NoError(t, err)
	require.Equal(t, StateVerifying, persisted.State)
}

func newVerifyingTask(t *testing.T, taskID ID, verificationID string) (*Runtime, Task) {
	t.Helper()
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	runtime, err := New(store)
	require.NoError(t, err)
	task, err := runtime.Submit(context.Background(), Submission{
		ID:             taskID,
		ComputerID:     "computer-1",
		Request:        computer.ExecRequest{Command: "run"},
		VerificationID: verificationID,
	})
	require.NoError(t, err)
	machine := &fakeComputer{id: "computer-1", result: &computer.ExecutionResult{ExitCode: 0}}
	task, err = runtime.Run(context.Background(), task.ID, machine)
	require.NoError(t, err)
	require.Equal(t, StateVerifying, task.State)
	return runtime, task
}
