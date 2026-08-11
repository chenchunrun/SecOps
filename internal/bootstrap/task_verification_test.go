package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
	"github.com/chenchunrun/SecOps/internal/verification"
)

type verificationComputer struct {
	id     computer.ID
	result *computer.ExecutionResult
	calls  int
}

func (c *verificationComputer) ID() computer.ID {
	return c.id
}

func (c *verificationComputer) Exec(_ context.Context, _ computer.ExecRequest) (*computer.ExecutionResult, error) {
	c.calls++
	return c.result, nil
}

func TestComputerRuntimeVerifiesTaskExecutionEvidence(t *testing.T) {
	t.Parallel()

	runtime, err := newComputerRuntime(context.Background(), t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, runtime.VerificationMaker)
	require.NotNil(t, runtime.VerificationChecker)
	task, err := runtime.Tasks.Submit(context.Background(), taskruntime.Submission{
		ID:             "task-bootstrap-verify",
		ComputerID:     "verification-computer",
		Request:        computer.ExecRequest{Command: "build"},
		VerificationID: "verify-bootstrap-task",
	})
	require.NoError(t, err)
	machine := &verificationComputer{
		id: "verification-computer",
		result: &computer.ExecutionResult{
			Output:    "build complete\n",
			ExitCode:  0,
			RiskScore: 12,
		},
	}
	task, err = runtime.Tasks.Run(context.Background(), task.ID, machine)
	require.NoError(t, err)
	require.Equal(t, taskruntime.StateVerifying, task.State)

	completed, err := runtime.VerifyTaskExecution(context.Background(), task.ID)
	require.NoError(t, err)
	require.Equal(t, taskruntime.StateSucceeded, completed.State)
	require.Equal(t, string(verification.VerdictPassed), completed.VerificationVerdict)
	require.Len(t, completed.VerificationEvidenceIDs, 1)
	require.Equal(t, 1, machine.calls)
}

func TestComputerRuntimeResumesAfterEvidenceWasPersistedBeforeRestart(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	runtime, err := newComputerRuntime(context.Background(), root)
	require.NoError(t, err)
	task, err := runtime.Tasks.Submit(context.Background(), taskruntime.Submission{
		ID:             "task-bootstrap-restart",
		ComputerID:     "verification-computer",
		Request:        computer.ExecRequest{Command: "deploy"},
		VerificationID: "verify-bootstrap-restart",
	})
	require.NoError(t, err)
	machine := &verificationComputer{id: "verification-computer", result: &computer.ExecutionResult{Output: "deployed", ExitCode: 0}}
	task, err = runtime.Tasks.Run(context.Background(), task.ID, machine)
	require.NoError(t, err)
	request, artifact, err := taskExecutionEvidence(task)
	require.NoError(t, err)
	_, err = runtime.VerificationMaker.Make(context.Background(), request, []verification.Artifact{artifact})
	require.NoError(t, err)

	restarted, err := newComputerRuntime(context.Background(), root)
	require.NoError(t, err)
	completed, err := restarted.VerifyTaskExecution(context.Background(), task.ID)
	require.NoError(t, err)
	require.Equal(t, taskruntime.StateSucceeded, completed.State)
	require.Equal(t, 1, machine.calls)
}

func TestComputerRuntimeRejectsVerificationForLegacyCompletedTask(t *testing.T) {
	t.Parallel()

	runtime, err := newComputerRuntime(context.Background(), t.TempDir())
	require.NoError(t, err)
	task, err := runtime.Tasks.Submit(context.Background(), taskruntime.Submission{
		ID:         "task-bootstrap-legacy",
		ComputerID: "verification-computer",
		Request:    computer.ExecRequest{Command: "build"},
	})
	require.NoError(t, err)
	machine := &verificationComputer{id: "verification-computer", result: &computer.ExecutionResult{ExitCode: 0}}
	task, err = runtime.Tasks.Run(context.Background(), task.ID, machine)
	require.NoError(t, err)
	require.Equal(t, taskruntime.StateSucceeded, task.State)

	unchanged, err := runtime.VerifyTaskExecution(context.Background(), task.ID)
	require.ErrorIs(t, err, taskruntime.ErrNotVerifiable)
	require.Equal(t, taskruntime.StateSucceeded, unchanged.State)
}
