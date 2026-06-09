package execution

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeSandboxRunner struct {
	called    bool
	gotCmd    string
	gotDir    string
	output    string
	returnErr error
}

func (f *fakeSandboxRunner) RunSandboxed(_ context.Context, command, workingDir string) (string, error) {
	f.called = true
	f.gotCmd = command
	f.gotDir = workingDir
	return f.output, f.returnErr
}

func TestMandatorySandbox_RoutesLocalExecution(t *testing.T) {
	runner := &fakeSandboxRunner{output: "sandboxed-output"}
	SetMandatorySandbox(runner)
	t.Cleanup(func() { SetMandatorySandbox(nil) })

	exec := NewLocalExecutor()
	res, err := exec.Execute(context.Background(), LocalRequest{
		SessionID:  "s1",
		ToolName:   "bash",
		Decision:   &Decision{Allowed: true},
		Command:    "echo hello",
		WorkingDir: "/work",
	})
	require.NoError(t, err)
	require.True(t, runner.called, "command must be routed through the mandatory sandbox")
	require.Equal(t, "echo hello", runner.gotCmd)
	require.Equal(t, "/work", runner.gotDir)
	require.Equal(t, "sandboxed-output", res.Output)
}

func TestMandatorySandbox_PolicyDenyStillBlocksBeforeSandbox(t *testing.T) {
	runner := &fakeSandboxRunner{output: "should-not-run"}
	SetMandatorySandbox(runner)
	t.Cleanup(func() { SetMandatorySandbox(nil) })

	exec := NewLocalExecutor()
	_, err := exec.Execute(context.Background(), LocalRequest{
		SessionID: "s1",
		ToolName:  "bash",
		Decision:  &Decision{Allowed: false, Reason: "denied by policy"},
		Command:   "echo hello",
	})
	require.Error(t, err)
	require.True(t, IsLocalErrorKind(err, LocalErrorKindPolicy))
	require.False(t, runner.called, "policy deny must block before the sandbox runs")
}
