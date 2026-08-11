package egress

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/security/redact"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
)

type capturingComputer struct {
	id      computer.ID
	backend computer.Backend
	request computer.ExecRequest
	execErr error
	output  string
}

func (c *capturingComputer) ID() computer.ID           { return c.id }
func (c *capturingComputer) Backend() computer.Backend { return c.backend }
func (c *capturingComputer) State() computer.State     { return computer.StateActive }
func (c *capturingComputer) Exec(_ context.Context, request computer.ExecRequest) (*computer.ExecutionResult, error) {
	environment := make(map[string]string, len(request.Config.Environment))
	for name, value := range request.Config.Environment {
		environment[name] = value
	}
	request.Config.Environment = environment
	c.request = request
	return &computer.ExecutionResult{Output: c.output, ExitCode: 0}, c.execErr
}
func (c *capturingComputer) Suspend(context.Context) error { return nil }
func (c *capturingComputer) Resume(context.Context) error  { return nil }
func (c *capturingComputer) Destroy(context.Context) error { return nil }

func TestLeaseComputerInjectsForOneExecutionAndRevokes(t *testing.T) {
	t.Parallel()

	broker, err := NewBroker(memorySource{values: map[string][]byte{
		"github/actions": []byte("secret-value"),
	}}, time.Minute)
	require.NoError(t, err)
	lease, err := broker.Issue(context.Background(), []Binding{
		{Reference: "github/actions", Environment: "PROXY_TOKEN"},
	}, time.Minute)
	require.NoError(t, err)

	base := &capturingComputer{id: "local", backend: computer.BackendLocal, output: "token=secret-value"}
	wrapped, err := NewLeaseComputer(base, lease)
	require.NoError(t, err)
	require.Equal(t, base.ID(), wrapped.ID())
	require.Equal(t, base.Backend(), wrapped.Backend())

	request := computer.ExecRequest{Command: "echo test"}
	request.Config.Environment = map[string]string{
		"PROXY_TOKEN": "caller-value",
		"REGION":      "test",
	}
	result, err := wrapped.Exec(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "secret-value", base.request.Config.Environment["PROXY_TOKEN"])
	require.Equal(t, "test", base.request.Config.Environment["REGION"])
	require.Equal(t, redact.Redacted, result.Output)

	_, err = wrapped.Exec(context.Background(), request)
	require.ErrorIs(t, err, ErrLeaseRevoked)
}

func TestLeaseComputerRevokesAfterExecutionFailure(t *testing.T) {
	t.Parallel()

	broker, err := NewBroker(memorySource{values: map[string][]byte{"ref": []byte("secret-value")}}, time.Minute)
	require.NoError(t, err)
	lease, err := broker.Issue(context.Background(), []Binding{{Reference: "ref", Environment: "TOKEN"}}, time.Minute)
	require.NoError(t, err)

	base := &capturingComputer{id: "docker", backend: computer.BackendDocker, execErr: errors.New("execution failed")}
	wrapped, err := NewLeaseComputer(base, lease)
	require.NoError(t, err)
	_, err = wrapped.Exec(context.Background(), computer.ExecRequest{Command: "false"})
	require.EqualError(t, err, "execution failed")
	_, err = lease.Environment()
	require.ErrorIs(t, err, ErrLeaseRevoked)
}

func TestLeaseComputerRejectsUnsupportedBackend(t *testing.T) {
	t.Parallel()

	broker, err := NewBroker(memorySource{values: map[string][]byte{"ref": []byte("secret-value")}}, time.Minute)
	require.NoError(t, err)
	lease, err := broker.Issue(context.Background(), []Binding{{Reference: "ref", Environment: "TOKEN"}}, time.Minute)
	require.NoError(t, err)

	wrapped, err := NewLeaseComputer(&capturingComputer{id: "ssh", backend: computer.BackendSSH}, lease)
	require.ErrorIs(t, err, ErrCredentialInjectionUnsupported)
	require.Nil(t, wrapped)
}

func TestTransientCredentialIsExcludedFromDurableTaskJSON(t *testing.T) {
	t.Parallel()

	task := taskruntime.Task{
		ID:         "transient-secret",
		ComputerID: "local",
		Request:    computer.ExecRequest{Command: "echo test"},
	}
	task.Request.Config.Environment = map[string]string{
		"PROXY_TOKEN": "secret-value-must-not-persist",
	}
	data, err := json.Marshal(task)
	require.NoError(t, err)
	require.NotContains(t, string(data), "PROXY_TOKEN")
	require.NotContains(t, string(data), "secret-value-must-not-persist")
	require.Contains(t, string(data), "transient-secret")
}
