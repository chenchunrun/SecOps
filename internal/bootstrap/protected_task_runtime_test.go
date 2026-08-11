package bootstrap

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/egress"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/scheduler"
	"github.com/chenchunrun/SecOps/internal/security"
	"github.com/chenchunrun/SecOps/internal/security/redact"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
)

type protectedSource struct {
	value []byte
	calls int
}

func (s *protectedSource) Resolve(context.Context, string) ([]byte, error) {
	s.calls++
	return append([]byte(nil), s.value...), nil
}

type protectedComputer struct {
	id          computer.ID
	request     computer.ExecRequest
	secretValue string
}

func (c *protectedComputer) ID() computer.ID           { return c.id }
func (c *protectedComputer) Backend() computer.Backend { return computer.BackendLocal }
func (c *protectedComputer) State() computer.State     { return computer.StateActive }
func (c *protectedComputer) Exec(_ context.Context, request computer.ExecRequest) (*computer.ExecutionResult, error) {
	environment := make(map[string]string, len(request.Config.Environment))
	for name, value := range request.Config.Environment {
		environment[name] = value
	}
	request.Config.Environment = environment
	c.request = request
	return &computer.ExecutionResult{Output: "credential=" + c.secretValue, ExitCode: 0}, nil
}
func (c *protectedComputer) Suspend(context.Context) error { return nil }
func (c *protectedComputer) Resume(context.Context) error  { return nil }
func (c *protectedComputer) Destroy(context.Context) error { return nil }

func TestProtectedScheduledTaskRuntimeRunsAuthorizedEgressWithoutPersistingSecret(t *testing.T) {
	t.Parallel()

	const secret = "secret-value-must-not-persist"
	computerRuntime, runtimeScheduler, machine := newProtectedTestRuntime(t, secret)
	policy, err := egress.NewPolicy([]egress.Rule{{
		ID:             "github-api",
		Protocol:       egress.ProtocolHTTPS,
		Host:           "api.github.com",
		Ports:          []int{443},
		CredentialRefs: []string{"github/actions"},
	}})
	require.NoError(t, err)
	source := &protectedSource{value: []byte(secret)}
	broker, err := egress.NewBroker(source, time.Minute)
	require.NoError(t, err)
	protectedRuntime, err := NewProtectedScheduledTaskRuntime(computerRuntime, runtimeScheduler, policy, broker)
	require.NoError(t, err)

	result, err := protectedRuntime.SubmitAndRun(context.Background(), ProtectedSubmission{
		Task: ScheduledSubmission{
			ID:           "protected-run",
			WorkspaceID:  DefaultWorkspaceID,
			Request:      computer.ExecRequest{Command: "call github"},
			Capabilities: []string{security.CapabilityShellReadOnly},
			Scope:        scheduler.ScopeWorkspace,
			Authorization: scheduler.Authorization{
				Decision: permission.DecisionAutoApprove,
				Approved: true,
			},
			Risk: lowSchedulerRisk(),
		},
		Destinations: []egress.Request{{
			Protocol:       egress.ProtocolHTTPS,
			Host:           "api.github.com",
			Port:           443,
			CredentialRefs: []string{"github/actions"},
		}},
		CredentialBindings: []egress.Binding{{
			Reference:   "github/actions",
			Environment: "GITHUB_TOKEN",
		}},
		CredentialTTL: time.Minute,
	})
	require.NoError(t, err)
	require.Equal(t, taskruntime.StateSucceeded, result.Task.State)
	require.Equal(t, machine.ID(), result.Task.ComputerID)
	require.Equal(t, secret, machine.request.Config.Environment["GITHUB_TOKEN"])
	require.Len(t, result.EgressDecisions, 1)
	require.True(t, result.EgressDecisions[0].Allowed)
	require.Equal(t, scheduler.OutcomeSelected, result.SchedulerDecision.Outcome)
	require.Equal(t, "credential="+redact.Redacted, result.Task.Result.Output)
	require.Equal(t, 1, source.calls)

	data, err := json.Marshal(result.Task)
	require.NoError(t, err)
	require.NotContains(t, string(data), secret)
	require.NotContains(t, string(data), "GITHUB_TOKEN")
}

func TestProtectedScheduledTaskRuntimeRejectsBeforeTaskPersistence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*ProtectedSubmission)
		wantError error
	}{
		{
			name: "egress denied",
			mutate: func(submission *ProtectedSubmission) {
				submission.Destinations[0].Host = "evil.example.com"
			},
			wantError: egress.ErrEgressDenied,
		},
		{
			name: "credential reference mismatch",
			mutate: func(submission *ProtectedSubmission) {
				submission.CredentialBindings[0].Reference = "production/root"
			},
			wantError: ErrCredentialReferenceMismatch,
		},
		{
			name: "unmanaged environment",
			mutate: func(submission *ProtectedSubmission) {
				submission.Task.Request.Config.Environment = map[string]string{"TOKEN": "unmanaged"}
			},
			wantError: ErrUnmanagedEnvironment,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			computerRuntime, runtimeScheduler, _ := newProtectedTestRuntime(t, "secret")
			policy, err := egress.NewPolicy([]egress.Rule{{
				ID:             "allowed",
				Protocol:       egress.ProtocolHTTPS,
				Host:           "api.github.com",
				Ports:          []int{443},
				CredentialRefs: []string{"github/actions"},
			}})
			require.NoError(t, err)
			source := &protectedSource{value: []byte("secret")}
			broker, err := egress.NewBroker(source, time.Minute)
			require.NoError(t, err)
			protectedRuntime, err := NewProtectedScheduledTaskRuntime(computerRuntime, runtimeScheduler, policy, broker)
			require.NoError(t, err)

			taskID := "rejected-" + strings.ReplaceAll(tt.name, " ", "-")
			submission := validProtectedSubmission(taskruntime.ID(taskID))
			tt.mutate(&submission)
			result, runErr := protectedRuntime.SubmitAndRun(context.Background(), submission)
			require.ErrorIs(t, runErr, tt.wantError)
			require.Empty(t, result.Task.ID)
			_, getErr := computerRuntime.Tasks.Get(context.Background(), submission.Task.ID)
			require.ErrorIs(t, getErr, taskruntime.ErrNotFound)
			require.Equal(t, 0, source.calls)
		})
	}
}

func newProtectedTestRuntime(
	t *testing.T,
	secret string,
) (*ComputerRuntime, *scheduler.Scheduler, *protectedComputer) {
	t.Helper()
	computerRuntime, err := newComputerRuntime(context.Background(), t.TempDir())
	require.NoError(t, err)
	machine := &protectedComputer{id: "protected-local", secretValue: secret}
	require.NoError(t, computerRuntime.Computers.Register(machine))
	runtimeScheduler, err := scheduler.New(computerRuntime.Computers, []scheduler.Profile{{
		ComputerID:   machine.ID(),
		Capabilities: []string{"*"},
		Scopes:       []scheduler.Scope{scheduler.ScopeWorkspace},
	}}, nil)
	require.NoError(t, err)
	return computerRuntime, runtimeScheduler, machine
}

func validProtectedSubmission(id taskruntime.ID) ProtectedSubmission {
	return ProtectedSubmission{
		Task: ScheduledSubmission{
			ID:           id,
			WorkspaceID:  DefaultWorkspaceID,
			Request:      computer.ExecRequest{Command: "call github"},
			Capabilities: []string{security.CapabilityShellReadOnly},
			Scope:        scheduler.ScopeWorkspace,
			Authorization: scheduler.Authorization{
				Decision: permission.DecisionAutoApprove,
				Approved: true,
			},
			Risk: lowSchedulerRisk(),
		},
		Destinations: []egress.Request{{
			Protocol:       egress.ProtocolHTTPS,
			Host:           "api.github.com",
			Port:           443,
			CredentialRefs: []string{"github/actions"},
		}},
		CredentialBindings: []egress.Binding{{
			Reference:   "github/actions",
			Environment: "GITHUB_TOKEN",
		}},
		CredentialTTL: time.Minute,
	}
}
