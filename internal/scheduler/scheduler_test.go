package scheduler

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/security"
)

type fakeInventory struct {
	computers []computer.Computer
}

func (f fakeInventory) List() []computer.Computer { return f.computers }

type fakeComputer struct {
	id      computer.ID
	backend computer.Backend
	state   computer.State
}

func (f *fakeComputer) ID() computer.ID           { return f.id }
func (f *fakeComputer) Backend() computer.Backend { return f.backend }
func (f *fakeComputer) State() computer.State     { return f.state }
func (f *fakeComputer) Exec(context.Context, computer.ExecRequest) (*computer.ExecutionResult, error) {
	return &computer.ExecutionResult{}, nil
}
func (f *fakeComputer) Suspend(context.Context) error { return nil }
func (f *fakeComputer) Resume(context.Context) error  { return nil }
func (f *fakeComputer) Destroy(context.Context) error { return nil }

type recordingObserver struct {
	events []Event
	err    error
}

func (r *recordingObserver) Record(_ context.Context, event Event) error {
	r.events = append(r.events, event)
	return r.err
}

func TestSchedulerRoutesDeterministically(t *testing.T) {
	t.Parallel()

	const (
		localID  computer.ID = "local-a"
		dockerID computer.ID = "docker-a"
		sshID    computer.ID = "ssh-a"
	)

	computers := []computer.Computer{
		&fakeComputer{id: sshID, backend: computer.BackendSSH, state: computer.StateActive},
		&fakeComputer{id: dockerID, backend: computer.BackendDocker, state: computer.StateActive},
		&fakeComputer{id: localID, backend: computer.BackendLocal, state: computer.StateActive},
	}
	profiles := []Profile{
		{ComputerID: localID, Capabilities: []string{"*"}, Scopes: []Scope{ScopeWorkspace, ScopeHost}},
		{ComputerID: dockerID, Capabilities: []string{"*"}, Scopes: []Scope{ScopeWorkspace, ScopeIsolated}},
		{ComputerID: sshID, Capabilities: []string{"*"}, Scopes: []Scope{ScopeRemote}},
	}
	scheduler, err := New(fakeInventory{computers: computers}, profiles, nil)
	require.NoError(t, err)

	tests := []struct {
		name         string
		capabilities []string
		scope        Scope
		risk         *security.RiskAssessment
		wantID       computer.ID
	}{
		{
			name:         "read-only workspace prefers local",
			capabilities: []string{security.CapabilityFileRead},
			scope:        ScopeWorkspace,
			risk:         lowRisk(),
			wantID:       localID,
		},
		{
			name:         "mutating workspace prefers docker",
			capabilities: []string{security.CapabilityFileWrite},
			scope:        ScopeWorkspace,
			risk:         lowRisk(),
			wantID:       dockerID,
		},
		{
			name:         "approved elevated risk prefers docker",
			capabilities: []string{security.CapabilityShellReadOnly},
			scope:        ScopeWorkspace,
			risk: &security.RiskAssessment{
				Score:  65,
				Level:  security.RiskLevelHigh,
				Action: security.RiskActionAdminReview,
			},
			wantID: dockerID,
		},
		{
			name:         "remote scope selects ssh",
			capabilities: []string{security.CapabilityLogRead},
			scope:        ScopeRemote,
			risk:         lowRisk(),
			wantID:       sshID,
		},
		{
			name:         "isolated scope selects docker",
			capabilities: []string{security.CapabilitySecurityScan},
			scope:        ScopeIsolated,
			risk:         lowRisk(),
			wantID:       dockerID,
		},
		{
			name:         "host scope selects local",
			capabilities: []string{security.CapabilityProcessQuery},
			scope:        ScopeHost,
			risk:         lowRisk(),
			wantID:       localID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decision, scheduleErr := scheduler.Schedule(context.Background(), Request{
				RequestID:    tt.name,
				Capabilities: tt.capabilities,
				Scope:        tt.scope,
				Authorization: Authorization{
					Decision: permission.DecisionAutoApprove,
					Approved: true,
				},
				Risk: tt.risk,
			})
			require.NoError(t, scheduleErr)
			require.Equal(t, OutcomeSelected, decision.Outcome)
			require.Equal(t, tt.wantID, decision.ComputerID)
			require.NotEmpty(t, decision.Reasons)
		})
	}
}

func TestSchedulerFailsClosed(t *testing.T) {
	t.Parallel()

	const localID computer.ID = "local-a"
	tests := []struct {
		name        string
		request     Request
		wantOutcome Outcome
		wantError   error
	}{
		{
			name: "permission denied",
			request: baseRequest(Authorization{
				Decision: permission.DecisionDeny,
			}),
			wantOutcome: OutcomeDenied,
			wantError:   ErrPermissionDenied,
		},
		{
			name: "confirmation pending",
			request: baseRequest(Authorization{
				Decision: permission.DecisionUserConfirm,
			}),
			wantOutcome: OutcomePending,
			wantError:   ErrAuthorizationRequired,
		},
		{
			name: "risk blocked",
			request: Request{
				RequestID:    "blocked",
				Capabilities: []string{security.CapabilityFileRead},
				Scope:        ScopeWorkspace,
				Authorization: Authorization{
					Decision: permission.DecisionAutoApprove,
					Approved: true,
				},
				Risk: &security.RiskAssessment{Score: 90, Level: security.RiskLevelCritical, Action: security.RiskActionBlock},
			},
			wantOutcome: OutcomeBlocked,
			wantError:   ErrRiskBlocked,
		},
		{
			name: "unsupported capability",
			request: Request{
				RequestID:    "unsupported",
				Capabilities: []string{security.CapabilityFileWrite},
				Scope:        ScopeWorkspace,
				Authorization: Authorization{
					Decision: permission.DecisionAutoApprove,
					Approved: true,
				},
				Risk: lowRisk(),
			},
			wantOutcome: OutcomeNoCandidate,
			wantError:   ErrNoCandidate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			observer := &recordingObserver{}
			scheduler, err := New(
				fakeInventory{computers: []computer.Computer{
					&fakeComputer{id: localID, backend: computer.BackendLocal, state: computer.StateActive},
				}},
				[]Profile{{ComputerID: localID, Capabilities: []string{security.CapabilityFileRead}, Scopes: []Scope{ScopeWorkspace}}},
				observer,
			)
			require.NoError(t, err)

			decision, scheduleErr := scheduler.Schedule(context.Background(), tt.request)
			require.ErrorIs(t, scheduleErr, tt.wantError)
			require.Equal(t, tt.wantOutcome, decision.Outcome)
			require.Empty(t, decision.ComputerID)
			require.Len(t, observer.events, 1)
		})
	}
}

func TestSchedulerExcludesUnavailableAndSortsByID(t *testing.T) {
	t.Parallel()

	computers := []computer.Computer{
		&fakeComputer{id: "docker-z", backend: computer.BackendDocker, state: computer.StateActive},
		&fakeComputer{id: "docker-a", backend: computer.BackendDocker, state: computer.StateCompleted},
		&fakeComputer{id: "docker-destroyed", backend: computer.BackendDocker, state: computer.StateDestroyed},
		&fakeComputer{id: "docker-suspended", backend: computer.BackendDocker, state: computer.StateSuspended},
	}
	profiles := make([]Profile, 0, len(computers))
	for _, candidate := range computers {
		profiles = append(profiles, Profile{
			ComputerID:   candidate.ID(),
			Capabilities: []string{"*"},
			Scopes:       []Scope{ScopeWorkspace},
		})
	}
	scheduler, err := New(fakeInventory{computers: computers}, profiles, nil)
	require.NoError(t, err)

	decision, err := scheduler.Schedule(context.Background(), Request{
		RequestID:    "stable-order",
		Capabilities: []string{security.CapabilityFileWrite},
		Scope:        ScopeWorkspace,
		Authorization: Authorization{
			Decision: permission.DecisionAutoApprove,
			Approved: true,
		},
		Risk: lowRisk(),
	})
	require.NoError(t, err)
	require.Equal(t, computer.ID("docker-a"), decision.ComputerID)
}

func TestSchedulerAuditFailureFailsClosed(t *testing.T) {
	t.Parallel()

	const localID computer.ID = "local-a"
	observer := &recordingObserver{err: errors.New("audit unavailable")}
	scheduler, err := New(
		fakeInventory{computers: []computer.Computer{
			&fakeComputer{id: localID, backend: computer.BackendLocal, state: computer.StateActive},
		}},
		[]Profile{{ComputerID: localID, Capabilities: []string{"*"}, Scopes: []Scope{ScopeWorkspace}}},
		observer,
	)
	require.NoError(t, err)

	decision, scheduleErr := scheduler.Schedule(context.Background(), baseRequest(Authorization{
		Decision: permission.DecisionAutoApprove,
		Approved: true,
	}))
	require.ErrorIs(t, scheduleErr, ErrAuditFailed)
	require.Empty(t, decision.ComputerID)
}

func lowRisk() *security.RiskAssessment {
	return &security.RiskAssessment{
		Score:  10,
		Level:  security.RiskLevelLow,
		Action: security.RiskActionAutoApprove,
	}
}

func baseRequest(authorization Authorization) Request {
	return Request{
		RequestID:     "request",
		Capabilities:  []string{security.CapabilityFileRead},
		Scope:         ScopeWorkspace,
		Authorization: authorization,
		Risk:          lowRisk(),
	}
}
