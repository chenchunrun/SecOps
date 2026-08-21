package scenarios

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/evidence"
)

func TestAttackSurfaceRequiresSignedImmutableScope(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	scope := validScope()
	signed, err := SignAuthorizationScope(scope, privateKey)
	require.NoError(t, err)
	signed.Scope.Ports = append(signed.Scope.Ports, 22)
	workflow := newAttackWorkflow(t, &fakeAttackProbe{}, &fakeKillSwitch{})
	_, err = workflow.Run(context.Background(), validAttackInput(publicKey, signed))
	require.ErrorContains(t, err, "signature is invalid")
}

func TestAttackSurfaceRejectsOutOfScopeAndKillSwitch(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signed, err := SignAuthorizationScope(validScope(), privateKey)
	require.NoError(t, err)
	input := validAttackInput(publicKey, signed)
	input.Target = AttackTarget{Host: "outside.example", Port: 443}
	workflow := newAttackWorkflow(t, &fakeAttackProbe{}, &fakeKillSwitch{})
	_, err = workflow.Run(context.Background(), input)
	require.ErrorContains(t, err, "outside signed")

	input = validAttackInput(publicKey, signed)
	workflow = newAttackWorkflow(t, &fakeAttackProbe{}, &fakeKillSwitch{triggered: true})
	_, err = workflow.Run(context.Background(), input)
	require.ErrorContains(t, err, "kill switch")
}

func TestAttackSurfaceUsesEphemeralNonDestructiveProbeAndRetest(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signed, err := SignAuthorizationScope(validScope(), privateKey)
	require.NoError(t, err)
	probe := &fakeAttackProbe{
		probeResult:  ProbeResult{Confirmed: true, AttackPath: "public endpoint to admin API", Raw: []byte("confirmed path")},
		retestResult: ProbeResult{Confirmed: false, Raw: []byte("path closed")},
	}
	workflow := newAttackWorkflow(t, probe, &fakeKillSwitch{})
	input := validAttackInput(publicKey, signed)
	input.Retest = true
	report, err := workflow.Run(context.Background(), input)
	require.NoError(t, err)
	require.True(t, report.Confirmed)
	require.True(t, report.Retested)
	require.Len(t, report.EvidenceIDs, 2)
	require.Equal(t, evidence.VerdictPassed, report.Verification)
	require.True(t, probe.lastProbe.Ephemeral)
	require.False(t, probe.lastProbe.Destructive)
}

func validScope() AuthorizationScope {
	return AuthorizationScope{
		ID: "scope-1", Domains: []string{"authorized.example"}, CIDRs: []string{"192.0.2.0/24"}, Ports: []int{443},
		ValidFrom: time.Now().Add(-time.Minute), ValidUntil: time.Now().Add(time.Hour), AllowActiveValidation: true,
	}
}

func validAttackInput(publicKey ed25519.PublicKey, scope SignedScope) AttackSurfaceInput {
	return AttackSurfaceInput{
		TaskID: "attack-task", Target: AttackTarget{Host: "api.authorized.example", Port: 443},
		Scope: scope, PublicKey: publicKey, MakerID: "maker", CheckerID: "checker", Active: true,
	}
}

func newAttackWorkflow(t *testing.T, probe AttackSurfaceProbe, killSwitch KillSwitch) *AttackSurfaceWorkflow {
	t.Helper()
	store, err := evidence.NewFileStore(t.TempDir())
	require.NoError(t, err)
	workflow, err := NewAttackSurfaceWorkflow(store, probe, killSwitch, &fakeScenarioAuditor{})
	require.NoError(t, err)
	return workflow
}

type fakeAttackProbe struct {
	probeResult  ProbeResult
	retestResult ProbeResult
	lastProbe    ProbeRequest
}

func (f *fakeAttackProbe) Probe(_ context.Context, request ProbeRequest) (ProbeResult, error) {
	f.lastProbe = request
	return f.probeResult, nil
}

func (f *fakeAttackProbe) Retest(_ context.Context, request ProbeRequest) (ProbeResult, error) {
	f.lastProbe = request
	return f.retestResult, nil
}

type fakeKillSwitch struct{ triggered bool }

func (f *fakeKillSwitch) Triggered() bool { return f.triggered }
