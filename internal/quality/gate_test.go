package quality

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecurityQualityGateTargets(t *testing.T) {
	t.Parallel()
	passing := Metrics{
		HighRiskEvidenceRate: 1, CoreTaskCompletionRate: 0.85, UnsupportedConclusionRate: 0.02,
		HighRiskCheckerRate: 1, CrashRecoveryRate: 0.95, CoreSkillContractRate: 1, CrossPlatformPassRate: 1,
	}
	result := Evaluate(passing)
	require.True(t, result.Passed)
	require.NoError(t, result.Error())

	failing := Metrics{}
	failing.UnsupportedConclusionRate = 1
	failing.UnauthorizedHighRiskOps = 1
	failing.DuplicateSideEffects = 1
	failing.PromptInjectionBreakthroughs = 1
	result = Evaluate(failing)
	require.False(t, result.Passed)
	require.Len(t, result.Failures, 10)
	require.Error(t, result.Error())
}

func TestReleasePolicyDefaultsToReadOnlyAndFailsClosed(t *testing.T) {
	t.Parallel()
	policy := DefaultReleasePolicy()
	require.True(t, policy.Allows(ActionReadOnlyInvestigation, false, false))
	require.False(t, policy.Allows(ActionApprovedResponse, true, false))
	require.False(t, policy.Allows(ActionAutomaticResponse, true, false))
	require.False(t, policy.Allows(ActionRedTeam, true, true))
	require.False(t, policy.Allows("unknown", true, true))
}

func TestReleasePolicyRequiresApprovalSignedScopeAndSupportsRollback(t *testing.T) {
	t.Parallel()
	policy := ReleasePolicy{ReadOnlyInvestigation: true, ApprovedResponse: true, AutomaticResponse: true, RedTeam: true}
	require.False(t, policy.Allows(ActionApprovedResponse, false, false))
	require.True(t, policy.Allows(ActionApprovedResponse, true, false))
	require.False(t, policy.Allows(ActionRedTeam, true, false))
	require.True(t, policy.Allows(ActionRedTeam, true, true))
	policy.EmergencyRollback = true
	require.True(t, policy.Allows(ActionReadOnlyInvestigation, false, false))
	require.False(t, policy.Allows(ActionApprovedResponse, true, false))
	require.False(t, policy.Allows(ActionAutomaticResponse, true, false))
	require.False(t, policy.Allows(ActionRedTeam, true, true))
}
