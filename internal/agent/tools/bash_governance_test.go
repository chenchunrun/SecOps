package tools

import (
	"slices"
	"testing"

	"github.com/chenchunrun/SecOps/internal/policy"
	"github.com/chenchunrun/SecOps/internal/security"
	"github.com/chenchunrun/SecOps/internal/shell"
	"github.com/stretchr/testify/require"
)

// TestBashBannedCommands_IncludesDestructive verifies the bash hard blocklist is
// unified with the risk assessor's banned set, so destructive system commands
// (rm/dd/reboot/shutdown/halt) are hard-blocked and cannot slip through under
// YOLO mode.
func TestBashBannedCommands_IncludesDestructive(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{"rm", "dd", "reboot", "shutdown", "halt"} {
		require.True(t, slices.Contains(bannedCommands, cmd), "expected %q in bash banned list", cmd)
	}

	blocker := shell.CommandsBlocker(bannedCommands)
	require.True(t, blocker([]string{"rm", "-rf", "/"}), "rm must be blocked")
	require.True(t, blocker([]string{"/sbin/reboot"}), "absolute-path reboot must be blocked")
	require.True(t, blocker([]string{"sudo", "dd", "if=/dev/zero"}), "wrapped dd must be blocked")
}

// TestBashPolicy_RiskHardBlock verifies a command scoring at/above the block
// threshold is denied by the policy evaluator regardless of the interactive
// permission layer (YOLO/allow-list cannot override a hard policy deny).
func TestBashPolicy_RiskHardBlock(t *testing.T) {
	t.Parallel()
	eval := newBashPolicyEvaluator()
	// banned(rm)=40 + sensitive_path(/etc/shadow)=25 + credential=50 => >=80.
	decision, err := eval.EvaluateBash(t.Context(), policy.Request{
		PolicyKind: "bash",
		ToolName:   BashToolName,
		Action:     "execute",
		Parameters: bashPolicyContext{
			Params: BashParams{Command: "rm /etc/shadow password=TopSecret123"},
		},
	})
	require.NoError(t, err)
	require.False(t, decision.Allowed, "high-risk command must be hard-denied by policy")
	require.Equal(t, "risk", decision.AuditFields["policy_type"])
}

// Sanity check that the assessor classifies the sample command as a block.
func TestRiskAssessor_BlocksHighScore(t *testing.T) {
	t.Parallel()
	a := security.NewRiskAssessor()
	got := a.AssessCommand("rm /etc/shadow password=TopSecret123")
	require.Equal(t, security.RiskActionBlock, got.Action)
}
