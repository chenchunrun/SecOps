package workbench

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	workbenchstate "github.com/chenchunrun/SecOps/internal/workbench"
)

func TestWorkbenchViewsExposeOperationalContextWithoutFixedColors(t *testing.T) {
	t.Parallel()
	component := New()
	component.SetSnapshot(workbenchstate.Snapshot{
		Tasks:         []workbenchstate.Task{{ID: "task-1", State: "running", CurrentAgent: "security", CurrentSkill: "linux-ir"}},
		Evidence:      []workbenchstate.EvidenceItem{{ID: "evidence-1", Source: "host", Trust: "high", Completeness: "complete", ContentHash: "sha256:x"}},
		Approvals:     []workbenchstate.Approval{{ID: "approval-1", Risk: "critical", Action: "host_isolate", Target: "server-1", Parameters: map[string]string{"interface": "eth0"}, Status: "pending"}},
		Verifications: []workbenchstate.Verification{{FindingID: "finding-1", CheckerID: "checker", Verdict: "needs_evidence", Reason: "missing post state"}},
	})
	for _, view := range []View{ViewTask, ViewEvidence, ViewApproval, ViewVerification} {
		component.SetView(view)
		rendered := component.Render(200)
		require.Contains(t, rendered, "["+string(view)+"]")
		require.NotContains(t, rendered, "\x1b[")
	}
	component.SetView(ViewApproval)
	rendered := component.Render(200)
	require.Contains(t, rendered, "risk=critical")
	require.Contains(t, rendered, "target=server-1")
	require.Contains(t, rendered, "interface=eth0")
	require.False(t, strings.Contains(rendered, "purple"))
}
