package workbench

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWorkbenchCorrelatesStateAndMetrics(t *testing.T) {
	t.Parallel()
	controller := &fakeController{}
	workbench := New(controller)
	require.NoError(t, workbench.UpsertTask(Task{ID: "task-1", Title: "Investigate", State: "running", CurrentAgent: "security"}))
	require.NoError(t, workbench.AddEvidence(EvidenceItem{ID: "evidence-1", TaskID: "task-1", Source: "host", Trust: "high", Completeness: "complete", ContentHash: "sha256:x"}))
	require.NoError(t, workbench.AddApproval(Approval{ID: "approval-1", TaskID: "task-1", Action: "host_isolate", Risk: "critical", Target: "server-1", Parameters: map[string]string{"interface": "eth0"}, Status: "pending"}))
	require.NoError(t, workbench.AddVerification(Verification{FindingID: "finding-1", TaskID: "task-1", CheckerID: "checker", Verdict: "needs_evidence", Reason: "missing post state"}))
	workbench.Observe(func(metrics *Metrics) {
		metrics.TasksStarted++
		metrics.TasksSucceeded++
		metrics.ModelTokens += 100
		metrics.PermissionDenials++
	})
	snapshot := workbench.Snapshot()
	require.Len(t, snapshot.Tasks, 1)
	require.Len(t, snapshot.Evidence, 1)
	require.Len(t, snapshot.Approvals, 1)
	require.Len(t, snapshot.Verifications, 1)
	require.Equal(t, 1.0, snapshot.Metrics.TaskSuccessRate())
	require.Equal(t, 1.0, snapshot.Metrics.EvidenceCompletenessRate())
	require.Equal(t, int64(1), snapshot.Metrics.CheckerRejections)

	require.NoError(t, workbench.Pause(context.Background(), "task-1"))
	require.NoError(t, workbench.Resume(context.Background(), "task-1"))
	require.NoError(t, workbench.Cancel(context.Background(), "task-1"))
	require.Equal(t, []string{"pause:task-1", "resume:task-1", "cancel:task-1"}, controller.calls)
}

type fakeController struct{ calls []string }

func (f *fakeController) Pause(_ context.Context, id string) error {
	f.calls = append(f.calls, "pause:"+id)
	return nil
}
func (f *fakeController) Resume(_ context.Context, id string) error {
	f.calls = append(f.calls, "resume:"+id)
	return nil
}
func (f *fakeController) Cancel(_ context.Context, id string) error {
	f.calls = append(f.calls, "cancel:"+id)
	return nil
}
