package scenarios

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/evidence"
)

func TestHostIRUsesReadOnlyPlatformAdapters(t *testing.T) {
	t.Parallel()
	for _, platform := range []string{"linux", "darwin", "windows"} {
		platform := platform
		t.Run(platform, func(t *testing.T) {
			t.Parallel()
			store, err := evidence.NewFileStore(t.TempDir())
			require.NoError(t, err)
			adapter := &fakeHostAdapter{snapshots: []HostSnapshot{{Suspicious: true}}}
			workflow, err := NewHostIRWorkflow(store, adapter, &fakeScenarioAuditor{})
			require.NoError(t, err)
			report, err := workflow.Run(context.Background(), HostIRInput{
				TaskID: "host-" + platform, Target: "server-1", Platform: platform,
				MakerID: "maker", CheckerID: "checker",
			})
			require.NoError(t, err)
			require.Equal(t, evidence.VerdictPassed, report.Verification)
			require.True(t, adapter.requests[0].ReadOnly)
			require.Equal(t, platform, adapter.requests[0].Platform)
			require.Zero(t, adapter.isolations)
		})
	}
}

func TestHostIsolationRequiresApprovalAndPreservesPrePostEvidence(t *testing.T) {
	t.Parallel()
	store, err := evidence.NewFileStore(t.TempDir())
	require.NoError(t, err)
	adapter := &fakeHostAdapter{snapshots: []HostSnapshot{{Suspicious: true}, {Suspicious: false}}}
	auditor := &fakeScenarioAuditor{}
	workflow, err := NewHostIRWorkflow(store, adapter, auditor)
	require.NoError(t, err)
	input := HostIRInput{
		TaskID: "host-approved", Target: "server-2", Platform: "linux", MakerID: "maker", CheckerID: "checker",
		RequestIsolation: true, Approval: &Approval{ID: "approval-1", TaskID: "host-approved", Target: "server-2", ApprovedBy: "operator", ExpiresAt: time.Now().Add(time.Hour)},
	}
	report, err := workflow.Run(context.Background(), input)
	require.NoError(t, err)
	require.True(t, report.IsolationExecuted)
	require.Len(t, report.EvidenceIDs, 2)
	require.Equal(t, 1, adapter.isolations)
	require.Equal(t, 1, auditor.calls)

	_, err = workflow.Run(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, 1, adapter.isolations, "replay must not repeat isolation")
}

func TestHostIsolationFailsClosedOnMissingApprovalOrAuditFailure(t *testing.T) {
	t.Parallel()
	store, err := evidence.NewFileStore(t.TempDir())
	require.NoError(t, err)
	adapter := &fakeHostAdapter{snapshots: []HostSnapshot{{Suspicious: true}}}
	workflow, err := NewHostIRWorkflow(store, adapter, &fakeScenarioAuditor{})
	require.NoError(t, err)
	report, err := workflow.Run(context.Background(), HostIRInput{
		TaskID: "host-no-approval", Target: "server", Platform: "linux", MakerID: "maker", CheckerID: "checker", RequestIsolation: true,
	})
	require.NoError(t, err)
	require.True(t, report.ApprovalRequired)
	require.False(t, report.IsolationExecuted)

	store, err = evidence.NewFileStore(t.TempDir())
	require.NoError(t, err)
	adapter = &fakeHostAdapter{snapshots: []HostSnapshot{{Suspicious: true}}}
	workflow, err = NewHostIRWorkflow(store, adapter, &fakeScenarioAuditor{err: errors.New("audit unavailable")})
	require.NoError(t, err)
	_, err = workflow.Run(context.Background(), HostIRInput{
		TaskID: "host-audit-failure", Target: "server", Platform: "linux", MakerID: "maker", CheckerID: "checker", RequestIsolation: true,
		Approval: &Approval{ID: "approval", TaskID: "host-audit-failure", Target: "server", ApprovedBy: "operator", ExpiresAt: time.Now().Add(time.Hour)},
	})
	require.ErrorContains(t, err, "audit host isolation")
	require.Zero(t, adapter.isolations)
}

type fakeHostAdapter struct {
	mu         sync.Mutex
	snapshots  []HostSnapshot
	requests   []HostCollectionRequest
	isolations int
}

func (f *fakeHostAdapter) Collect(_ context.Context, request HostCollectionRequest) (HostSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, request)
	if len(f.snapshots) == 0 {
		return HostSnapshot{}, errors.New("no snapshot")
	}
	snapshot := f.snapshots[0]
	if len(f.snapshots) > 1 {
		f.snapshots = f.snapshots[1:]
	}
	return snapshot, nil
}

func (f *fakeHostAdapter) Isolate(_ context.Context, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.isolations++
	return nil
}

type fakeScenarioAuditor struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (f *fakeScenarioAuditor) Record(_ context.Context, _ ScenarioAuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}
