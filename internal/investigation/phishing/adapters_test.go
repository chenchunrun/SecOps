package phishing

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/evidence"
)

func TestProductionWorkflowPersistsEvidenceAndAuditReferences(t *testing.T) {
	t.Parallel()
	store, err := evidence.NewFileStore(t.TempDir())
	require.NoError(t, err)
	auditStore := audit.NewInMemoryAuditStore()
	workflow, err := NewProductionWorkflow(store, auditStore, nil, time.Second)
	require.NoError(t, err)

	report, err := workflow.Run(context.Background(), validInput("task-production", "Review https://example.test safely"))
	require.NoError(t, err)
	require.Equal(t, evidence.VerdictPassed, report.Verification.Verdict)
	events, err := auditStore.ListEvents(&audit.AuditFilter{ResourceName: "task-production"})
	require.NoError(t, err)
	require.Len(t, events, 2)
	require.Equal(t, report.Finding.ID, events[1].Details["finding_id"])
	require.Equal(t, string(report.Verification.Verdict), events[1].Details["verification_verdict"])
}

func TestEvidenceCheckerRejectsTamperedPayload(t *testing.T) {
	t.Parallel()
	store, err := evidence.NewFileStore(t.TempDir())
	require.NoError(t, err)
	checker, err := NewEvidenceChecker(store)
	require.NoError(t, err)

	result, err := checker.Check(context.Background(), CheckRequest{
		TaskID: "task-missing", Finding: evidence.Finding{TaskID: "task-missing"}, EvidenceIDs: []string{"missing"},
	})
	require.NoError(t, err)
	require.Equal(t, evidence.VerdictRejected, result.Verdict)
}
