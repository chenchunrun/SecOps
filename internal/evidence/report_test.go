package evidence

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHighRiskReportRequiresVerificationAndReplaysRawEvidence(t *testing.T) {
	t.Parallel()
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	item, err := store.PutEvidence(context.Background(), validEvidence("report-evidence", "report-task", CompletenessComplete), []byte("raw mail payload"))
	require.NoError(t, err)
	require.NoError(t, store.PutFact(context.Background(), Fact{
		ID: "report-fact", TaskID: "report-task", Statement: "A login URL is present.", EvidenceIDs: []string{item.ID},
	}))
	require.NoError(t, store.PutInference(context.Background(), Inference{
		ID: "report-inference", TaskID: "report-task", Statement: "The message may be credential phishing.",
		FactIDs: []string{"report-fact"}, Confidence: 0.8, Alternatives: []string{"benign training simulation"},
	}))
	require.NoError(t, store.PutFinding(context.Background(), Finding{
		ID: "report-finding", TaskID: "report-task", MakerID: "maker", Severity: SeverityHigh,
		FactIDs: []string{"report-fact"}, InferenceIDs: []string{"report-inference"},
		Recommendation: "Quarantine pending identity validation.",
	}))

	_, err = store.BuildReport(context.Background(), "report-finding")
	require.ErrorIs(t, err, ErrIncomplete)
	require.NoError(t, store.VerifyFinding(context.Background(), Verification{
		FindingID: "report-finding", TaskID: "report-task", CheckerID: "checker",
		Verdict: VerdictPassed, EvidenceIDs: []string{item.ID}, Reason: "evidence confirmed",
	}))

	bundle, err := store.ReplayFinding(context.Background(), "report-finding")
	require.NoError(t, err)
	require.Equal(t, "A login URL is present.", bundle.Report.Facts[0].Statement)
	require.Equal(t, "The message may be credential phishing.", bundle.Report.Inferences[0].Statement)
	require.Equal(t, "Quarantine pending identity validation.", bundle.Report.Finding.Recommendation)
	require.Equal(t, VerdictPassed, bundle.Report.Verification.Verdict)
	require.Equal(t, []byte("raw mail payload"), bundle.RawEvidence[item.ID])
}

func TestReportRejectsCrossTaskInference(t *testing.T) {
	t.Parallel()
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	item, err := store.PutEvidence(context.Background(), validEvidence("cross-evidence", "task-a", CompletenessComplete), []byte("raw"))
	require.NoError(t, err)
	require.NoError(t, store.PutFact(context.Background(), Fact{ID: "cross-fact", TaskID: "task-a", Statement: "fact", EvidenceIDs: []string{item.ID}}))
	err = store.PutInference(context.Background(), Inference{ID: "cross-inference", TaskID: "task-b", Statement: "inference", FactIDs: []string{"cross-fact"}, Confidence: 0.5})
	require.ErrorIs(t, err, ErrTaskMismatch)
}
