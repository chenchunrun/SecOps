package evidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEvidenceStoreRejectsInvalidReferences(t *testing.T) {
	t.Parallel()
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	err = store.PutFact(context.Background(), Fact{ID: "fact-missing", TaskID: "task-a", Statement: "missing", EvidenceIDs: []string{"missing"}})
	require.ErrorIs(t, err, ErrNotFound)

	item, err := store.PutEvidence(context.Background(), validEvidence("evidence-a", "task-a", CompletenessComplete), []byte("payload"))
	require.NoError(t, err)
	err = store.PutFact(context.Background(), Fact{ID: "fact-cross-task", TaskID: "task-b", Statement: "cross task", EvidenceIDs: []string{item.ID}})
	require.ErrorIs(t, err, ErrTaskMismatch)
}

func TestEvidenceStoreRejectsTamperedAndIncompleteEvidence(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := NewFileStore(root)
	require.NoError(t, err)

	truncated, err := store.PutEvidence(context.Background(), validEvidence("evidence-truncated", "task-a", CompletenessTruncated), []byte("partial"))
	require.NoError(t, err)
	err = store.PutFact(context.Background(), Fact{ID: "fact-truncated", TaskID: "task-a", Statement: "unsupported", EvidenceIDs: []string{truncated.ID}})
	require.ErrorIs(t, err, ErrIncomplete)

	complete, err := store.PutEvidence(context.Background(), validEvidence("evidence-complete", "task-a", CompletenessComplete), []byte("original"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "raw", complete.RawReference), []byte("tampered"), 0o600))
	_, _, err = store.GetEvidence(context.Background(), complete.ID)
	require.ErrorIs(t, err, ErrIntegrity)
}

func TestHighRiskFindingRequiresIndependentCheckerAndEvidence(t *testing.T) {
	t.Parallel()
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	item, err := store.PutEvidence(context.Background(), validEvidence("evidence-mail", "task-phishing", CompletenessComplete), []byte("mail"))
	require.NoError(t, err)
	require.NoError(t, store.PutFact(context.Background(), Fact{ID: "fact-mail", TaskID: "task-phishing", Statement: "credential harvesting URL observed", EvidenceIDs: []string{item.ID}}))
	require.NoError(t, store.PutFinding(context.Background(), Finding{
		ID: "finding-phishing", TaskID: "task-phishing", MakerID: "security-maker", Severity: SeverityHigh,
		FactIDs: []string{"fact-mail"}, Recommendation: "Block the URL and reset exposed credentials.",
	}))

	err = store.VerifyFinding(context.Background(), Verification{
		FindingID: "finding-phishing", TaskID: "task-phishing", CheckerID: "security-maker",
		Verdict: VerdictPassed, EvidenceIDs: []string{item.ID}, Reason: "confirmed",
	})
	require.ErrorIs(t, err, ErrCheckerNotIsolated)

	err = store.VerifyFinding(context.Background(), Verification{
		FindingID: "finding-phishing", TaskID: "task-phishing", CheckerID: "independent-checker",
		Verdict: VerdictPassed, Reason: "unsupported",
	})
	require.ErrorIs(t, err, ErrIncomplete)

	require.NoError(t, store.VerifyFinding(context.Background(), Verification{
		FindingID: "finding-phishing", TaskID: "task-phishing", CheckerID: "independent-checker",
		Verdict: VerdictPassed, EvidenceIDs: []string{item.ID}, Reason: "raw message supports the fact",
	}))
	persisted, err := store.GetVerification(context.Background(), "finding-phishing")
	require.NoError(t, err)
	require.Equal(t, VerdictPassed, persisted.Verdict)
}

func validEvidence(id, taskID string, completeness Completeness) Evidence {
	return Evidence{
		ID: id, TaskID: taskID, Source: EvidenceSource{Type: "email", Reference: "fixture.eml"},
		Summary: "Email investigation artifact", TrustLevel: TrustUntrusted, Completeness: completeness,
	}
}
