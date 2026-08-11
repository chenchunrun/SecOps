package verification

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
)

func TestMakerAndCheckerSurviveRuntimeRestart(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store, err := NewFileStore(root)
	require.NoError(t, err)
	maker, err := NewMaker(store)
	require.NoError(t, err)

	evidence, err := maker.Make(context.Background(), Request{
		ID:         "verify-build-1",
		TaskID:     "task-build-1",
		ComputerID: computer.ID("docker-build"),
		Requirements: []Requirement{
			{Kind: "test-report", Minimum: 1},
			{Kind: "build-log", Minimum: 1},
		},
	}, []Artifact{
		{Kind: "test-report", Source: "go-test", Payload: []byte("PASS\n")},
		{Kind: "build-log", Source: "go-build", Payload: []byte("build complete\n")},
	})
	require.NoError(t, err)
	require.Len(t, evidence, 2)
	require.NotEmpty(t, evidence[0].Digest)
	require.NotEmpty(t, evidence[0].Locator)
	require.NotContains(t, evidence[0].Locator, root)

	reopened, err := NewFileStore(root)
	require.NoError(t, err)
	checker, err := NewChecker(reopened)
	require.NoError(t, err)
	result, err := checker.Check(context.Background(), "verify-build-1")
	require.NoError(t, err)
	require.Equal(t, VerdictPassed, result.Verdict)
	require.Empty(t, result.Findings)
	require.Len(t, result.EvidenceIDs, 2)

	persisted, err := reopened.GetResult(context.Background(), "verify-build-1")
	require.NoError(t, err)
	require.Equal(t, result, persisted)
}

func TestCheckerFailsWhenRequiredEvidenceIsMissing(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	maker, err := NewMaker(store)
	require.NoError(t, err)
	_, err = maker.Make(context.Background(), Request{
		ID:           "verify-missing",
		TaskID:       "task-missing",
		ComputerID:   "local-default",
		Requirements: []Requirement{{Kind: "test-report", Minimum: 2}},
	}, []Artifact{{Kind: "test-report", Source: "go-test", Payload: []byte("one report")}})
	require.NoError(t, err)
	checker, err := NewChecker(store)
	require.NoError(t, err)

	result, err := checker.Check(context.Background(), "verify-missing")
	require.NoError(t, err)
	require.Equal(t, VerdictFailed, result.Verdict)
	require.Equal(t, []Finding{{Code: FindingMissingEvidence, Requirement: "test-report", Message: "required 2 evidence item(s), found 1"}}, result.Findings)
}

func TestCheckerFailsClosedWhenEvidencePayloadIsTampered(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	maker, err := NewMaker(store)
	require.NoError(t, err)
	evidence, err := maker.Make(context.Background(), Request{
		ID:           "verify-tampered",
		TaskID:       "task-tampered",
		ComputerID:   "ssh-default",
		Requirements: []Requirement{{Kind: "service-log", Minimum: 1}},
	}, []Artifact{{Kind: "service-log", Source: "ssh", Payload: []byte("healthy")}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(store.payloadPath(evidence[0].Locator), []byte("modified"), 0o600))
	checker, err := NewChecker(store)
	require.NoError(t, err)

	result, err := checker.Check(context.Background(), "verify-tampered")
	require.NoError(t, err)
	require.Equal(t, VerdictFailed, result.Verdict)
	require.Equal(t, FindingIntegrityFailure, result.Findings[0].Code)
	require.Equal(t, evidence[0].ID, result.Findings[0].EvidenceID)
}

func TestMakerRejectsInvalidBatchWithoutVisiblePartialState(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	maker, err := NewMaker(store)
	require.NoError(t, err)

	evidence, err := maker.Make(context.Background(), Request{
		ID:           "../escape",
		TaskID:       "task-invalid",
		ComputerID:   "local-default",
		Requirements: []Requirement{{Kind: "report", Minimum: 1}},
	}, []Artifact{{Kind: "report", Source: "test", Payload: []byte("payload")}})
	require.ErrorIs(t, err, ErrInvalidRequest)
	require.Nil(t, evidence)
	_, err = store.GetRequest(context.Background(), "../escape")
	require.ErrorIs(t, err, ErrNotFound)

	evidence, err = maker.Make(context.Background(), Request{
		ID:           "verify-invalid-artifact",
		TaskID:       "task-invalid-artifact",
		ComputerID:   "local-default",
		Requirements: []Requirement{{Kind: "report", Minimum: 1}},
	}, []Artifact{
		{Kind: "report", Source: "test", Payload: []byte("valid")},
		{Kind: "../escape", Source: "test", Payload: []byte("invalid")},
	})
	require.ErrorIs(t, err, ErrInvalidEvidence)
	require.Nil(t, evidence)
	_, err = store.GetRequest(context.Background(), "verify-invalid-artifact")
	require.ErrorIs(t, err, ErrNotFound)
	listed, err := store.ListEvidence(context.Background(), "verify-invalid-artifact")
	require.NoError(t, err)
	require.Empty(t, listed)
}

func TestVerificationRecordsAreImmutable(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	maker, err := NewMaker(store)
	require.NoError(t, err)
	request := Request{
		ID:           "verify-immutable",
		TaskID:       "task-immutable",
		ComputerID:   "local-default",
		Requirements: []Requirement{{Kind: "report", Minimum: 1}},
	}
	_, err = maker.Make(context.Background(), request, []Artifact{{Kind: "report", Source: "test", Payload: []byte("first")}})
	require.NoError(t, err)
	_, err = maker.Make(context.Background(), request, []Artifact{{Kind: "report", Source: "test", Payload: []byte("second")}})
	require.ErrorIs(t, err, ErrAlreadyExists)
}
