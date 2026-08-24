package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/evidence"
)

func TestEvidenceStoreSurvivesComputerRuntimeRestart(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	runtime, err := newComputerRuntime(context.Background(), root)
	require.NoError(t, err)
	require.NotNil(t, runtime.EvidenceStore)

	created, err := runtime.EvidenceStore.PutEvidence(context.Background(), evidence.Evidence{
		ID: "restart-evidence", TaskID: "restart-task",
		Source:  evidence.EvidenceSource{Type: "test", Reference: "fixture"},
		Summary: "restart fixture", TrustLevel: evidence.TrustHigh,
		Completeness: evidence.CompletenessComplete,
	}, []byte("persistent payload"))
	require.NoError(t, err)

	reopened, err := newComputerRuntime(context.Background(), root)
	require.NoError(t, err)
	loaded, payload, err := reopened.EvidenceStore.GetEvidence(context.Background(), created.ID)
	require.NoError(t, err)
	require.Equal(t, created, loaded)
	require.Equal(t, []byte("persistent payload"), payload)
}
