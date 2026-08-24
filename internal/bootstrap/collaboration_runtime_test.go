package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/collaboration"
)

func TestHandoffStoreSurvivesRuntimeRestart(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	runtime, err := newComputerRuntime(context.Background(), root)
	require.NoError(t, err)
	require.NotNil(t, runtime.HandoffStore)
	envelope := collaboration.HandoffEnvelope{
		ID: "restart-handoff", TaskID: "restart-task",
		Producer: "planner", ProducerRole: collaboration.RolePlanner,
		Consumer: "security", ConsumerRole: collaboration.RoleSecurity,
		Objective: "Investigate the referenced evidence.", EvidenceIDs: []string{"evidence-1"},
		RequiredCapabilities: []string{"evidence:read"}, ExpectedOutputSchema: "finding-v1",
	}
	require.NoError(t, runtime.HandoffStore.Publish(context.Background(), envelope))

	reopened, err := newComputerRuntime(context.Background(), root)
	require.NoError(t, err)
	loaded, err := reopened.HandoffStore.Get(context.Background(), envelope.ID)
	require.NoError(t, err)
	require.Equal(t, envelope.ID, loaded.ID)
}
