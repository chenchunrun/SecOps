package bootstrap

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/scheduler"
	"github.com/chenchunrun/SecOps/internal/security"
)

func TestNewRuntimeSchedulerSelectsRegisteredDefaultLocalComputer(t *testing.T) {
	t.Parallel()

	runtime, err := newComputerRuntime(context.Background(), t.TempDir())
	require.NoError(t, err)

	runtimeScheduler, err := NewRuntimeScheduler(
		runtime,
		filepath.Join(t.TempDir(), "audit", "scheduler.jsonl"),
	)
	require.NoError(t, err)

	decision, err := runtimeScheduler.Schedule(context.Background(), scheduler.Request{
		RequestID:    "bootstrap-local",
		Capabilities: []string{security.CapabilityFileRead},
		Scope:        scheduler.ScopeWorkspace,
		Authorization: scheduler.Authorization{
			Decision: permission.DecisionAutoApprove,
			Approved: true,
		},
		Risk: &security.RiskAssessment{
			Score:  10,
			Level:  security.RiskLevelLow,
			Action: security.RiskActionAutoApprove,
		},
	})
	require.NoError(t, err)
	require.Equal(t, computer.ID(DefaultLocalComputerID), decision.ComputerID)
	require.Equal(t, computer.BackendLocal, decision.Backend)
}

func TestNewRuntimeSchedulerRejectsNilRuntime(t *testing.T) {
	t.Parallel()

	runtimeScheduler, err := NewRuntimeScheduler(nil, filepath.Join(t.TempDir(), "scheduler.jsonl"))
	require.ErrorIs(t, err, ErrComputerRuntimeRequired)
	require.Nil(t, runtimeScheduler)
}
