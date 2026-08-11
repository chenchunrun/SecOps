package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/taskruntime"
)

func TestNewConfiguredProtectedScheduledTaskRuntimeWiresAuditedExecution(t *testing.T) {
	t.Setenv("SECOPS_GITHUB_TOKEN", "configured-secret")

	directory := t.TempDir()
	configPath := filepath.Join(directory, "egress.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{
  "rules": [{
    "id": "github-api",
    "protocol": "https",
    "host": "api.github.com",
    "ports": [443],
    "credential_refs": ["github/actions"]
  }],
  "credential_environment": {"github/actions": "SECOPS_GITHUB_TOKEN"},
  "max_credential_ttl": "1m",
  "audit_path": "audit/egress.jsonl"
}`), 0o600))

	computerRuntime, runtimeScheduler, machine := newProtectedTestRuntime(t, "configured-secret")
	protectedRuntime, err := NewConfiguredProtectedScheduledTaskRuntime(
		computerRuntime,
		runtimeScheduler,
		configPath,
	)
	require.NoError(t, err)

	result, err := protectedRuntime.SubmitAndRun(context.Background(), validProtectedSubmission("configured-task"))
	require.NoError(t, err)
	require.Equal(t, taskruntime.StateSucceeded, result.Task.State)
	require.Equal(t, "configured-secret", machine.request.Config.Environment["GITHUB_TOKEN"])

	auditData, err := os.ReadFile(filepath.Join(directory, "audit", "egress.jsonl"))
	require.NoError(t, err)
	require.Contains(t, string(auditData), `"request_id":"configured-task"`)
	require.NotContains(t, string(auditData), "configured-secret")
}
