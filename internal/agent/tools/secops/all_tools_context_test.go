package secops

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAllBuiltInToolsHonorCanceledContext(t *testing.T) {
	t.Parallel()
	for _, tool := range []SecOpsTool{
		NewLogAnalyzeTool(nil),
		NewMonitoringQueryTool(nil),
		NewComplianceCheckTool(nil),
		NewCertificateAuditTool(nil),
		NewSecurityScanTool(nil),
		NewConfigurationAuditTool(nil),
		NewNetworkDiagnosticTool(nil),
		NewDatabaseQueryTool(nil),
		NewBackupCheckTool(nil),
		NewReplicationStatusTool(nil),
		NewSecretAuditTool(nil),
		NewRotationCheckTool(nil),
		NewAccessReviewTool(nil),
		NewInfrastructureQueryTool(nil),
		NewDeploymentStatusTool(nil),
		NewAlertCheckTool(nil),
		NewIncidentTimelineTool(nil),
		NewResourceMonitorTool(nil),
		NewAttackReasonTool(nil),
		NewIncidentAssessTool(nil),
	} {
		t.Run(string(tool.Type()), func(t *testing.T) {
			t.Parallel()
			contextual, ok := tool.(ContextTool)
			require.True(t, ok, "built-in tools must not use the legacy execution path")
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			result, err := contextual.ExecuteContext(ctx, nil)
			require.ErrorIs(t, err, context.Canceled)
			require.Nil(t, result)
		})
	}
}

func TestResourceSampleWaitHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan struct{})
	go func() { sampleCPUUsage(ctx, time.Hour); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("CPU sampling ignored cancellation")
	}
}
