package registry

import (
	"encoding/json"
	"testing"

	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
	"github.com/stretchr/testify/require"
)

func TestNewSecOpsRegistry_CoversAllRegisteredToolTypes(t *testing.T) {
	t.Parallel()

	reg := NewSecOpsRegistry()

	expected := []secops.ToolType{
		secops.ToolTypeLogAnalyze,
		secops.ToolTypeMonitoringQuery,
		secops.ToolTypeComplianceCheck,
		secops.ToolTypeCertificateAudit,
		secops.ToolTypeSecurityScan,
		secops.ToolTypeConfigurationAudit,
		secops.ToolTypeNetworkDiagnostic,
		secops.ToolTypeDatabaseQuery,
		secops.ToolTypeBackupCheck,
		secops.ToolTypeReplicationStatus,
		secops.ToolTypeSecretAudit,
		secops.ToolTypeRotationCheck,
		secops.ToolTypeAccessReview,
		secops.ToolTypeInfrastructureQuery,
		secops.ToolTypeDeploymentStatus,
		secops.ToolTypeAlertCheck,
		secops.ToolTypeIncidentTimeline,
		secops.ToolTypeResourceMonitor,
		secops.ToolTypeAttackReason,
		secops.ToolTypeIncidentAssess,
	}

	for _, toolType := range expected {
		_, ok := reg.Get(toolType)
		require.Truef(t, ok, "missing descriptor for %s", toolType)
	}
}

func TestNewSecOpsRegistry_DecodeNetworkDiagnosticParams(t *testing.T) {
	t.Parallel()

	reg := NewSecOpsRegistry()
	desc, ok := reg.Get(secops.ToolTypeNetworkDiagnostic)
	require.True(t, ok)

	decoded, err := desc.Decode(json.RawMessage(`{"type":"ping","target":"8.8.8.8"}`))
	require.NoError(t, err)

	params, ok := decoded.(*secops.NetworkDiagnosticParams)
	require.True(t, ok)
	require.Equal(t, secops.DiagnosticPing, params.Type)
	require.Equal(t, "8.8.8.8", params.Target)
}
