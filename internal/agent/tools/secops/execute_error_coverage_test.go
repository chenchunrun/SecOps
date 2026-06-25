package secops

import (
	"errors"
	"testing"
)

// TestExecute_InvalidParams covers the universal Execute error branch where the
// params argument has the wrong dynamic type.
func TestExecute_InvalidParams(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		tool SecOpsTool
	}{
		{"access_review", NewAccessReviewTool(nil)},
		{"alert_check", NewAlertCheckTool(nil)},
		{"attack_reason", NewAttackReasonTool(nil)},
		{"backup_check", NewBackupCheckTool(nil)},
		{"certificate_audit", NewCertificateAuditTool(nil)},
		{"compliance_check", NewComplianceCheckTool(nil)},
		{"configuration_audit", NewConfigurationAuditTool(nil)},
		{"database_query", NewDatabaseQueryTool(nil)},
		{"deployment_status", NewDeploymentStatusTool(nil)},
		{"incident_assess", NewIncidentAssessTool(nil)},
		{"incident_timeline", NewIncidentTimelineTool(nil)},
		{"infrastructure_query", NewInfrastructureQueryTool(nil)},
		{"log_analyze", NewLogAnalyzeTool(nil)},
		{"monitoring_query", NewMonitoringQueryTool(nil)},
		{"network_diagnostic", NewNetworkDiagnosticTool(nil)},
		{"replication_status", NewReplicationStatusTool(nil)},
		{"resource_monitor", NewResourceMonitorTool(nil)},
		{"rotation_check", NewRotationCheckTool(nil)},
		{"secret_audit", NewSecretAuditTool(nil)},
		{"security_scan", NewSecurityScanTool(nil)},
	}

	badParams := struct{ Foo string }{Foo: "bar"}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tc.tool.Execute(badParams)
			if !errors.Is(err, ErrInvalidParams) {
				t.Errorf("expected ErrInvalidParams, got %v", err)
			}
		})
	}
}
