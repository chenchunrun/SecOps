package registry

import "github.com/chenchunrun/SecOps/internal/agent/tools/secops"

func NewSecOpsRegistry() *Registry {
	r := New()

	mustRegister(r, Descriptor{ToolType: secops.ToolTypeLogAnalyze, Decode: decodeJSONInto[secops.LogAnalyzeParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeMonitoringQuery, Decode: decodeJSONInto[secops.MonitoringQueryParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeComplianceCheck, Decode: decodeJSONInto[secops.ComplianceCheckParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeCertificateAudit, Decode: decodeJSONInto[secops.CertificateAuditParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeSecurityScan, Decode: decodeJSONInto[secops.SecurityScanParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeConfigurationAudit, Decode: decodeJSONInto[secops.ConfigAuditParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeNetworkDiagnostic, Decode: decodeJSONInto[secops.NetworkDiagnosticParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeDatabaseQuery, Decode: decodeJSONInto[secops.DatabaseQueryParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeBackupCheck, Decode: decodeJSONInto[secops.BackupCheckParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeReplicationStatus, Decode: decodeJSONInto[secops.ReplicationStatusParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeSecretAudit, Decode: decodeJSONInto[secops.SecretAuditParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeRotationCheck, Decode: decodeJSONInto[secops.RotationCheckParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeAccessReview, Decode: decodeJSONInto[secops.AccessReviewParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeInfrastructureQuery, Decode: decodeJSONInto[secops.InfrastructureQueryParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeDeploymentStatus, Decode: decodeJSONInto[secops.DeploymentStatusParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeAlertCheck, Decode: decodeJSONInto[secops.AlertCheckParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeIncidentTimeline, Decode: decodeJSONInto[secops.IncidentTimelineParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeResourceMonitor, Decode: decodeJSONInto[secops.ResourceMonitorParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeAttackReason, Decode: decodeJSONInto[secops.AttackReasonParams]})
	mustRegister(r, Descriptor{ToolType: secops.ToolTypeIncidentAssess, Decode: decodeJSONInto[secops.IncidentAssessParams]})

	return r
}

func mustRegister(r *Registry, desc Descriptor) {
	if err := r.Register(desc); err != nil {
		panic(err)
	}
}
