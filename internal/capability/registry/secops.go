package registry

import (
	"fmt"

	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
)

const (
	ExecutionProfileLocalOnly     ExecutionProfile = "local_only"
	ExecutionProfileRemoteCapable ExecutionProfile = "remote_capable"
)

func NewSecOpsRegistry() *Registry {
	return MustNew(secOpsDescriptors()...)
}

type secOpsCompatibilityAliasEntry struct {
	canonical string
	aliases   []string
}

var secOpsCompatibilityAliasEntries = []secOpsCompatibilityAliasEntry{
	{canonical: "infrastructure_query", aliases: []string{"Infrastructure Query"}},
	{canonical: "compliance_check", aliases: []string{"Compliance Check", "Compliance Checker"}},
	{canonical: "network_diagnostic", aliases: []string{"Network Diagnostic", "Network Diagnostics"}},
	{canonical: "monitoring_query", aliases: []string{"Monitoring Query"}},
	{canonical: "log_analyze", aliases: []string{"Log Analyze", "Log Analysis"}},
}

// secOpsToolDataset is the single source of truth for both capability
// descriptors and runtime SecOps tool registration.
func secOpsToolDataset() []ToolDatasetEntry[secops.SecOpsToolRegistry] {
	return []ToolDatasetEntry[secops.SecOpsToolRegistry]{
		NewToolDatasetEntry[secops.LogAnalyzeParams](secops.NewLogAnalyzeTool, ExecutionProfileRemoteCapable, "environment_inspection"),
		NewToolDatasetEntry[secops.MonitoringQueryParams](secops.NewMonitoringQueryTool, ExecutionProfileRemoteCapable, "environment_inspection"),
		NewToolDatasetEntry[secops.ComplianceCheckParams](secops.NewComplianceCheckTool, ExecutionProfileRemoteCapable, "config_audit", "environment_inspection"),
		NewToolDatasetEntry[secops.CertificateAuditParams](secops.NewCertificateAuditTool, ExecutionProfileRemoteCapable, "config_audit", "environment_inspection"),
		NewToolDatasetEntry[secops.SecurityScanParams](secops.NewSecurityScanTool, ExecutionProfileRemoteCapable, "active_probe", "network_surface"),
		NewToolDatasetEntry[secops.ConfigAuditParams](secops.NewConfigurationAuditTool, ExecutionProfileRemoteCapable, "config_audit", "environment_inspection"),
		NewToolDatasetEntry[secops.NetworkDiagnosticParams](secops.NewNetworkDiagnosticTool, ExecutionProfileRemoteCapable, "active_probe", "network_surface"),
		NewToolDatasetEntry[secops.DatabaseQueryParams](secops.NewDatabaseQueryTool, ExecutionProfileRemoteCapable, "environment_inspection"),
		NewToolDatasetEntry[secops.BackupCheckParams](secops.NewBackupCheckTool, ExecutionProfileRemoteCapable, "environment_inspection"),
		NewToolDatasetEntry[secops.ReplicationStatusParams](secops.NewReplicationStatusTool, ExecutionProfileRemoteCapable, "environment_inspection"),
		NewToolDatasetEntry[secops.SecretAuditParams](secops.NewSecretAuditTool, ExecutionProfileRemoteCapable, "config_audit", "environment_inspection"),
		NewToolDatasetEntry[secops.RotationCheckParams](secops.NewRotationCheckTool, ExecutionProfileRemoteCapable, "config_audit", "environment_inspection"),
		NewToolDatasetEntry[secops.AccessReviewParams](secops.NewAccessReviewTool, ExecutionProfileRemoteCapable, "config_audit", "environment_inspection"),
		NewToolDatasetEntry[secops.InfrastructureQueryParams](secops.NewInfrastructureQueryTool, ExecutionProfileRemoteCapable, "environment_inspection"),
		NewToolDatasetEntry[secops.DeploymentStatusParams](secops.NewDeploymentStatusTool, ExecutionProfileRemoteCapable, "environment_inspection"),
		NewToolDatasetEntry[secops.AlertCheckParams](secops.NewAlertCheckTool, ExecutionProfileRemoteCapable, "environment_inspection"),
		NewToolDatasetEntry[secops.IncidentTimelineParams](secops.NewIncidentTimelineTool, ExecutionProfileRemoteCapable, "environment_inspection"),
		NewToolDatasetEntry[secops.ResourceMonitorParams](secops.NewResourceMonitorTool, ExecutionProfileRemoteCapable, "environment_inspection"),
		NewToolDatasetEntry[secops.AttackReasonParams](secops.NewAttackReasonTool, ExecutionProfileLocalOnly, "investigation_reasoning"),
		NewToolDatasetEntry[secops.IncidentAssessParams](secops.NewIncidentAssessTool, ExecutionProfileLocalOnly, "investigation_reasoning"),
	}
}

func secOpsSpecs() []Spec {
	return ToolDatasetSpecs(secOpsToolDataset()...)
}

func secOpsDescriptors() []Descriptor {
	return SpecsToDescriptors(secOpsSpecs()...)
}

// RegisterSecOpsToolSet registers the runtime SecOps tools from the same
// dataset used to build capability descriptors.
func RegisterSecOpsToolSet(registry *secops.SecOpsToolRegistry) error {
	return RegisterToolDataset(registry, func(reg *secops.SecOpsToolRegistry, tool secops.SecOpsTool) error {
		if err := reg.Register(tool); err != nil {
			return fmt.Errorf("register secops tool: %w", err)
		}
		return nil
	}, secOpsToolDataset()...)
}

func secOpsDescriptorForTest[T any, Tool secops.SecOpsTool](ctor func(*secops.SecOpsToolRegistry) Tool, profile ExecutionProfile, tags ...string) Descriptor {
	return NewToolSpec[T](ctor(nil), profile, tags...).Descriptor()
}

// SecOpsToolNames returns the canonical SecOps tool keys from the registry
// dataset. Callers should prefer this over maintaining a second hard-coded
// list.
func SecOpsToolNames() []string {
	specs := secOpsSpecs()
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.Key)
	}
	return names
}

// SecOpsCompatibilityAliases returns a defensive copy of the compatibility
// alias map used for legacy SecOps tool names.
func SecOpsCompatibilityAliases() map[string][]string {
	aliases := make(map[string][]string, len(secOpsCompatibilityAliasEntries))
	for _, entry := range secOpsCompatibilityAliasEntries {
		aliases[entry.canonical] = append([]string(nil), entry.aliases...)
	}
	return aliases
}

// SecOpsCompatibilityAliasNames returns the flattened ordered compatibility
// alias names from the SecOps dataset.
func SecOpsCompatibilityAliasNames() []string {
	var names []string
	for _, entry := range secOpsCompatibilityAliasEntries {
		names = append(names, entry.aliases...)
	}
	return names
}
