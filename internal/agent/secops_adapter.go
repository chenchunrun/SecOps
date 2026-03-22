package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/charmbracelet/crush/internal/agent/tools/secops"
	"github.com/charmbracelet/crush/internal/permission"

	"charm.land/fantasy"
)

// Adapter implements fantasy.AgentTool by delegating to the wrapped SecOpsTool.
type Adapter struct {
	tool  secops.SecOpsTool
	perms permission.Service
}

// Info returns tool metadata.
func (a *Adapter) Info() fantasy.ToolInfo {
	return fantasy.ToolInfo{
		Name:        a.tool.Name(),
		Description: a.tool.Description(),
	}
}

// Run executes the tool with the given parameters.
func (a *Adapter) Run(ctx context.Context, call fantasy.ToolCall) (fantasy.ToolResponse, error) {
	// Convert ToolCall.Input (JSON string) to params map
	var paramsMap map[string]interface{}
	if call.Input != "" {
		if err := json.Unmarshal([]byte(call.Input), &paramsMap); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("failed to parse arguments: %v", err)), nil
		}
	}

	// Convert map to the appropriate params struct
	paramsBytes, err := json.Marshal(paramsMap)
	if err != nil {
		return fantasy.NewTextErrorResponse(fmt.Sprintf("failed to marshal params: %v", err)), nil
	}

	// Switch on tool type and unmarshal into the correct struct, then call
	// ValidateParams BEFORE Execute to ensure all security checks run.
	switch a.tool.Type() {
	case secops.ToolTypeLogAnalyze:
		var p secops.LogAnalyzeParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeMonitoringQuery:
		var p secops.MonitoringQueryParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeComplianceCheck:
		var p secops.ComplianceCheckParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeCertificateAudit:
		var p secops.CertificateAuditParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeSecurityScan:
		var p secops.SecurityScanParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeConfigurationAudit:
		var p secops.ConfigAuditParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeNetworkDiagnostic:
		var p secops.NetworkDiagnosticParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeDatabaseQuery:
		var p secops.DatabaseQueryParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeBackupCheck:
		var p secops.BackupCheckParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeReplicationStatus:
		var p secops.ReplicationStatusParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeSecretAudit:
		var p secops.SecretAuditParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeRotationCheck:
		var p secops.RotationCheckParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeAccessReview:
		var p secops.AccessReviewParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeInfrastructureQuery:
		var p secops.InfrastructureQueryParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeDeploymentStatus:
		var p secops.DeploymentStatusParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeAlertCheck:
		var p secops.AlertCheckParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeIncidentTimeline:
		var p secops.IncidentTimelineParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	case secops.ToolTypeResourceMonitor:
		var p secops.ResourceMonitorParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(&p)

	default:
		return fantasy.NewTextErrorResponse(fmt.Sprintf("unsupported tool type: %s", a.tool.Type())), nil
	}
}

// executeAndRespond calls tool.Execute and serializes the result to a ToolResponse.
func (a *Adapter) executeAndRespond(params interface{}) (fantasy.ToolResponse, error) {
	caps := a.tool.RequiredCapabilities()
	if len(caps) > 0 {
		slog.Debug("SecOps tool capabilities check", "tool", a.tool.Type(), "caps", caps)
	}

	result, err := a.tool.Execute(params)
	if err != nil {
		return fantasy.NewTextErrorResponse(err.Error()), nil
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return fantasy.NewTextErrorResponse(fmt.Sprintf("failed to marshal result: %v", err)), nil
	}

	return fantasy.NewTextResponse(string(resultBytes)), nil
}

// ProviderOptions implements fantasy.AgentTool.
func (a *Adapter) ProviderOptions() fantasy.ProviderOptions {
	return nil
}

// SetProviderOptions implements fantasy.AgentTool.
func (a *Adapter) SetProviderOptions(opts fantasy.ProviderOptions) {}

// RegisterSecOpsTools registers all SecOps tools with the Crush coordinator's tool list.
// It returns a slice of fantasy.AgentTool that can be passed to SetTools.
func RegisterSecOpsTools(registry *secops.SecOpsToolRegistry, perms permission.Service) []fantasy.AgentTool {
	var tools []fantasy.AgentTool

	for _, t := range registry.List() {
		adapter := &Adapter{
			tool:  t,
			perms: perms,
		}
		tools = append(tools, adapter)
		slog.Debug("Registered SecOps tool with coordinator", "tool", t.Type(), "name", t.Name())
	}

	return tools
}
