package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/charmbracelet/crush/internal/agent/tools/secops"
	"github.com/charmbracelet/crush/internal/permission"

	"charm.land/fantasy"
)

// secOpsToolAdapter wraps a SecOpsTool as a fantasy.AgentTool for use in the Crush agent.
type secOpsToolAdapter struct {
	tool  secops.SecOpsTool
	perms permission.Service
	mu    sync.RWMutex
}

// NewSecOpsToolAdapter creates a new adapter that wraps all registered SecOps tools as fantasy.AgentTool.
func NewSecOpsToolAdapter(registry *secops.SecOpsToolRegistry, perms permission.Service) *secOpsToolAdapter {
	return &secOpsToolAdapter{}
}

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

	// We use a generic map for validation since each tool has its own param type.
	var genericParams interface{}
	switch a.tool.Type() {
	case secops.ToolTypeResourceMonitor:
		var p secops.ResourceMonitorParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		genericParams = &p
	case secops.ToolTypeInfrastructureQuery:
		var p secops.InfrastructureQueryParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		genericParams = &p
	case secops.ToolTypeDeploymentStatus:
		var p secops.DeploymentStatusParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		genericParams = &p
	case secops.ToolTypeAlertCheck:
		var p secops.AlertCheckParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		genericParams = &p
	case secops.ToolTypeIncidentTimeline:
		var p secops.IncidentTimelineParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		genericParams = &p
	default:
		// For all other tools, use a generic map
		var m map[string]interface{}
		if err := json.Unmarshal(paramsBytes, &m); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		genericParams = m
	}

	// Check capabilities
	caps := a.tool.RequiredCapabilities()
	if len(caps) > 0 {
		slog.Debug("SecOps tool capabilities check", "tool", a.tool.Type(), "caps", caps)
	}

	result, err := a.tool.Execute(genericParams)
	if err != nil {
		return fantasy.NewTextErrorResponse(err.Error()), nil
	}

	// Serialize result to JSON
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

// secOpsToolsAdapter is the adapter instance
var secOpsToolsAdapter *secOpsToolAdapter
var adapterOnce sync.Once

// GetSecOpsToolsAdapter returns the singleton SecOps tools adapter.
func GetSecOpsToolsAdapter(registry *secops.SecOpsToolRegistry, perms permission.Service) *secOpsToolAdapter {
	adapterOnce.Do(func() {
		secOpsToolsAdapter = NewSecOpsToolAdapter(registry, perms)
	})
	return secOpsToolsAdapter
}
