package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/chenchunrun/SecOps/internal/agent/tools"
	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/security"

	"charm.land/fantasy"
)

// Adapter implements fantasy.AgentTool by delegating to the wrapped SecOpsTool.
type Adapter struct {
	tool        secops.SecOpsTool
	perms       permission.Service
	secopsPerms permission.SecOpsService
	assessor    *security.RiskAssessor
}

type remoteValidationError struct {
	code string
	msg  string
}

func (e *remoteValidationError) Error() string {
	return e.msg
}

// Info returns tool metadata.
func (a *Adapter) Info() fantasy.ToolInfo {
	return fantasy.ToolInfo{
		Name:        string(a.tool.Type()),
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
	paramsMap = normalizeSecOpsParams(a.tool.Type(), paramsMap)
	if err := validateRemoteSSHParams(paramsMap); err != nil {
		a.recordRemoteValidationAuditEvent(ctx, call, paramsMap, err)
		return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid remote ssh parameters: %v", err)), nil
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
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeMonitoringQuery:
		var p secops.MonitoringQueryParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeComplianceCheck:
		var p secops.ComplianceCheckParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeCertificateAudit:
		var p secops.CertificateAuditParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeSecurityScan:
		var p secops.SecurityScanParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeConfigurationAudit:
		var p secops.ConfigAuditParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeNetworkDiagnostic:
		var p secops.NetworkDiagnosticParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeDatabaseQuery:
		var p secops.DatabaseQueryParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeBackupCheck:
		var p secops.BackupCheckParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeReplicationStatus:
		var p secops.ReplicationStatusParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeSecretAudit:
		var p secops.SecretAuditParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeRotationCheck:
		var p secops.RotationCheckParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeAccessReview:
		var p secops.AccessReviewParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeInfrastructureQuery:
		var p secops.InfrastructureQueryParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeDeploymentStatus:
		var p secops.DeploymentStatusParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeAlertCheck:
		var p secops.AlertCheckParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeIncidentTimeline:
		var p secops.IncidentTimelineParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	case secops.ToolTypeResourceMonitor:
		var p secops.ResourceMonitorParams
		if err := json.Unmarshal(paramsBytes, &p); err != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
		}
		if err := a.tool.ValidateParams(&p); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
		return a.executeAndRespond(ctx, call, &p)

	default:
		return fantasy.NewTextErrorResponse(fmt.Sprintf("unsupported tool type: %s", a.tool.Type())), nil
	}
}

var (
	remoteHostPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:\-\[\]]*$`)
	remoteUserPattern      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	remoteProfileIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

func validateRemoteSSHParams(params map[string]interface{}) error {
	if len(params) == 0 {
		return nil
	}

	checkNoControl := func(name, val string) error {
		if strings.ContainsAny(val, "\r\n\x00") {
			return fmt.Errorf("%s contains control characters", name)
		}
		return nil
	}

	getString := func(key string) string {
		v, ok := params[key]
		if !ok {
			return ""
		}
		s, ok := v.(string)
		if !ok {
			return ""
		}
		return strings.TrimSpace(s)
	}

	remoteHost := getString("remote_host")
	remoteUser := getString("remote_user")
	remoteProfile := getString("remote_profile")
	remoteKeyPath := getString("remote_key_path")
	remoteProxyJump := getString("remote_proxy_jump")

	if remoteHost != "" {
		if strings.HasPrefix(remoteHost, "-") {
			return &remoteValidationError{code: "host_dash_prefix", msg: "remote_host cannot start with '-'"}
		}
		if err := checkNoControl("remote_host", remoteHost); err != nil {
			return &remoteValidationError{code: "host_control_chars", msg: err.Error()}
		}
		if !remoteHostPattern.MatchString(remoteHost) {
			return &remoteValidationError{code: "host_invalid_format", msg: "remote_host has invalid format"}
		}
	}

	if remoteUser != "" {
		if strings.HasPrefix(remoteUser, "-") {
			return &remoteValidationError{code: "user_dash_prefix", msg: "remote_user cannot start with '-'"}
		}
		if err := checkNoControl("remote_user", remoteUser); err != nil {
			return &remoteValidationError{code: "user_control_chars", msg: err.Error()}
		}
		if !remoteUserPattern.MatchString(remoteUser) {
			return &remoteValidationError{code: "user_invalid_format", msg: "remote_user has invalid format"}
		}
	}

	if remoteProfile != "" {
		if strings.HasPrefix(remoteProfile, "-") {
			return &remoteValidationError{code: "profile_dash_prefix", msg: "remote_profile cannot start with '-'"}
		}
		if err := checkNoControl("remote_profile", remoteProfile); err != nil {
			return &remoteValidationError{code: "profile_control_chars", msg: err.Error()}
		}
		if !remoteProfileIDPattern.MatchString(remoteProfile) {
			return &remoteValidationError{code: "profile_invalid_format", msg: "remote_profile has invalid format"}
		}
	}

	if remoteKeyPath != "" {
		if strings.HasPrefix(remoteKeyPath, "-") {
			return &remoteValidationError{code: "key_path_dash_prefix", msg: "remote_key_path cannot start with '-'"}
		}
		if err := checkNoControl("remote_key_path", remoteKeyPath); err != nil {
			return &remoteValidationError{code: "key_path_control_chars", msg: err.Error()}
		}
	}

	if remoteProxyJump != "" {
		if strings.HasPrefix(remoteProxyJump, "-") {
			return &remoteValidationError{code: "proxy_jump_dash_prefix", msg: "remote_proxy_jump cannot start with '-'"}
		}
		if err := checkNoControl("remote_proxy_jump", remoteProxyJump); err != nil {
			return &remoteValidationError{code: "proxy_jump_control_chars", msg: err.Error()}
		}
	}

	if portRaw, ok := params["remote_port"]; ok {
		switch p := portRaw.(type) {
		case float64:
			if p < 0 || p > 65535 {
				return &remoteValidationError{code: "port_out_of_range", msg: "remote_port must be between 0 and 65535"}
			}
		case int:
			if p < 0 || p > 65535 {
				return &remoteValidationError{code: "port_out_of_range", msg: "remote_port must be between 0 and 65535"}
			}
		}
	}

	return nil
}

func (a *Adapter) recordRemoteValidationAuditEvent(
	ctx context.Context,
	call fantasy.ToolCall,
	params map[string]interface{},
	err error,
) {
	sessionID := tools.GetSessionFromContext(ctx)
	if sessionID == "" {
		sessionID = "secops"
	}
	role := secOpsRoleFromContext(ctx)

	code := "unknown_validation_error"
	if rv, ok := err.(*remoteValidationError); ok && rv.code != "" {
		code = rv.code
	}

	host := strings.TrimSpace(stringValue(params["remote_host"]))
	user := strings.TrimSpace(stringValue(params["remote_user"]))
	target := host
	if target != "" && user != "" {
		target = user + "@" + host
	}

	event := audit.NewAuditEventBuilder(audit.EventTypePermissionDenied).
		WithSession(sessionID).
		WithUser(role, role).
		WithAction("remote_param_validation_failed").
		WithResource(string(permission.ResourceTypeCommand), string(a.tool.Type()), string(a.tool.Type())).
		WithRemoteTarget("ssh", target, strings.TrimSpace(stringValue(params["remote_env"])), strings.TrimSpace(stringValue(params["remote_profile"]))).
		WithDetail("tool_call_id", call.ID).
		WithDetail("validation_reason_code", code).
		WithDetail("validation_error", err.Error()).
		WithDetail("ssh_option_profile", "secops_default_v1").
		WithDetail("remote_policy_source", "secops_permission_engine").
		WithResult(audit.ResultDenied).
		Build()
	event.Reason = code
	_ = audit.RecordGlobal(event)
}

func stringValue(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func normalizeSecOpsParams(toolType secops.ToolType, in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return map[string]interface{}{}
	}
	out := make(map[string]interface{}, len(in)+3)
	for k, v := range in {
		out[k] = v
	}

	switch toolType {
	case secops.ToolTypeNetworkDiagnostic:
		if _, ok := out["type"]; !ok {
			if v, exists := out["diagnostic_type"]; exists {
				out["type"] = v
			}
		}
		if _, ok := out["target"]; !ok {
			if v, exists := out["host"]; exists {
				out["target"] = v
			}
		}
		if cmdRaw, exists := out["command"]; exists {
			if cmd, ok := cmdRaw.(string); ok {
				fillNetworkTypeAndTargetFromCommand(out, cmd)
			}
		}
		if _, ok := out["type"]; !ok {
			out["type"] = string(secops.DiagnosticPing)
		}

	case secops.ToolTypeComplianceCheck:
		if _, ok := out["framework"]; !ok {
			out["framework"] = string(secops.FrameworkCIS)
		}

	case secops.ToolTypeInfrastructureQuery:
		if _, ok := out["system_type"]; !ok {
			out["system_type"] = "terraform"
		}
		if _, ok := out["query_type"]; !ok {
			out["query_type"] = "resources"
		}
	}

	return out
}

func fillNetworkTypeAndTargetFromCommand(out map[string]interface{}, command string) {
	cmd := strings.ToLower(strings.TrimSpace(command))
	if cmd == "" {
		return
	}
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return
	}

	if _, ok := out["type"]; !ok {
		switch fields[0] {
		case "ping":
			out["type"] = string(secops.DiagnosticPing)
		case "traceroute", "tracepath":
			out["type"] = string(secops.DiagnosticTraceroute)
		case "mtr":
			out["type"] = string(secops.DiagnosticMTR)
		case "dig", "nslookup":
			out["type"] = string(secops.DiagnosticDNS)
		case "nmap":
			out["type"] = string(secops.DiagnosticPortScan)
		}
	}

	if _, ok := out["target"]; ok {
		return
	}
	for i := len(fields) - 1; i >= 0; i-- {
		f := strings.Trim(fields[i], "\"' ")
		if f == "" || strings.HasPrefix(f, "-") {
			continue
		}
		out["target"] = f
		return
	}
}

// executeAndRespond calls tool.Execute and serializes the result to a ToolResponse.
func (a *Adapter) executeAndRespond(ctx context.Context, call fantasy.ToolCall, params interface{}) (fantasy.ToolResponse, error) {
	caps := a.tool.RequiredCapabilities()
	if len(caps) > 0 {
		slog.Debug("SecOps tool capabilities check", "tool", a.tool.Type(), "caps", caps)
	}

	role := secOpsRoleFromContext(ctx)
	if err := validateCapabilities(role, caps); err != nil {
		return fantasy.NewTextErrorResponse(err.Error()), nil
	}

	if err := a.enforceRiskDecision(ctx, call, role); err != nil {
		return fantasy.NewTextErrorResponse(err.Error()), nil
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

// RegisterDefaultSecOpsToolSet registers the built-in 18 SecOps tools.
func RegisterDefaultSecOpsToolSet(registry *secops.SecOpsToolRegistry) error {
	if registry == nil {
		return fmt.Errorf("secops registry is nil")
	}
	constructors := []func(*secops.SecOpsToolRegistry) secops.SecOpsTool{
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewLogAnalyzeTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewMonitoringQueryTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewComplianceCheckTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewCertificateAuditTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewSecurityScanTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewConfigurationAuditTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewNetworkDiagnosticTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewDatabaseQueryTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewBackupCheckTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewReplicationStatusTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewSecretAuditTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewRotationCheckTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewAccessReviewTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewInfrastructureQueryTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewDeploymentStatusTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewAlertCheckTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewIncidentTimelineTool(nil) },
		func(*secops.SecOpsToolRegistry) secops.SecOpsTool { return secops.NewResourceMonitorTool(nil) },
	}
	for _, ctor := range constructors {
		if err := registry.Register(ctor(registry)); err != nil {
			return fmt.Errorf("register secops tool: %w", err)
		}
	}
	return nil
}

// RegisterSecOpsTools registers all SecOps tools with the Crush coordinator's tool list.
// It returns a slice of fantasy.AgentTool that can be passed to SetTools.
func RegisterSecOpsTools(registry *secops.SecOpsToolRegistry, perms permission.Service) []fantasy.AgentTool {
	var tools []fantasy.AgentTool
	secopsPerms := permission.NewDefaultService()
	assessor := security.NewRiskAssessor()

	for _, t := range registry.List() {
		adapter := &Adapter{
			tool:        t,
			perms:       perms,
			secopsPerms: secopsPerms,
			assessor:    assessor,
		}
		tools = append(tools, adapter)
		slog.Debug("Registered SecOps tool with coordinator", "tool", t.Type(), "name", t.Name())
	}

	return tools
}

func (a *Adapter) enforceRiskDecision(ctx context.Context, call fantasy.ToolCall, role string) error {
	if a.secopsPerms == nil || a.assessor == nil {
		return nil
	}

	sessionID := tools.GetSessionFromContext(ctx)
	if sessionID == "" {
		sessionID = "secops"
	}

	assessment := a.assessRisk(call.Input)
	remoteCtx := parseRemoteContext(call.Input)
	resourcePath := string(a.tool.Type())
	if remoteCtx.Transport == "ssh" && remoteCtx.TargetHost != "" {
		resourcePath = "ssh://" + remoteCtx.TargetHost
	}
	req := &permission.PermissionRequest{
		SessionID:    sessionID,
		ToolCallID:   call.ID,
		ToolName:     string(a.tool.Type()),
		Description:  call.Input,
		Action:       "execute",
		ResourceType: permission.ResourceTypeCommand,
		ResourcePath: resourcePath,
		UserID:       role,
		Username:     role,
		RequestTime:  timeNowUTC(),
		RiskScore:    assessment.Score,
		RiskFactors:  riskFactorNames(assessment.Factors),
		Transport:    remoteCtx.Transport,
		TargetHost:   remoteCtx.TargetHost,
		TargetEnv:    remoteCtx.TargetEnv,
		TargetID:     remoteCtx.TargetID,
	}
	a.recordRiskAuditEvent(req, assessment, "risk_evaluated")

	switch assessment.Level {
	case security.RiskLevelCritical:
		req.Severity = permission.SeverityCritical
	case security.RiskLevelHigh:
		req.Severity = permission.SeverityHigh
	case security.RiskLevelMedium:
		req.Severity = permission.SeverityMedium
	default:
		req.Severity = permission.SeverityLow
	}

	decision, err := a.secopsPerms.MakeDecision(req)
	if err != nil {
		return fmt.Errorf("secops decision failed: %w", err)
	}
	if decision == permission.DecisionAutoApprove && role == string(RoleOpsAgent) {
		decision = permission.DecisionUserConfirm
	}
	req.Decision = decision
	_ = a.secopsPerms.AuditLog(req, decision)
	a.recordDecisionAuditEvent(req, assessment, decision, "")

	switch decision {
	case permission.DecisionDeny:
		return fmt.Errorf("secops blocked execution: risk score=%d", assessment.Score)
	case permission.DecisionAdminReview:
		return fmt.Errorf("secops requires admin review: risk score=%d", assessment.Score)
	case permission.DecisionUserConfirm:
		if a.perms == nil {
			return fmt.Errorf("secops requires user confirmation but permission service unavailable")
		}
		granted, reqErr := a.perms.Request(ctx, permission.CreatePermissionRequest{
			SessionID:   sessionID,
			ToolCallID:  call.ID,
			ToolName:    string(a.tool.Type()),
			Description: "SecOps risk confirmation required",
			Action:      "execute",
			Params:      call.Input,
			Path:        resourcePath,
			Transport:   remoteCtx.Transport,
			TargetHost:  remoteCtx.TargetHost,
			TargetEnv:   remoteCtx.TargetEnv,
			TargetID:    remoteCtx.TargetID,
		})
		if reqErr != nil {
			a.recordDecisionAuditEvent(req, assessment, decision, reqErr.Error())
			return fmt.Errorf("permission request failed: %w", reqErr)
		}
		if !granted {
			a.recordDecisionAuditEvent(req, assessment, permission.DecisionDeny, "user denied permission")
			return permission.ErrorPermissionDenied
		}
		a.recordDecisionAuditEvent(req, assessment, permission.DecisionAutoApprove, "user confirmed")
	}

	return nil
}

func (a *Adapter) assessRisk(input string) *security.RiskAssessment {
	baseInput := strings.TrimSpace(input)
	if baseInput == "" {
		baseInput = string(a.tool.Type())
	}

	best := a.assessor.AssessCommand(baseInput)
	for _, candidate := range riskCandidatesFromInput(input) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		current := a.assessor.AssessCommand(candidate)
		if current.Score > best.Score {
			best = current
		}
	}
	return best
}

func riskCandidatesFromInput(input string) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	var payload any
	if err := json.Unmarshal([]byte(input), &payload); err != nil {
		return nil
	}

	out := make([]string, 0)
	collectRiskCandidates(payload, &out)
	return out
}

func collectRiskCandidates(value any, out *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, val := range v {
			lk := strings.ToLower(strings.TrimSpace(key))
			switch t := val.(type) {
			case string:
				if isRiskStringKey(lk) {
					*out = append(*out, t)
				}
			default:
				collectRiskCandidates(t, out)
			}
		}
	case []any:
		for _, item := range v {
			collectRiskCandidates(item, out)
		}
	}
}

func isRiskStringKey(key string) bool {
	switch key {
	case "command", "cmd", "query", "pattern", "keyword", "target_path", "path", "url", "resource", "script", "args":
		return true
	default:
		return strings.HasSuffix(key, "_path") || strings.HasSuffix(key, "_query")
	}
}

func validateCapabilities(role string, caps []string) error {
	for _, cap := range caps {
		if !roleHasCapability(role, cap) {
			return fmt.Errorf("capability denied: role=%s missing %s", role, cap)
		}
	}
	return nil
}

func roleHasCapability(role, capability string) bool {
	for _, candidate := range expandedRoles(role) {
		if security.CheckCapability(candidate, capability) {
			return true
		}
	}
	return false
}

func expandedRoles(role string) []string {
	switch role {
	case "admin":
		// Admin inherits viewer/operator and can also execute security analyst/responder flows.
		return []string{"admin", "operator", "viewer", "responder", "analyst"}
	case "operator":
		return []string{"operator", "viewer"}
	case "responder":
		return []string{"responder", "analyst"}
	default:
		return []string{role}
	}
}

func secOpsRoleFromContext(ctx context.Context) string {
	agentID := strings.ToLower(strings.TrimSpace(tools.GetAgentIDFromContext(ctx)))
	switch agentID {
	case "admin", "operator", "viewer", "analyst", "responder":
		return agentID
	}

	switch agentID {
	case config.AgentSecurityExpertAgent:
		return "analyst"
	case config.AgentOpsAgent:
		return string(RoleOpsAgent)
	case config.AgentTask, config.AgentCoder:
		return "admin"
	default:
		return "admin"
	}
}

func riskFactorNames(factors []security.RiskFactor) []string {
	names := make([]string, 0, len(factors))
	for _, f := range factors {
		names = append(names, f.Name)
	}
	return names
}

func timeNowUTC() time.Time {
	return time.Now().UTC()
}

func (a *Adapter) recordRiskAuditEvent(req *permission.PermissionRequest, assessment *security.RiskAssessment, action string) {
	if req == nil {
		return
	}
	builder := audit.NewAuditEventBuilder(audit.EventTypePermissionRequest).
		WithSession(req.SessionID).
		WithUser(req.UserID, req.Username).
		WithAction(action).
		WithResource(string(req.ResourceType), req.ToolName, req.ResourcePath).
		WithRiskScore(req.RiskScore, string(assessment.Level)).
		WithRemoteTarget(req.Transport, req.TargetHost, req.TargetEnv, req.TargetID).
		WithDetail("tool_call_id", req.ToolCallID).
		WithDetail("risk_factors", req.RiskFactors).
		WithDetail("risk_action", assessment.Action).
		WithDetail("risk_details", assessment.Details)
	addRemoteAuditProfileDetails(builder, req.Transport)
	event := builder.WithResult(audit.ResultSuccess).Build()
	_ = audit.RecordGlobal(event)
}

func (a *Adapter) recordDecisionAuditEvent(
	req *permission.PermissionRequest,
	assessment *security.RiskAssessment,
	decision permission.PermissionDecision,
	errMsg string,
) {
	if req == nil {
		return
	}

	eventType := audit.EventTypePermissionApproved
	result := audit.ResultSuccess
	action := "risk_decision_" + string(decision)
	if decision == permission.DecisionDeny || decision == permission.DecisionAdminReview {
		eventType = audit.EventTypePermissionDenied
		result = audit.ResultDenied
	}
	if errMsg != "" {
		result = audit.ResultError
	}

	builder := audit.NewAuditEventBuilder(eventType).
		WithSession(req.SessionID).
		WithUser(req.UserID, req.Username).
		WithAction(action).
		WithResource(string(req.ResourceType), req.ToolName, req.ResourcePath).
		WithRiskScore(req.RiskScore, string(assessment.Level)).
		WithRemoteTarget(req.Transport, req.TargetHost, req.TargetEnv, req.TargetID).
		WithDetail("tool_call_id", req.ToolCallID).
		WithDetail("decision", decision).
		WithDetail("risk_factors", req.RiskFactors)
	addRemoteAuditProfileDetails(builder, req.Transport)
	event := builder.WithResult(result).Build()
	if errMsg != "" {
		event.ErrorMsg = errMsg
	}
	_ = audit.RecordGlobal(event)
}

func addRemoteAuditProfileDetails(builder *audit.AuditEventBuilder, transport string) {
	if strings.ToLower(strings.TrimSpace(transport)) != "ssh" {
		return
	}
	builder.
		WithDetail("ssh_option_profile", "secops_default_v1").
		WithDetail("remote_policy_source", "secops_permission_engine")
}

type remoteContext struct {
	Transport  string
	TargetHost string
	TargetEnv  string
	TargetID   string
}

func parseRemoteContext(input string) remoteContext {
	input = strings.TrimSpace(input)
	if input == "" {
		return remoteContext{}
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(input), &payload); err != nil {
		return remoteContext{}
	}

	host := firstString(payload, "remote_host", "target_host")
	user := firstString(payload, "remote_user")
	target := strings.TrimSpace(host)
	if target != "" && strings.TrimSpace(user) != "" {
		target = strings.TrimSpace(user) + "@" + target
	}
	if target == "" {
		return remoteContext{}
	}

	return remoteContext{
		Transport:  "ssh",
		TargetHost: target,
		TargetEnv:  firstString(payload, "remote_env", "target_env", "env", "environment"),
		TargetID:   firstString(payload, "remote_profile", "target_id", "profile", "profile_id"),
	}
}

func firstString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := m[key]
		if !ok {
			continue
		}
		if s, ok := v.(string); ok {
			s = strings.TrimSpace(s)
			if s != "" {
				return s
			}
		}
	}
	return ""
}
