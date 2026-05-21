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
	capregistry "github.com/chenchunrun/SecOps/internal/capability/registry"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/policy"
	"github.com/chenchunrun/SecOps/internal/security"

	"charm.land/fantasy"
	fantasyschema "charm.land/fantasy/schema"
)

// Adapter implements fantasy.AgentTool by delegating to the wrapped SecOpsTool.
type Adapter struct {
	tool        secops.SecOpsTool
	perms       permission.Service
	secopsPerms permission.SecOpsService
	assessor    *security.RiskAssessor
	decider     policy.Decider
	registry    *capregistry.Registry
}

type secopsPolicyContext struct {
	Call         fantasy.ToolCall
	Role         string
	RequiredCaps []string
	RiskTags     []string
}

type secopsPolicyEvaluator struct {
	adapter *Adapter
}

type remoteValidationError struct {
	code string
	msg  string
}

func (e *remoteValidationError) Error() string {
	return e.msg
}

type executionProfileError struct {
	profile string
	msg     string
}

func (e *executionProfileError) Error() string {
	return e.msg
}

// Info returns tool metadata including a JSON schema derived from the params
// struct so the LLM receives correct parameter names and types.
func (a *Adapter) Info() fantasy.ToolInfo {
	info := fantasy.ToolInfo{
		Name:        string(a.tool.Type()),
		Description: a.tool.Description(),
	}
	if a.registry != nil {
		if t, ok := a.registry.ParamsTypeFor(string(a.tool.Type())); ok {
			s := fantasyschema.Generate(t)
			info.Parameters = fantasyschema.ToParameters(s)
			info.Required = s.Required
		}
	}
	return info
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
	if err := a.validateExecutionProfile(paramsMap); err != nil {
		return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
	}
	if err := validateRemoteSSHParams(paramsMap); err != nil {
		a.recordRemoteValidationAuditEvent(ctx, call, paramsMap, err)
		return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid remote ssh parameters: %v", err)), nil
	}

	// Convert map to the appropriate params struct
	paramsBytes, err := json.Marshal(paramsMap)
	if err != nil {
		return fantasy.NewTextErrorResponse(fmt.Sprintf("failed to marshal params: %v", err)), nil
	}

	params, err := a.decodeParams(paramsBytes)
	if err != nil {
		return fantasy.NewTextErrorResponse(fmt.Sprintf("invalid params: %v", err)), nil
	}
	if err := a.tool.ValidateParams(params); err != nil {
		return fantasy.NewTextErrorResponse(err.Error()), nil
	}
	return a.executeAndRespond(ctx, call, params)
}

var (
	remoteHostPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:\-\[\]]*$`)
	remoteUserPattern      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	remoteProfileIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	// remoteKeyPathPattern enforces absolute or home-relative paths to SSH keys,
	// preventing path traversal and option injection (HIGH-02).
	remoteKeyPathPattern = regexp.MustCompile(`^(/[A-Za-z0-9_./ -]+|~/[A-Za-z0-9_./ -]+)$`)
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
		// Enforce absolute/home-relative path to prevent path traversal (HIGH-02).
		if !remoteKeyPathPattern.MatchString(remoteKeyPath) {
			return &remoteValidationError{code: "key_path_invalid_format", msg: "remote_key_path must be an absolute path or ~/... home-relative path"}
		}
	}

	if remoteProxyJump != "" {
		if strings.HasPrefix(remoteProxyJump, "-") {
			return &remoteValidationError{code: "proxy_jump_dash_prefix", msg: "remote_proxy_jump cannot start with '-'"}
		}
		if err := checkNoControl("remote_proxy_jump", remoteProxyJump); err != nil {
			return &remoteValidationError{code: "proxy_jump_control_chars", msg: err.Error()}
		}
		// Apply the same format validation as remote_host to prevent option injection (HIGH-02).
		if !remoteHostPattern.MatchString(remoteProxyJump) {
			return &remoteValidationError{code: "proxy_jump_invalid_format", msg: "remote_proxy_jump has invalid format"}
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

	case secops.ToolTypeSecretAudit:
		// Accept "path" as an alias for "target_path".
		if _, ok := out["target_path"]; !ok {
			if v, exists := out["path"]; exists {
				out["target_path"] = v
			}
		}

	case secops.ToolTypeSecurityScan:
		// Accept "path" as an alias for "target_path".
		if _, ok := out["target_path"]; !ok {
			if v, exists := out["path"]; exists {
				out["target_path"] = v
			}
		}
		// Default scanner to trivy when not specified.
		if _, ok := out["scanner"]; !ok {
			out["scanner"] = string(secops.ScannerTrivy)
		}
		// Default target type to filesystem when a path is provided.
		if _, ok := out["target"]; !ok {
			if _, hasPath := out["target_path"]; hasPath {
				out["target"] = string(secops.TargetFilesystem)
			}
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
	caps := a.requiredCapabilities()
	riskTags := a.policyTags()
	if len(caps) > 0 {
		slog.Debug("SecOps tool capabilities check", "tool", a.tool.Type(), "caps", caps)
	}

	role := secOpsRoleFromContext(ctx)
	if a.decider != nil {
		decision, err := a.decider.Decide(ctx, policy.Request{
			PolicyKind:   "secops",
			SessionID:    tools.GetSessionFromContext(ctx),
			ToolCallID:   call.ID,
			ToolName:     string(a.tool.Type()),
			Action:       "execute",
			Description:  call.Input,
			Role:         role,
			RequiredCaps: caps,
			RiskTags:     riskTags,
			Parameters: secopsPolicyContext{
				Call:         call,
				Role:         role,
				RequiredCaps: caps,
				RiskTags:     riskTags,
			},
		})
		if err != nil {
			return fantasy.ToolResponse{}, err
		}
		if !decision.Allowed {
			return fantasy.NewTextErrorResponse(decision.Reason), nil
		}
	} else {
		if err := a.validateCapabilities(ctx, role, caps); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}

		if err := a.enforceRiskDecision(ctx, call, role, nil); err != nil {
			return fantasy.NewTextErrorResponse(err.Error()), nil
		}
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

// RegisterDefaultSecOpsToolSet registers the built-in SecOps tools.
func RegisterDefaultSecOpsToolSet(registry *secops.SecOpsToolRegistry) error {
	return capregistry.RegisterSecOpsToolSet(registry)
}

// RegisterSecOpsTools registers all SecOps tools with the Crush coordinator's tool list.
// It returns a slice of fantasy.AgentTool that can be passed to SetTools.
func RegisterSecOpsTools(registry *secops.SecOpsToolRegistry, perms permission.Service, cfg *config.Config) []fantasy.AgentTool {
	var tools []fantasy.AgentTool
	secopsPerms := permission.NewDefaultService()
	applySecOpsCapabilityGrants(secopsPerms, cfg)
	assessor := security.NewRiskAssessor()
	descriptorRegistry := capregistry.NewSecOpsRegistry()

	for _, t := range registry.List() {
		adapter := &Adapter{
			tool:        t,
			perms:       perms,
			secopsPerms: secopsPerms,
			assessor:    assessor,
			registry:    descriptorRegistry,
		}
		adapter.decider = policy.NewDefaultDecider(nil, secopsPolicyEvaluator{adapter: adapter})
		tools = append(tools, adapter)
		slog.Debug("Registered SecOps tool with coordinator", "tool", t.Type(), "name", t.Name())
	}

	return tools
}

func (a *Adapter) decodeParams(raw json.RawMessage) (any, error) {
	if a.registry == nil {
		return nil, fmt.Errorf("capability registry is not configured")
	}

	params, err := a.registry.Decode(string(a.tool.Type()), raw)
	if err != nil {
		if strings.HasPrefix(err.Error(), "unsupported descriptor key: ") {
			return nil, fmt.Errorf("unsupported tool type: %s", a.tool.Type())
		}
		return nil, err
	}

	return params, nil
}

func (a *Adapter) validateExecutionProfile(params map[string]interface{}) error {
	if a.registry == nil {
		return nil
	}

	profile, ok := a.registry.ExecutionProfileFor(string(a.tool.Type()))
	if !ok {
		return nil
	}
	if profile != capregistry.ExecutionProfileLocalOnly {
		return nil
	}
	if !hasRemoteExecutionParams(params) {
		return nil
	}

	return &executionProfileError{
		profile: string(profile),
		msg:     fmt.Sprintf("tool %s does not support remote execution", a.tool.Type()),
	}
}

func hasRemoteExecutionParams(params map[string]interface{}) bool {
	if len(params) == 0 {
		return false
	}
	for _, key := range []string{"remote_host", "remote_user", "remote_port", "remote_key_path", "remote_proxy_jump", "remote_profile", "remote_env"} {
		v, ok := params[key]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				return true
			}
		case float64:
			if t != 0 {
				return true
			}
		case int:
			if t != 0 {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func (a *Adapter) requiredCapabilities() []string {
	if a.registry != nil {
		if caps := a.registry.RequiredCapabilities(string(a.tool.Type())); len(caps) > 0 {
			return caps
		}
	}
	return a.tool.RequiredCapabilities()
}

func (a *Adapter) policyTags() []string {
	if a.registry != nil {
		if tags := a.registry.PolicyTags(string(a.tool.Type())); len(tags) > 0 {
			return tags
		}
	}
	return nil
}

func (e secopsPolicyEvaluator) EvaluateSecOps(ctx context.Context, req policy.Request) (policy.Decision, error) {
	secopsCtx, ok := req.Parameters.(secopsPolicyContext)
	if !ok {
		return policy.Decision{}, fmt.Errorf("unexpected secops policy params type %T", req.Parameters)
	}

	if err := e.adapter.validateCapabilities(ctx, secopsCtx.Role, secopsCtx.RequiredCaps); err != nil {
		return policy.Decision{
			Allowed: false,
			Reason:  err.Error(),
			AuditFields: map[string]any{
				"tool_name": req.ToolName,
				"policy":    "capability-check",
			},
		}, nil
	}

	if err := e.adapter.enforceRiskDecision(ctx, secopsCtx.Call, secopsCtx.Role, secopsCtx.RiskTags); err != nil {
		return policy.Decision{
			Allowed: false,
			Reason:  err.Error(),
			AuditFields: map[string]any{
				"tool_name": req.ToolName,
				"policy":    "secops-risk-evaluator",
			},
		}, nil
	}

	return policy.Decision{
		Allowed: true,
		Reason:  "secops policy evaluated",
		AuditFields: map[string]any{
			"tool_name": req.ToolName,
			"policy":    "secops-risk-evaluator",
		},
	}, nil
}

func (a *Adapter) enforceRiskDecision(ctx context.Context, call fantasy.ToolCall, role string, riskTags []string) error {
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
		RiskFactors:  mergeRiskTags(riskFactorNames(assessment.Factors), riskTags),
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

func mergeRiskTags(factors []string, tags []string) []string {
	if len(tags) == 0 {
		return factors
	}
	seen := make(map[string]struct{}, len(factors)+len(tags))
	out := make([]string, 0, len(factors)+len(tags))
	for _, item := range factors {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	for _, item := range tags {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
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

func applySecOpsCapabilityGrants(svc permission.SecOpsService, cfg *config.Config) {
	if svc == nil || cfg == nil || cfg.Permissions == nil {
		return
	}
	for subject, caps := range cfg.Permissions.SecOpsCapabilityGrants {
		subject = strings.ToLower(strings.TrimSpace(subject))
		if subject == "" {
			continue
		}
		for _, cap := range caps {
			cap = strings.TrimSpace(cap)
			if cap == "" {
				continue
			}
			svc.GrantCapability(subject, cap)
		}
	}
}

func (a *Adapter) validateCapabilities(ctx context.Context, role string, caps []string) error {
	for _, cap := range caps {
		allowed, err := a.roleHasCapability(ctx, role, cap)
		if err != nil {
			return fmt.Errorf("capability check failed: %w", err)
		}
		if !allowed {
			return fmt.Errorf("capability denied: role=%s missing %s", role, cap)
		}
	}
	return nil
}

func (a *Adapter) roleHasCapability(ctx context.Context, role, capability string) (bool, error) {
	for _, candidate := range expandedRoles(role) {
		if security.CheckCapability(candidate, capability) {
			return true, nil
		}
	}
	if a == nil || a.secopsPerms == nil {
		return false, nil
	}
	for _, subject := range capabilityGrantSubjects(ctx, role) {
		ok, err := a.secopsPerms.CheckCapability(subject, capability)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
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

func capabilityGrantSubjects(ctx context.Context, role string) []string {
	var subjects []string
	seen := make(map[string]struct{})

	add := func(subject string) {
		subject = strings.ToLower(strings.TrimSpace(subject))
		if subject == "" {
			return
		}
		if _, ok := seen[subject]; ok {
			return
		}
		seen[subject] = struct{}{}
		subjects = append(subjects, subject)
	}

	add(role)
	for _, candidate := range expandedRoles(role) {
		add(candidate)
	}
	add(tools.GetAgentIDFromContext(ctx))

	return subjects
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
	case config.AgentTask:
		// Task agent needs operator-level to run read-only diagnostics and reports.
		return "operator"
	case config.AgentCoder:
		// Coder agent works on source code and does not require SecOps privileges.
		return "viewer"
	case config.AgentPlanner:
		// Planner explores read-only and must not inherit elevated SecOps roles.
		return "viewer"
	default:
		// Fail-safe: unknown agents get the least-privilege role.
		return "viewer"
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
