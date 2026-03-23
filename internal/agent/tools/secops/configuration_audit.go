package secops

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ConfigAuditTarget 配置审计目标
type ConfigAuditTarget string

const (
	ConfigSSH       ConfigAuditTarget = "ssh"
	ConfigSudo      ConfigAuditTarget = "sudo"
	ConfigFirewall  ConfigAuditTarget = "firewall"
	ConfigFilePerms ConfigAuditTarget = "file_permissions"
	ConfigKernel    ConfigAuditTarget = "kernel"
	ConfigSysctl    ConfigAuditTarget = "sysctl"
)

// ConfigAuditParams 配置审计参数
type ConfigAuditParams struct {
	Targets        []ConfigAuditTarget `json:"targets"`                // 审计目标
	CheckSecurity  bool                `json:"check_security"`         // 检查安全配置
	CheckCompliance bool               `json:"check_compliance"`       // 检查合规配置
	CheckPerformance bool              `json:"check_performance"`      // 检查性能配置
	Deep           bool                `json:"deep,omitempty"`         // 深度检查
	CustomRules    []string            `json:"custom_rules,omitempty"` // 自定义规则
	RemoteHost     string              `json:"remote_host,omitempty"`
	RemoteUser     string              `json:"remote_user,omitempty"`
	RemotePort     int                 `json:"remote_port,omitempty"`
	RemoteKeyPath  string              `json:"remote_key_path,omitempty"`
	RemoteProxyJump string             `json:"remote_proxy_jump,omitempty"`
}

// ConfigAuditRule 配置审计规则
type ConfigAuditRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`        // critical, high, medium, low
	Category    string `json:"category"`        // security, compliance, performance
	Parameter   string `json:"parameter"`       // 配置参数名
	Target      ConfigAuditTarget `json:"target"`
	RecommendedValue string `json:"recommended_value"`
	CurrentValue string `json:"current_value,omitempty"`
	Status      string `json:"status"`         // pass, fail, warning, info
	Remediation string `json:"remediation"`
}

// ConfigAuditResult 配置审计结果
type ConfigAuditResult struct {
	Timestamp        time.Time          `json:"timestamp"`
	SystemInfo       string             `json:"system_info"`
	TotalRules       int                `json:"total_rules"`
	PassedRules      int                `json:"passed_rules"`
	FailedRules      int                `json:"failed_rules"`
	WarningRules     int                `json:"warning_rules"`
	InfoRules        int                `json:"info_rules"`
	Score            float64            `json:"score"`             // 0-100
	RiskLevel        string             `json:"risk_level"`        // critical, high, medium, low
	Rules            []*ConfigAuditRule `json:"rules"`
	Recommendations  []string           `json:"recommendations,omitempty"`
}

// ConfigurationAuditTool 配置审计工具
type ConfigurationAuditTool struct {
	registry *SecOpsToolRegistry
}

// NewConfigurationAuditTool 创建配置审计工具
func NewConfigurationAuditTool(registry *SecOpsToolRegistry) *ConfigurationAuditTool {
	return &ConfigurationAuditTool{
		registry: registry,
	}
}

// Type 实现 Tool.Type
func (cat *ConfigurationAuditTool) Type() ToolType {
	return ToolTypeConfigurationAudit
}

// Name 实现 Tool.Name
func (cat *ConfigurationAuditTool) Name() string {
	return "Configuration Auditor"
}

// Description 实现 Tool.Description
func (cat *ConfigurationAuditTool) Description() string {
	return "Audit system configurations (SSH, sudo, firewall, file permissions) for security and compliance"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (cat *ConfigurationAuditTool) RequiredCapabilities() []string {
	return []string{
		"file:read",
		"compliance:check",
		"system:query",
	}
}

// ValidateParams 实现 Tool.ValidateParams
func (cat *ConfigurationAuditTool) ValidateParams(params interface{}) error {
	p, ok := params.(*ConfigAuditParams)
	if !ok {
		return ErrInvalidParams
	}

	if len(p.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}

	for _, target := range p.Targets {
		if !cat.isValidTarget(target) {
			return fmt.Errorf("invalid target: %s", target)
		}
	}
	if p.RemotePort < 0 || p.RemotePort > 65535 {
		return fmt.Errorf("remote_port must be between 1 and 65535")
	}
	if strings.TrimSpace(p.RemoteHost) == "" {
		if strings.TrimSpace(p.RemoteUser) != "" || p.RemotePort > 0 ||
			strings.TrimSpace(p.RemoteKeyPath) != "" || strings.TrimSpace(p.RemoteProxyJump) != "" {
			return fmt.Errorf("remote_host is required when remote ssh options are set")
		}
	}

	return nil
}

// Execute 实现 Tool.Execute
func (cat *ConfigurationAuditTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*ConfigAuditParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := cat.ValidateParams(p); err != nil {
		return nil, err
	}

	result := &ConfigAuditResult{
		Timestamp:       time.Now(),
		SystemInfo:      "Linux 5.10.0",
		Rules:           make([]*ConfigAuditRule, 0),
		Recommendations: make([]string, 0),
	}
	if strings.TrimSpace(p.RemoteHost) != "" {
		result.SystemInfo = "remote:" + formatAuditRemoteTarget(p.RemoteUser, p.RemoteHost)
	}

	// 为每个目标执行审计
	for _, target := range p.Targets {
		rules := cat.getRulesForTarget(target, p)
		result.Rules = append(result.Rules, rules...)
	}

	// 审计每个规则
	for _, rule := range result.Rules {
		cat.auditRule(rule, p)

		switch rule.Status {
		case "pass":
			result.PassedRules++
		case "fail":
			result.FailedRules++
		case "warning":
			result.WarningRules++
		case "info":
			result.InfoRules++
		}
	}

	result.TotalRules = len(result.Rules)

	// 计算评分
	result.Score = cat.calculateScore(result)
	result.RiskLevel = cat.determineRiskLevel(result)

	// 生成建议
	result.Recommendations = cat.generateRecommendations(result)

	return result, nil
}

// 私有方法

// isValidTarget 检查目标是否有效
func (cat *ConfigurationAuditTool) isValidTarget(target ConfigAuditTarget) bool {
	switch target {
	case ConfigSSH, ConfigSudo, ConfigFirewall, ConfigFilePerms, ConfigKernel, ConfigSysctl:
		return true
	default:
		return false
	}
}

// getRulesForTarget 获取目标的审计规则
func (cat *ConfigurationAuditTool) getRulesForTarget(target ConfigAuditTarget, params *ConfigAuditParams) []*ConfigAuditRule {
	switch target {
	case ConfigSSH:
		return cat.getSSHRules(params)
	case ConfigSudo:
		return cat.getSudoRules(params)
	case ConfigFirewall:
		return cat.getFirewallRules(params)
	case ConfigFilePerms:
		return cat.getFilePermRules(params)
	case ConfigKernel:
		return cat.getKernelRules(params)
	case ConfigSysctl:
		return cat.getSysctlRules(params)
	default:
		return make([]*ConfigAuditRule, 0)
	}
}

// getSSHRules SSH 配置规则
func (cat *ConfigurationAuditTool) getSSHRules(params *ConfigAuditParams) []*ConfigAuditRule {
	return []*ConfigAuditRule{
		{
			ID:               "SSH-001",
			Name:             "SSH Root Login",
			Description:      "Check if direct root login is disabled",
			Severity:         "critical",
			Category:         "security",
			Parameter:        "PermitRootLogin",
			Target:           ConfigSSH,
			RecommendedValue: "no",
			Status:           "pass",
		},
		{
			ID:               "SSH-002",
			Name:             "SSH Password Auth",
			Description:      "Check if password authentication is disabled",
			Severity:         "high",
			Category:         "security",
			Parameter:        "PasswordAuthentication",
			Target:           ConfigSSH,
			RecommendedValue: "no",
			Status:           "pass",
		},
		{
			ID:               "SSH-003",
			Name:             "SSH Key Exchange",
			Description:      "Check if weak key exchange algorithms are disabled",
			Severity:         "medium",
			Category:         "security",
			Parameter:        "KexAlgorithms",
			Target:           ConfigSSH,
			RecommendedValue: "strong algorithms only",
			Status:           "warning",
			Remediation:      "Disable weak KEX algorithms like diffie-hellman-group1-sha1",
		},
	}
}

// getSudoRules Sudo 配置规则
func (cat *ConfigurationAuditTool) getSudoRules(params *ConfigAuditParams) []*ConfigAuditRule {
	return []*ConfigAuditRule{
		{
			ID:               "SUDO-001",
			Name:             "Sudo Logging",
			Description:      "Check if sudo commands are logged",
			Severity:         "high",
			Category:         "compliance",
			Parameter:        "log_output",
			Target:           ConfigSudo,
			RecommendedValue: "enabled",
			Status:           "fail",
			Remediation:      "Enable sudo command logging with 'log_output'",
		},
		{
			ID:               "SUDO-002",
			Name:             "Sudo NOPASSWD",
			Description:      "Check for NOPASSWD entries",
			Severity:         "critical",
			Category:         "security",
			Parameter:        "NOPASSWD",
			Target:           ConfigSudo,
			RecommendedValue: "none",
			Status:           "pass",
		},
	}
}

// getFirewallRules 防火墙配置规则
func (cat *ConfigurationAuditTool) getFirewallRules(params *ConfigAuditParams) []*ConfigAuditRule {
	return []*ConfigAuditRule{
		{
			ID:               "FW-001",
			Name:             "Firewall Enabled",
			Description:      "Check if firewall is enabled",
			Severity:         "critical",
			Category:         "security",
			Parameter:        "enabled",
			Target:           ConfigFirewall,
			RecommendedValue: "true",
			Status:           "pass",
		},
		{
			ID:               "FW-002",
			Name:             "Default Inbound Policy",
			Description:      "Check default inbound policy",
			Severity:         "high",
			Category:         "security",
			Parameter:        "default_inbound",
			Target:           ConfigFirewall,
			RecommendedValue: "DROP",
			Status:           "pass",
		},
	}
}

// getFilePermRules 文件权限规则
func (cat *ConfigurationAuditTool) getFilePermRules(params *ConfigAuditParams) []*ConfigAuditRule {
	return []*ConfigAuditRule{
		{
			ID:               "FP-001",
			Name:             "Passwd File Permissions",
			Description:      "Check /etc/passwd permissions",
			Severity:         "high",
			Category:         "security",
			Parameter:        "/etc/passwd",
			Target:           ConfigFilePerms,
			RecommendedValue: "0644",
			Status:           "pass",
		},
		{
			ID:               "FP-002",
			Name:             "Shadow File Permissions",
			Description:      "Check /etc/shadow permissions",
			Severity:         "critical",
			Category:         "security",
			Parameter:        "/etc/shadow",
			Target:           ConfigFilePerms,
			RecommendedValue: "0640",
			Status:           "fail",
			Remediation:      "Set /etc/shadow permissions to 0640",
		},
	}
}

// getKernelRules 内核配置规则
func (cat *ConfigurationAuditTool) getKernelRules(params *ConfigAuditParams) []*ConfigAuditRule {
	return []*ConfigAuditRule{
		{
			ID:               "KER-001",
			Name:             "ASLR",
			Description:      "Check Address Space Layout Randomization",
			Severity:         "medium",
			Category:         "security",
			Parameter:        "kernel.randomize_va_space",
			Target:           ConfigKernel,
			RecommendedValue: "2",
			Status:           "pass",
		},
	}
}

// getSysctlRules Sysctl 配置规则
func (cat *ConfigurationAuditTool) getSysctlRules(params *ConfigAuditParams) []*ConfigAuditRule {
	return []*ConfigAuditRule{
		{
			ID:               "SYS-001",
			Name:             "IP Forwarding",
			Description:      "Check if IP forwarding is disabled",
			Severity:         "medium",
			Category:         "security",
			Parameter:        "net.ipv4.ip_forward",
			Target:           ConfigSysctl,
			RecommendedValue: "0",
			Status:           "pass",
		},
	}
}

// auditRule 审计单个规则
func (cat *ConfigurationAuditTool) auditRule(rule *ConfigAuditRule, params *ConfigAuditParams) {
	_ = params

	switch rule.ID {
	case "SSH-001":
		v, ok := readSSHDConfigValueForParams(params, "PermitRootLogin")
		if !ok {
			rule.Status = "warning"
			rule.CurrentValue = "unknown"
			rule.Remediation = "Ensure PermitRootLogin is set to no in sshd_config"
			return
		}
		rule.CurrentValue = v
		if strings.EqualFold(v, "no") {
			rule.Status = "pass"
		} else {
			rule.Status = "fail"
			rule.Remediation = "Set PermitRootLogin no in sshd_config"
		}
	case "SSH-002":
		v, ok := readSSHDConfigValueForParams(params, "PasswordAuthentication")
		if !ok {
			rule.Status = "warning"
			rule.CurrentValue = "unknown"
			rule.Remediation = "Ensure PasswordAuthentication is set to no in sshd_config"
			return
		}
		rule.CurrentValue = v
		if strings.EqualFold(v, "no") {
			rule.Status = "pass"
		} else {
			rule.Status = "fail"
			rule.Remediation = "Set PasswordAuthentication no in sshd_config"
		}
	case "SSH-003":
		v, ok := readSSHDConfigValueForParams(params, "KexAlgorithms")
		if !ok || strings.TrimSpace(v) == "" {
			rule.Status = "warning"
			rule.CurrentValue = "unknown"
			return
		}
		rule.CurrentValue = v
		if strings.Contains(strings.ToLower(v), "diffie-hellman-group1-sha1") {
			rule.Status = "warning"
		} else {
			rule.Status = "pass"
		}
	case "SUDO-001":
		v, ok := hasSudoLogOutputForParams(params)
		if !ok {
			rule.Status = "warning"
			rule.CurrentValue = "unknown"
			return
		}
		if v {
			rule.Status = "pass"
			rule.CurrentValue = "enabled"
		} else {
			rule.Status = "fail"
			rule.CurrentValue = "disabled"
			rule.Remediation = "Enable sudo log_output in sudoers or sudoers.d"
		}
	case "SUDO-002":
		v, ok := hasSudoNoPasswordForParams(params)
		if !ok {
			rule.Status = "warning"
			rule.CurrentValue = "unknown"
			return
		}
		if v {
			rule.Status = "fail"
			rule.CurrentValue = "present"
			rule.Remediation = "Remove NOPASSWD entries from sudoers policy"
		} else {
			rule.Status = "pass"
			rule.CurrentValue = "none"
		}
	case "FW-001":
		enabled, current := firewallEnabledForParams(params)
		rule.CurrentValue = current
		if strings.EqualFold(current, "unknown") {
			rule.Status = "warning"
			return
		}
		if enabled {
			rule.Status = "pass"
		} else {
			rule.Status = "fail"
			rule.Remediation = "Enable host firewall (ufw/firewalld/iptables policy)"
		}
	case "FW-002":
		ok, current := defaultInboundDropForParams(params)
		rule.CurrentValue = current
		if strings.EqualFold(current, "unknown") {
			rule.Status = "warning"
			return
		}
		if ok {
			rule.Status = "pass"
		} else {
			rule.Status = "fail"
			rule.Remediation = "Set default inbound policy to DROP/deny"
		}
	case "FP-001", "FP-002":
		mode, ok := readFileModeForParams(params, rule.Parameter)
		if !ok {
			rule.Status = "warning"
			rule.CurrentValue = "missing"
			return
		}
		rule.CurrentValue = mode
		if mode == rule.RecommendedValue {
			rule.Status = "pass"
		} else {
			rule.Status = "fail"
			rule.Remediation = fmt.Sprintf("Set %s permissions to %s", rule.Parameter, rule.RecommendedValue)
		}
	case "KER-001":
		v, ok := readSysctlValueForParams(params, "kernel.randomize_va_space")
		if !ok {
			rule.Status = "warning"
			rule.CurrentValue = "unknown"
			return
		}
		rule.CurrentValue = v
		if strings.TrimSpace(v) == "2" {
			rule.Status = "pass"
		} else {
			rule.Status = "fail"
			rule.Remediation = "Set kernel.randomize_va_space=2"
		}
	case "SYS-001":
		v, ok := readSysctlValueForParams(params, "net.ipv4.ip_forward")
		if !ok {
			rule.Status = "warning"
			rule.CurrentValue = "unknown"
			return
		}
		rule.CurrentValue = v
		if strings.TrimSpace(v) == "0" {
			rule.Status = "pass"
		} else {
			rule.Status = "fail"
			rule.Remediation = "Set net.ipv4.ip_forward=0 unless routing is required"
		}
	}
}

func readSSHDConfigValueForParams(params *ConfigAuditParams, key string) (string, bool) {
	if params == nil || strings.TrimSpace(params.RemoteHost) == "" {
		return readSSHDConfigValue(key)
	}
	return remoteReadSSHDConfigValue(params, key)
}

func hasSudoLogOutputForParams(params *ConfigAuditParams) (bool, bool) {
	if params == nil || strings.TrimSpace(params.RemoteHost) == "" {
		return hasSudoLogOutput()
	}
	lines, ok := readRemoteSudoPolicyLines(params)
	if !ok {
		return false, false
	}
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "log_output") {
			return true, true
		}
	}
	return false, true
}

func hasSudoNoPasswordForParams(params *ConfigAuditParams) (bool, bool) {
	if params == nil || strings.TrimSpace(params.RemoteHost) == "" {
		return hasSudoNoPassword()
	}
	lines, ok := readRemoteSudoPolicyLines(params)
	if !ok {
		return false, false
	}
	for _, line := range lines {
		if strings.Contains(strings.ToUpper(line), "NOPASSWD") {
			return true, true
		}
	}
	return false, true
}

func firewallEnabledForParams(params *ConfigAuditParams) (bool, string) {
	if params == nil || strings.TrimSpace(params.RemoteHost) == "" {
		return firewallEnabled()
	}

	if out, ok := runRemoteCommand(params, "ufw status"); ok {
		s := strings.ToLower(out)
		if strings.Contains(s, "status: active") {
			return true, "ufw:active"
		}
		if strings.Contains(s, "status: inactive") {
			return false, "ufw:inactive"
		}
	}
	if out, ok := runRemoteCommand(params, "firewall-cmd --state"); ok {
		s := strings.TrimSpace(strings.ToLower(out))
		if s == "running" {
			return true, "firewalld:running"
		}
		return false, "firewalld:" + s
	}
	if out, ok := runRemoteCommand(params, "iptables -S"); ok {
		if strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-P INPUT REJECT") {
			return true, "iptables:default_restrictive"
		}
		if strings.Contains(out, "-A INPUT") {
			return true, "iptables:rules_present"
		}
		return false, "iptables:no_rules"
	}
	return false, "unknown"
}

func defaultInboundDropForParams(params *ConfigAuditParams) (bool, string) {
	if params == nil || strings.TrimSpace(params.RemoteHost) == "" {
		return defaultInboundDrop()
	}
	if out, ok := runRemoteCommand(params, "ufw status verbose"); ok {
		s := strings.ToLower(out)
		if strings.Contains(s, "default: deny (incoming)") {
			return true, "ufw:deny"
		}
		if strings.Contains(s, "default: allow (incoming)") {
			return false, "ufw:allow"
		}
	}
	if out, ok := runRemoteCommand(params, "iptables -S"); ok {
		if strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-P INPUT REJECT") {
			return true, "iptables:drop"
		}
		if strings.Contains(out, "-P INPUT ACCEPT") {
			return false, "iptables:accept"
		}
	}
	return false, "unknown"
}

func readFileModeForParams(params *ConfigAuditParams, path string) (string, bool) {
	if params == nil || strings.TrimSpace(params.RemoteHost) == "" {
		return readFileMode(path)
	}
	out, ok := runRemoteCommand(params, "stat -c '%a' "+auditShellQuote(path))
	if !ok {
		return "", false
	}
	mode := strings.TrimSpace(out)
	if mode == "" {
		return "", false
	}
	return mode, true
}

func readSysctlValueForParams(params *ConfigAuditParams, key string) (string, bool) {
	if params == nil || strings.TrimSpace(params.RemoteHost) == "" {
		return readSysctlValue(key)
	}
	procPath := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	if out, ok := runRemoteCommand(params, "cat "+auditShellQuote(procPath)); ok {
		v := strings.TrimSpace(out)
		if v != "" {
			return v, true
		}
	}
	out, ok := runRemoteCommand(params, "sysctl -n "+auditShellQuote(key))
	if !ok {
		return "", false
	}
	v := strings.TrimSpace(out)
	return v, v != ""
}

func remoteReadSSHDConfigValue(params *ConfigAuditParams, key string) (string, bool) {
	paths := []string{
		"/etc/ssh/sshd_config",
		"/usr/local/etc/ssh/sshd_config",
	}
	lowerKey := strings.ToLower(strings.TrimSpace(key))
	for _, path := range paths {
		cmd := "awk 'tolower($1)==\"" + lowerKey + "\" {for (i=2; i<=NF; i++) printf $i (i==NF?\"\":\" \"); print \"\"}' " + auditShellQuote(path) + " | tail -n 1"
		if out, ok := runRemoteCommand(params, cmd); ok {
			v := strings.TrimSpace(out)
			if v != "" {
				return v, true
			}
		}
	}
	return "", false
}

func readRemoteSudoPolicyLines(params *ConfigAuditParams) ([]string, bool) {
	cmd := "cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed -e 's/#.*$//' -e '/^\\s*$/d'"
	out, ok := runRemoteCommand(params, cmd)
	if !ok {
		return nil, false
	}
	lines := make([]string, 0)
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines, len(lines) > 0
}

func runRemoteCommand(params *ConfigAuditParams, remoteCommand string) (string, bool) {
	if params == nil {
		return "", false
	}
	host := strings.TrimSpace(params.RemoteHost)
	if host == "" {
		return "", false
	}

	target := formatAuditRemoteTarget(params.RemoteUser, host)
	args := []string{"-o", "BatchMode=yes"}
	if params.RemotePort > 0 {
		args = append(args, "-p", strconv.Itoa(params.RemotePort))
	}
	if key := strings.TrimSpace(params.RemoteKeyPath); key != "" {
		args = append(args, "-i", key)
	}
	if jump := strings.TrimSpace(params.RemoteProxyJump); jump != "" {
		args = append(args, "-J", jump)
	}
	args = append(args, target, "sh", "-lc", remoteCommand)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh", args...).CombinedOutput()
	if err != nil {
		return "", false
	}
	return string(out), true
}

func formatAuditRemoteTarget(user, host string) string {
	u := strings.TrimSpace(user)
	h := strings.TrimSpace(host)
	if u == "" {
		return h
	}
	return u + "@" + h
}

func auditShellQuote(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

// calculateScore 计算审计评分
func (cat *ConfigurationAuditTool) calculateScore(result *ConfigAuditResult) float64 {
	if result.TotalRules == 0 {
		return 100
	}

	passed := float64(result.PassedRules)
	warning := float64(result.WarningRules)
	total := float64(result.TotalRules)

	score := (passed*100 + warning*50) / total
	return score
}

// determineRiskLevel 确定风险等级
func (cat *ConfigurationAuditTool) determineRiskLevel(result *ConfigAuditResult) string {
	if result.FailedRules > 0 {
		if result.Score < 50 {
			return "critical"
		} else if result.Score < 70 {
			return "high"
		}
		return "medium"
	}

	if result.WarningRules > 0 {
		return "low"
	}

	return "pass"
}

// generateRecommendations 生成建议
func (cat *ConfigurationAuditTool) generateRecommendations(result *ConfigAuditResult) []string {
	recommendations := make([]string, 0)

	if result.FailedRules > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("CRITICAL: Fix %d failed configuration rules immediately", result.FailedRules))

		for _, rule := range result.Rules {
			if rule.Status == "fail" && rule.Remediation != "" {
				recommendations = append(recommendations, fmt.Sprintf("%s: %s", rule.ID, rule.Remediation))
			}
		}
	}

	if result.WarningRules > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("WARNING: Review %d warning-level configuration issues", result.WarningRules))
	}

	if result.TotalRules == 0 {
		recommendations = append(recommendations, "No rules to audit")
	}

	return recommendations
}

func readSSHDConfigValue(key string) (string, bool) {
	paths := []string{
		"/etc/ssh/sshd_config",
		"/usr/local/etc/ssh/sshd_config",
	}

	lowerKey := strings.ToLower(key)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			fields := strings.Fields(trimmed)
			if len(fields) < 2 {
				continue
			}
			if strings.ToLower(fields[0]) == lowerKey {
				return strings.Join(fields[1:], " "), true
			}
		}
	}
	return "", false
}

func hasSudoLogOutput() (bool, bool) {
	lines, ok := readSudoPolicyLines()
	if !ok {
		return false, false
	}
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "log_output") {
			return true, true
		}
	}
	return false, true
}

func hasSudoNoPassword() (bool, bool) {
	lines, ok := readSudoPolicyLines()
	if !ok {
		return false, false
	}
	for _, line := range lines {
		if strings.Contains(strings.ToUpper(line), "NOPASSWD") {
			return true, true
		}
	}
	return false, true
}

func readSudoPolicyLines() ([]string, bool) {
	paths := []string{"/etc/sudoers"}
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			paths = append(paths, filepath.Join("/etc/sudoers.d", entry.Name()))
		}
	}

	lines := make([]string, 0)
	found := false
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		found = true
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			lines = append(lines, trimmed)
		}
	}
	return lines, found
}

func firewallEnabled() (bool, string) {
	if out, err := exec.Command("ufw", "status").CombinedOutput(); err == nil {
		s := strings.ToLower(string(out))
		if strings.Contains(s, "status: active") {
			return true, "ufw:active"
		}
		if strings.Contains(s, "status: inactive") {
			return false, "ufw:inactive"
		}
	}

	if out, err := exec.Command("firewall-cmd", "--state").CombinedOutput(); err == nil {
		s := strings.TrimSpace(strings.ToLower(string(out)))
		if s == "running" {
			return true, "firewalld:running"
		}
		return false, "firewalld:"+s
	}

	if out, err := exec.Command("iptables", "-S").CombinedOutput(); err == nil {
		s := string(out)
		if strings.Contains(s, "-P INPUT DROP") || strings.Contains(s, "-P INPUT REJECT") {
			return true, "iptables:default_restrictive"
		}
		if strings.Contains(s, "-A INPUT") {
			return true, "iptables:rules_present"
		}
		return false, "iptables:no_rules"
	}

	return false, "unknown"
}

func defaultInboundDrop() (bool, string) {
	if out, err := exec.Command("ufw", "status", "verbose").CombinedOutput(); err == nil {
		s := strings.ToLower(string(out))
		if strings.Contains(s, "default: deny (incoming)") {
			return true, "ufw:deny"
		}
		if strings.Contains(s, "default: allow (incoming)") {
			return false, "ufw:allow"
		}
	}

	if out, err := exec.Command("iptables", "-S").CombinedOutput(); err == nil {
		s := string(out)
		if strings.Contains(s, "-P INPUT DROP") || strings.Contains(s, "-P INPUT REJECT") {
			return true, "iptables:drop"
		}
		if strings.Contains(s, "-P INPUT ACCEPT") {
			return false, "iptables:accept"
		}
	}

	return false, "unknown"
}

func readFileMode(path string) (string, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	mode := info.Mode().Perm()
	return fmt.Sprintf("%04o", mode), true
}

func readSysctlValue(key string) (string, bool) {
	procPath := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	if data, err := os.ReadFile(procPath); err == nil {
		return strings.TrimSpace(string(data)), true
	}

	cmd := exec.Command("sysctl", "-n", key)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(bytes.TrimSpace(out))), true
}
