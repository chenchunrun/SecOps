package secops

import (
	"fmt"
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
	// 在实际实现中，这里会读取系统配置并与规则比较
	// 目前使用模拟数据
	_ = params
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
