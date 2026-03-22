package secops

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ComplianceFramework 合规框架
type ComplianceFramework string

const (
	FrameworkCIS         ComplianceFramework = "cis"
	FrameworkPCIDSS      ComplianceFramework = "pci_dss"
	FrameworkSOC2        ComplianceFramework = "soc2"
	FrameworkHIPAA       ComplianceFramework = "hipaa"
	FrameworkISO27001    ComplianceFramework = "iso27001"
	FrameworkDockerBench ComplianceFramework = "docker_bench"
)

var (
	iso27001PolicyPaths = []string{
		"/etc/security/iso27001-policy",
		"/etc/security/policy",
	}
	iso27001AuditLogPaths = []string{
		"/var/log/audit/audit.log",
		"/var/log/auth.log",
		"/var/log/secure",
	}
	iso27001AccessControlPath = "/etc/shadow"

	dockerBenchDaemonConfigPath = "/etc/docker/daemon.json"
	dockerBenchSocketPath       = "/var/run/docker.sock"
	dockerBenchIPForwardPath    = "/proc/sys/net/ipv4/ip_forward"
)

// ComplianceStatus 合规状态
type ComplianceStatus string

const (
	StatusPassed        ComplianceStatus = "passed"
	StatusFailed        ComplianceStatus = "failed"
	StatusWarning       ComplianceStatus = "warning"
	StatusNotApplicable ComplianceStatus = "not_applicable"
)

// ComplianceSeverity 合规严重级别
type ComplianceSeverity string

const (
	SeverityHigh   ComplianceSeverity = "high"
	SeverityMedium ComplianceSeverity = "medium"
	SeverityLow    ComplianceSeverity = "low"
	SeverityInfo   ComplianceSeverity = "info"
)

// ComplianceCheckParams 合规检查参数
type ComplianceCheckParams struct {
	// 框架选择
	Framework ComplianceFramework `json:"framework"`

	// 检查范围
	Categories []string `json:"categories,omitempty"` // e.g., ["system", "network", "access"]
	RuleIDs    []string `json:"rule_ids,omitempty"`   // 指定规则ID

	// 检查选项
	Full      bool `json:"full,omitempty"`       // 全面检查 vs 快速检查
	FixIssues bool `json:"fix_issues,omitempty"` // 自动修复
	Timeout   int  `json:"timeout,omitempty"`    // 检查超时（秒）

	// 输出选项
	IncludeRemediation bool `json:"include_remediation,omitempty"`
}

// ComplianceRule 合规规则
type ComplianceRule struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    ComplianceSeverity     `json:"severity"`
	Framework   ComplianceFramework    `json:"framework"`
	Category    string                 `json:"category"`
	Status      ComplianceStatus       `json:"status"`
	Evidence    string                 `json:"evidence,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Remediation *Remediation           `json:"remediation,omitempty"`
	Impact      string                 `json:"impact,omitempty"`
	LastChecked time.Time              `json:"last_checked"`
}

// Remediation 补救步骤
type Remediation struct {
	Description  string   `json:"description"`
	Steps        []string `json:"steps"`
	Priority     int      `json:"priority"`      // 1-5，数字越高优先级越高
	Difficulty   string   `json:"difficulty"`    // easy, medium, hard
	TimeEstimate int      `json:"time_estimate"` // 分钟
	Automated    bool     `json:"automated"`
}

// ComplianceCheckResult 合规检查结果
type ComplianceCheckResult struct {
	Framework       ComplianceFramework `json:"framework"`
	CheckTime       time.Time           `json:"check_time"`
	TotalRules      int                 `json:"total_rules"`
	PassedRules     int                 `json:"passed_rules"`
	FailedRules     int                 `json:"failed_rules"`
	WarningRules    int                 `json:"warning_rules"`
	Score           float64             `json:"score"` // 0-100
	Status          ComplianceStatus    `json:"status"`
	Rules           []*ComplianceRule   `json:"rules"`
	Summary         *ComplianceSummary  `json:"summary,omitempty"`
	Recommendations []*Recommendation   `json:"recommendations,omitempty"`
}

// ComplianceSummary 合规摘要
type ComplianceSummary struct {
	HighPriority     int  `json:"high_priority_issues"`
	MediumPriority   int  `json:"medium_priority_issues"`
	LowPriority      int  `json:"low_priority_issues"`
	TrendImprovement bool `json:"trend_improvement"`
}

// Recommendation 建议
type Recommendation struct {
	Title       string  `json:"title"`
	Priority    int     `json:"priority"`
	ImpactScore float64 `json:"impact_score"` // 0-1
	Effort      string  `json:"effort"`       // low, medium, high
}

// ComplianceCheckTool 合规检查工具
type ComplianceCheckTool struct {
	registry *SecOpsToolRegistry
}

// NewComplianceCheckTool 创建合规检查工具
func NewComplianceCheckTool(registry *SecOpsToolRegistry) *ComplianceCheckTool {
	return &ComplianceCheckTool{
		registry: registry,
	}
}

// Type 实现 Tool.Type
func (cct *ComplianceCheckTool) Type() ToolType {
	return ToolTypeComplianceCheck
}

// Name 实现 Tool.Name
func (cct *ComplianceCheckTool) Name() string {
	return "Compliance Checker"
}

// Description 实现 Tool.Description
func (cct *ComplianceCheckTool) Description() string {
	return "Check system compliance against various frameworks (CIS, Docker Bench, PCI-DSS, SOC2, HIPAA, ISO27001)"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (cct *ComplianceCheckTool) RequiredCapabilities() []string {
	return []string{
		"compliance:check",
		"compliance:report",
	}
}

// ValidateParams 实现 Tool.ValidateParams
func (cct *ComplianceCheckTool) ValidateParams(params interface{}) error {
	p, ok := params.(*ComplianceCheckParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.Framework == "" {
		return fmt.Errorf("framework is required")
	}

	// 验证框架
	validFrameworks := map[ComplianceFramework]bool{
		FrameworkCIS:         true,
		FrameworkPCIDSS:      true,
		FrameworkSOC2:        true,
		FrameworkHIPAA:       true,
		FrameworkISO27001:    true,
		FrameworkDockerBench: true,
	}

	if !validFrameworks[p.Framework] {
		return fmt.Errorf("unsupported framework: %s", p.Framework)
	}

	if p.Timeout < 0 {
		return fmt.Errorf("timeout cannot be negative")
	}

	for _, category := range p.Categories {
		if strings.TrimSpace(category) == "" {
			return fmt.Errorf("categories cannot contain empty values")
		}
	}
	for _, ruleID := range p.RuleIDs {
		if strings.TrimSpace(ruleID) == "" {
			return fmt.Errorf("rule_ids cannot contain empty values")
		}
	}

	return nil
}

// Execute 实现 Tool.Execute
func (cct *ComplianceCheckTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*ComplianceCheckParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := cct.ValidateParams(p); err != nil {
		return nil, err
	}

	// 执行合规检查
	result := cct.runComplianceCheck(p)
	return result, nil
}

// 私有方法

// runComplianceCheck 运行合规检查
func (cct *ComplianceCheckTool) runComplianceCheck(params *ComplianceCheckParams) *ComplianceCheckResult {
	result := &ComplianceCheckResult{
		Framework:       params.Framework,
		CheckTime:       time.Now(),
		Rules:           make([]*ComplianceRule, 0),
		Recommendations: make([]*Recommendation, 0),
	}

	// 根据框架获取规则
	rules := cct.getRulesForFramework(params.Framework, params.Categories)

	// 过滤规则
	if len(params.RuleIDs) > 0 {
		rules = cct.filterRulesByID(rules, params.RuleIDs)
	}

	// 执行检查
	for _, rule := range rules {
		cct.checkRule(rule, params.Full)
		result.Rules = append(result.Rules, rule)

		// 统计
		result.TotalRules++
		switch rule.Status {
		case StatusPassed:
			result.PassedRules++
		case StatusFailed:
			result.FailedRules++
		case StatusWarning:
			result.WarningRules++
		}
	}

	// 计算合规分数
	result.Score = cct.calculateScore(result)

	// 确定总体状态
	result.Status = cct.determineStatus(result)

	// 生成摘要
	result.Summary = cct.generateSummary(result)

	// 生成建议
	result.Recommendations = cct.generateRecommendations(result)

	return result
}

// getRulesForFramework 获取框架的规则
func (cct *ComplianceCheckTool) getRulesForFramework(framework ComplianceFramework, categories []string) []*ComplianceRule {
	rules := make([]*ComplianceRule, 0)

	switch framework {
	case FrameworkCIS:
		rules = cct.getCISRules()
	case FrameworkPCIDSS:
		rules = cct.getPCIDSSRules()
	case FrameworkSOC2:
		rules = cct.getSOC2Rules()
	case FrameworkHIPAA:
		rules = cct.getHIPAARules()
	case FrameworkISO27001:
		rules = cct.getISO27001Rules()
	case FrameworkDockerBench:
		rules = cct.getDockerBenchRules()
	}

	// 按类别过滤
	if len(categories) > 0 {
		filtered := make([]*ComplianceRule, 0)
		categoryMap := make(map[string]bool)
		for _, cat := range categories {
			categoryMap[cat] = true
		}

		for _, rule := range rules {
			if categoryMap[rule.Category] {
				filtered = append(filtered, rule)
			}
		}
		rules = filtered
	}

	return rules
}

// getCISRules 获取 CIS Benchmark 规则
func (cct *ComplianceCheckTool) getCISRules() []*ComplianceRule {
	return []*ComplianceRule{
		{
			ID:          "cis_1_1",
			Title:       "Ensure filesystem configuration is done",
			Description: "Proper filesystem configuration is the foundation of a secure system",
			Severity:    SeverityHigh,
			Framework:   FrameworkCIS,
			Category:    "filesystem",
			Status:      StatusFailed,
			Evidence:    "Found insecure filesystem configuration",
		},
		{
			ID:          "cis_2_1",
			Title:       "Ensure X Window System is not installed",
			Description: "Unless your use case requires graphical user interface, it is advisable to leave X11 uninstalled",
			Severity:    SeverityMedium,
			Framework:   FrameworkCIS,
			Category:    "packages",
			Status:      StatusPassed,
			Evidence:    "X Window System is not installed",
		},
		{
			ID:          "cis_3_1",
			Title:       "Ensure IP forwarding is disabled",
			Description: "IP forwarding permits the kernel to forward packets from one network interface to another",
			Severity:    SeverityHigh,
			Framework:   FrameworkCIS,
			Category:    "network",
			Status:      StatusWarning,
			Evidence:    "IP forwarding is enabled but should be disabled",
			Remediation: &Remediation{
				Description: "Disable IP forwarding",
				Steps: []string{
					"Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf",
					"Run: sysctl -p",
				},
				Priority:     5,
				Difficulty:   "easy",
				TimeEstimate: 5,
				Automated:    true,
			},
		},
	}
}

// getPCIDSSRules 获取 PCI-DSS 规则
func (cct *ComplianceCheckTool) getPCIDSSRules() []*ComplianceRule {
	return []*ComplianceRule{
		{
			ID:          "pci_2_1",
			Title:       "Always change vendor-supplied defaults",
			Description: "Attackers use vendor defaults to compromise systems",
			Severity:    SeverityHigh,
			Framework:   FrameworkPCIDSS,
			Category:    "authentication",
			Status:      StatusPassed,
			Evidence:    "All default credentials have been changed",
		},
	}
}

// getSOC2Rules 获取 SOC2 规则
func (cct *ComplianceCheckTool) getSOC2Rules() []*ComplianceRule {
	return []*ComplianceRule{
		{
			ID:          "soc2_cc1",
			Title:       "Logical and physical access controls",
			Description: "Ensure proper access controls are in place",
			Severity:    SeverityHigh,
			Framework:   FrameworkSOC2,
			Category:    "access_control",
			Status:      StatusPassed,
			Evidence:    "Access controls are properly configured",
		},
	}
}

// getHIPAARules 获取 HIPAA 规则
func (cct *ComplianceCheckTool) getHIPAARules() []*ComplianceRule {
	return []*ComplianceRule{
		{
			ID:          "hipaa_164_308",
			Title:       "Administrative Safeguards",
			Description: "Implement administrative safeguards for ePHI",
			Severity:    SeverityHigh,
			Framework:   FrameworkHIPAA,
			Category:    "data_protection",
			Status:      StatusFailed,
			Evidence:    "Some administrative safeguards are missing",
		},
	}
}

// getISO27001Rules 获取 ISO27001 规则
func (cct *ComplianceCheckTool) getISO27001Rules() []*ComplianceRule {
	return []*ComplianceRule{
		{
			ID:          "iso27001_5_1",
			Title:       "Information security policy",
			Description: "Maintain documented information security policies",
			Severity:    SeverityHigh,
			Framework:   FrameworkISO27001,
			Category:    "governance",
			Status:      StatusWarning,
			Evidence:    "Policy file not yet verified",
		},
		{
			ID:          "iso27001_8_15",
			Title:       "Logging and monitoring",
			Description: "Ensure security events are logged and retained",
			Severity:    SeverityHigh,
			Framework:   FrameworkISO27001,
			Category:    "logging",
			Status:      StatusWarning,
			Evidence:    "Audit logs not yet verified",
		},
		{
			ID:          "iso27001_8_3",
			Title:       "Access restriction",
			Description: "Restrict access to sensitive system files and controls",
			Severity:    SeverityMedium,
			Framework:   FrameworkISO27001,
			Category:    "access_control",
			Status:      StatusWarning,
			Evidence:    "Access control not yet verified",
		},
	}
}

// getDockerBenchRules 获取 Docker Bench 规则
func (cct *ComplianceCheckTool) getDockerBenchRules() []*ComplianceRule {
	return []*ComplianceRule{
		{
			ID:          "docker_bench_1_1",
			Title:       "Docker daemon configuration is hardened",
			Description: "Validate daemon hardening options such as user namespace remapping",
			Severity:    SeverityHigh,
			Framework:   FrameworkDockerBench,
			Category:    "daemon",
			Status:      StatusWarning,
			Evidence:    "Daemon configuration not yet verified",
		},
		{
			ID:          "docker_bench_1_2",
			Title:       "Docker socket permissions are restricted",
			Description: "Ensure the Docker socket is not world-writable",
			Severity:    SeverityHigh,
			Framework:   FrameworkDockerBench,
			Category:    "filesystem",
			Status:      StatusWarning,
			Evidence:    "Socket permissions not yet verified",
		},
		{
			ID:          "docker_bench_1_3",
			Title:       "IP forwarding is disabled",
			Description: "Verify kernel forwarding is disabled for the Docker host",
			Severity:    SeverityMedium,
			Framework:   FrameworkDockerBench,
			Category:    "network",
			Status:      StatusWarning,
			Evidence:    "IP forwarding not yet verified",
		},
	}
}

// filterRulesByID 按 ID 过滤规则
func (cct *ComplianceCheckTool) filterRulesByID(rules []*ComplianceRule, ruleIDs []string) []*ComplianceRule {
	idMap := make(map[string]bool)
	for _, id := range ruleIDs {
		idMap[id] = true
	}

	filtered := make([]*ComplianceRule, 0)
	for _, rule := range rules {
		if idMap[rule.ID] {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

// checkRule 检查单个规则
func (cct *ComplianceCheckTool) checkRule(rule *ComplianceRule, full bool) {
	rule.LastChecked = time.Now()
	cct.evaluateRule(rule)
	if rule.Status == StatusFailed && full {
		rule.Evidence = "Detailed check: " + rule.Evidence
	}
}

func (cct *ComplianceCheckTool) evaluateRule(rule *ComplianceRule) {
	switch rule.ID {
	case "cis_1_1":
		cct.evalCISFilesystem(rule)
	case "cis_2_1":
		cct.evalCISXWindow(rule)
	case "cis_3_1":
		cct.evalCISIPForward(rule)
	case "pci_2_1":
		cct.evalPCIDefaults(rule)
	case "soc2_cc1":
		cct.evalSOC2AccessControl(rule)
	case "hipaa_164_308":
		cct.evalHIPAASafeguards(rule)
	case "iso27001_5_1":
		cct.evalISO27001Policy(rule)
	case "iso27001_8_15":
		cct.evalISO27001Logging(rule)
	case "iso27001_8_3":
		cct.evalISO27001AccessControl(rule)
	case "docker_bench_1_1":
		cct.evalDockerBenchDaemonConfig(rule)
	case "docker_bench_1_2":
		cct.evalDockerBenchSocketPermissions(rule)
	case "docker_bench_1_3":
		cct.evalDockerBenchIPForward(rule)
	}
}

func (cct *ComplianceCheckTool) evalCISFilesystem(rule *ComplianceRule) {
	info, err := os.Stat("/etc/fstab")
	if err != nil {
		rule.Status = StatusWarning
		rule.Evidence = fmt.Sprintf("cannot verify /etc/fstab: %v", err)
		return
	}
	mode := info.Mode().Perm()
	if mode&0o002 != 0 {
		rule.Status = StatusFailed
		rule.Evidence = fmt.Sprintf("/etc/fstab is world-writable (%#o)", mode)
		return
	}
	rule.Status = StatusPassed
	rule.Evidence = fmt.Sprintf("/etc/fstab permissions are restricted (%#o)", mode)
}

func (cct *ComplianceCheckTool) evalCISXWindow(rule *ComplianceRule) {
	xPaths := []string{
		"/usr/bin/Xorg",
		"/usr/bin/startx",
		"/usr/X11/bin/Xorg",
	}
	for _, p := range xPaths {
		if _, err := os.Stat(p); err == nil {
			rule.Status = StatusWarning
			rule.Evidence = fmt.Sprintf("X Window component detected: %s", p)
			return
		}
	}
	rule.Status = StatusPassed
	rule.Evidence = "X Window System binaries not detected"
}

func (cct *ComplianceCheckTool) evalCISIPForward(rule *ComplianceRule) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		rule.Status = StatusWarning
		rule.Evidence = fmt.Sprintf("cannot read ip_forward: %v", err)
		return
	}
	val := strings.TrimSpace(string(data))
	if val == "0" {
		rule.Status = StatusPassed
		rule.Evidence = "IP forwarding is disabled"
		return
	}
	rule.Status = StatusWarning
	rule.Evidence = fmt.Sprintf("IP forwarding is enabled (value=%s)", val)
}

func (cct *ComplianceCheckTool) evalPCIDefaults(rule *ComplianceRule) {
	// Lightweight production-safe check: detect explicit default credential envs.
	defaultHints := []string{
		"DEFAULT_PASSWORD",
		"DEFAULT_PASS",
		"MYSQL_ROOT_PASSWORD",
	}
	for _, key := range defaultHints {
		v := strings.TrimSpace(os.Getenv(key))
		if v == "" {
			continue
		}
		low := strings.ToLower(v)
		if low == "admin" || low == "password" || low == "root" || low == "123456" {
			rule.Status = StatusFailed
			rule.Evidence = fmt.Sprintf("default credential pattern detected in %s", key)
			return
		}
	}
	rule.Status = StatusPassed
	rule.Evidence = "No obvious vendor default credentials detected"
}

func (cct *ComplianceCheckTool) evalSOC2AccessControl(rule *ComplianceRule) {
	type target struct {
		path    string
		maxPerm os.FileMode
	}
	targets := []target{
		{path: "/etc/passwd", maxPerm: 0o644},
		{path: "/etc/shadow", maxPerm: 0o640},
	}
	for _, t := range targets {
		info, err := os.Stat(t.path)
		if err != nil {
			rule.Status = StatusWarning
			rule.Evidence = fmt.Sprintf("cannot verify %s: %v", t.path, err)
			return
		}
		perm := info.Mode().Perm()
		if perm > t.maxPerm {
			rule.Status = StatusFailed
			rule.Evidence = fmt.Sprintf("%s permissions too open (%#o > %#o)", t.path, perm, t.maxPerm)
			return
		}
	}
	rule.Status = StatusPassed
	rule.Evidence = "Critical account files have restricted permissions"
}

func (cct *ComplianceCheckTool) evalHIPAASafeguards(rule *ComplianceRule) {
	auditCandidates := []string{
		"/var/log/audit/audit.log",
		"/var/log/auth.log",
		"/var/log/secure",
	}
	for _, p := range auditCandidates {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.Size() == 0 {
			continue
		}
		rule.Status = StatusPassed
		rule.Evidence = fmt.Sprintf("audit trace available: %s (%s)", p, strconv.FormatInt(info.Size(), 10))
		return
	}
	rule.Status = StatusWarning
	rule.Evidence = "audit trail files not found or empty"
}

func (cct *ComplianceCheckTool) evalISO27001Policy(rule *ComplianceRule) {
	for _, path := range iso27001PolicyPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() || info.Size() == 0 {
			continue
		}
		rule.Status = StatusPassed
		rule.Evidence = fmt.Sprintf("security policy present: %s (%s)", path, strconv.FormatInt(info.Size(), 10))
		return
	}
	rule.Status = StatusWarning
	rule.Evidence = "security policy file not found or empty"
}

func (cct *ComplianceCheckTool) evalISO27001Logging(rule *ComplianceRule) {
	for _, path := range iso27001AuditLogPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() || info.Size() == 0 {
			continue
		}
		rule.Status = StatusPassed
		rule.Evidence = fmt.Sprintf("audit log available: %s (%s)", path, strconv.FormatInt(info.Size(), 10))
		return
	}
	rule.Status = StatusWarning
	rule.Evidence = "audit logs not found or empty"
}

func (cct *ComplianceCheckTool) evalISO27001AccessControl(rule *ComplianceRule) {
	info, err := os.Stat(iso27001AccessControlPath)
	if err != nil {
		rule.Status = StatusWarning
		rule.Evidence = fmt.Sprintf("cannot verify %s: %v", iso27001AccessControlPath, err)
		return
	}

	mode := info.Mode().Perm()
	// Accept common secure modes such as 0o600 and 0o640.
	if mode > 0o640 {
		rule.Status = StatusFailed
		rule.Evidence = fmt.Sprintf("%s permissions are too open (%#o)", iso27001AccessControlPath, mode)
		return
	}

	rule.Status = StatusPassed
	rule.Evidence = fmt.Sprintf("%s permissions are restricted (%#o)", iso27001AccessControlPath, mode)
}

func (cct *ComplianceCheckTool) evalDockerBenchDaemonConfig(rule *ComplianceRule) {
	data, err := os.ReadFile(dockerBenchDaemonConfigPath)
	if err != nil {
		rule.Status = StatusWarning
		rule.Evidence = fmt.Sprintf("cannot read %s: %v", dockerBenchDaemonConfigPath, err)
		return
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		rule.Status = StatusWarning
		rule.Evidence = fmt.Sprintf("invalid Docker daemon config %s: %v", dockerBenchDaemonConfigPath, err)
		return
	}

	if value, ok := config["userns-remap"].(string); ok && strings.TrimSpace(value) != "" {
		rule.Status = StatusPassed
		rule.Evidence = fmt.Sprintf("user namespace remapping enabled in %s", filepath.Base(dockerBenchDaemonConfigPath))
		return
	}
	if value, ok := config["rootless"].(bool); ok && value {
		rule.Status = StatusPassed
		rule.Evidence = fmt.Sprintf("rootless mode enabled in %s", filepath.Base(dockerBenchDaemonConfigPath))
		return
	}
	if value, ok := config["live-restore"].(bool); ok && value {
		rule.Status = StatusWarning
		rule.Evidence = fmt.Sprintf("live-restore enabled but userns-remap is not configured in %s", filepath.Base(dockerBenchDaemonConfigPath))
		return
	}

	rule.Status = StatusFailed
	rule.Evidence = fmt.Sprintf("daemon config %s does not enable core hardening controls", dockerBenchDaemonConfigPath)
}

func (cct *ComplianceCheckTool) evalDockerBenchSocketPermissions(rule *ComplianceRule) {
	info, err := os.Stat(dockerBenchSocketPath)
	if err != nil {
		rule.Status = StatusWarning
		rule.Evidence = fmt.Sprintf("cannot verify %s: %v", dockerBenchSocketPath, err)
		return
	}

	mode := info.Mode().Perm()
	if mode&0o022 != 0 {
		rule.Status = StatusFailed
		rule.Evidence = fmt.Sprintf("docker socket permissions are too open (%#o)", mode)
		return
	}

	rule.Status = StatusPassed
	rule.Evidence = fmt.Sprintf("docker socket permissions are restricted (%#o)", mode)
}

func (cct *ComplianceCheckTool) evalDockerBenchIPForward(rule *ComplianceRule) {
	data, err := os.ReadFile(dockerBenchIPForwardPath)
	if err != nil {
		rule.Status = StatusWarning
		rule.Evidence = fmt.Sprintf("cannot read %s: %v", dockerBenchIPForwardPath, err)
		return
	}

	val := strings.TrimSpace(string(data))
	if val == "0" {
		rule.Status = StatusPassed
		rule.Evidence = "IP forwarding is disabled"
		return
	}

	rule.Status = StatusWarning
	rule.Evidence = fmt.Sprintf("IP forwarding is enabled (value=%s)", val)
}

// calculateScore 计算合规分数
func (cct *ComplianceCheckTool) calculateScore(result *ComplianceCheckResult) float64 {
	if result.TotalRules == 0 {
		return 100
	}

	// 分数计算：通过规则 * 100 / 总规则
	// 警告规则算 50% 的分数
	score := float64((result.PassedRules*100)+(result.WarningRules*50)) / float64(result.TotalRules)
	return score
}

// determineStatus 确定总体状态
func (cct *ComplianceCheckTool) determineStatus(result *ComplianceCheckResult) ComplianceStatus {
	if result.FailedRules == 0 {
		return StatusPassed
	}
	if result.Score >= 80 {
		return StatusWarning
	}
	return StatusFailed
}

// generateSummary 生成摘要
func (cct *ComplianceCheckTool) generateSummary(result *ComplianceCheckResult) *ComplianceSummary {
	summary := &ComplianceSummary{}

	for _, rule := range result.Rules {
		if rule.Status == StatusFailed {
			switch rule.Severity {
			case SeverityHigh:
				summary.HighPriority++
			case SeverityMedium:
				summary.MediumPriority++
			case SeverityLow:
				summary.LowPriority++
			}
		}
	}

	return summary
}

// generateRecommendations 生成建议
func (cct *ComplianceCheckTool) generateRecommendations(result *ComplianceCheckResult) []*Recommendation {
	recommendations := make([]*Recommendation, 0)

	// 为失败的规则生成建议
	for i, rule := range result.Rules {
		if rule.Status == StatusFailed && rule.Severity == SeverityHigh && i < 3 {
			recommendations = append(recommendations, &Recommendation{
				Title:       "Fix: " + rule.Title,
				Priority:    5,
				ImpactScore: 0.9,
				Effort:      "medium",
			})
		}
	}

	return recommendations
}
