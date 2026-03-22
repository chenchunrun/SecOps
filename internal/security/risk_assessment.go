package security

import (
	"regexp"
	"strings"
)

// RiskFactor 风险因子
type RiskFactor struct {
	Name     string // 因子名称
	Weight   int    // 权重 (0-100)
	Evidence string // 证据描述
}

// RiskAssessment 风险评估结果
type RiskAssessment struct {
	Score   int           // 总风险分数 (0-100)
	Level   RiskLevel     // 风险级别
	Factors []RiskFactor  // 风险因子列表
	Action  RiskAction    // 建议的决策
	Details string        // 详细说明
}

// RiskLevel 风险级别
type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "CRITICAL"
	RiskLevelHigh     RiskLevel = "HIGH"
	RiskLevelMedium   RiskLevel = "MEDIUM"
	RiskLevelLow      RiskLevel = "LOW"
)

// RiskAction 风险决策
type RiskAction string

const (
	RiskActionBlock         RiskAction = "block"
	RiskActionAdminReview   RiskAction = "admin_review"
	RiskActionUserConfirm   RiskAction = "user_confirm"
	RiskActionAutoApprove   RiskAction = "auto_approve"
)

// RiskAssessor 风险评估器
type RiskAssessor struct {
	config            *RiskAssessorConfig
	credentialRegexes []*regexp.Regexp
	modifyRegexes     []*regexp.Regexp
	networkRegexes    []*regexp.Regexp
}

// RiskAssessorConfig 风险评估器配置
type RiskAssessorConfig struct {
	// 禁用命令列表
	BannedCommands []string
	// 敏感路径列表
	SensitivePaths []string
	// 凭证检测模式
	CredentialPatterns []string
	// 风险分数阈值
	BlockThreshold       int // >= 此分数时拒绝
	AdminReviewThreshold int // >= 此分数时需要管理员审查
	UserConfirmThreshold int // >= 此分数时需要用户确认
}

// DefaultBannedCommands returns the full list of banned shell commands,
// merging entries from both the risk assessor and the bash tool.
func DefaultBannedCommands() []string {
	return []string{
		// From risk_assessment.go (not in bash.go)
		"dd",
		"halt",
		"reboot",
		"shutdown",

		// Network/Download tools
		"alias",
		"aria2c",
		"axel",
		"chrome",
		"curl",
		"curlie",
		"firefox",
		"http-prompt",
		"httpie",
		"links",
		"lynx",
		"nc",
		"safari",
		"scp",
		"ssh",
		"telnet",
		"w3m",
		"wget",
		"xh",

		// System administration
		"doas",
		"su",
		"sudo",

		// Package managers
		"apk",
		"apt",
		"apt-cache",
		"apt-get",
		"dnf",
		"dpkg",
		"emerge",
		"home-manager",
		"makepkg",
		"opkg",
		"pacman",
		"paru",
		"pkg",
		"pkg_add",
		"pkg_delete",
		"portage",
		"rpm",
		"yay",
		"yum",
		"zypper",

		// System modification
		"at",
		"batch",
		"chkconfig",
		"crontab",
		"fdisk",
		"mkfs",
		"mount",
		"parted",
		"service",
		"systemctl",
		"umount",

		// Network configuration
		"firewall-cmd",
		"ifconfig",
		"ip",
		"iptables",
		"netstat",
		"pfctl",
		"route",
		"ufw",

		// File removal (kept from risk_assessment.go)
		"rm",
	}
}

// DefaultRiskAssessorConfig 默认风险评估配置
func DefaultRiskAssessorConfig() *RiskAssessorConfig {
	return &RiskAssessorConfig{
		BannedCommands: DefaultBannedCommands(),
		SensitivePaths: []string{
			"/etc/shadow",
			"/etc/passwd",
			"/root/.ssh",
			"/etc/sudoers",
			"/.aws/credentials",
			"/.kube/config",
			"/etc/ssl/private",
			"/var/lib/docker",
			"/.gcp/credentials",
			"/.azure/credentials",
			"/etc/kubernetes",
			"/var/www",
		},
		CredentialPatterns: []string{
			`(?i)password\s*=`,
			`(?i)passwd\s*=`,
			`(?i)pwd\s*=`,
			`(?i)api[_-]?key\s*=`,
			`(?i)secret[_-]?key?\s*=`,
			`(?i)access[_-]?token\s*=`,
			`(?i)token\s*=`,
			`(?i)auth[_-]?token\s*=`,
			`(?i)bearer\s+\S+`,
			`--password`,
			`-p\s*\w+`,
			`(?i)private[_-]?key\s*=`,
			`(?i)db[_-]?password\s*=`,
			`(?i)connection[_-]?string\s*=`,
		},
		BlockThreshold:       80,
		AdminReviewThreshold: 60,
		UserConfirmThreshold: 40,
	}
}

// NewRiskAssessor 创建风险评估器
func NewRiskAssessor() *RiskAssessor {
	return newRiskAssessor(DefaultRiskAssessorConfig())
}

// NewRiskAssessorWithConfig 使用自定义配置创建风险评估器
func NewRiskAssessorWithConfig(config *RiskAssessorConfig) *RiskAssessor {
	return newRiskAssessor(config)
}

// newRiskAssessor 内部构造函数，预编译正则表达式
func newRiskAssessor(config *RiskAssessorConfig) *RiskAssessor {
	ra := &RiskAssessor{
		config: config,
	}

	// 预编译凭证检测正则
	for _, pattern := range config.CredentialPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			ra.credentialRegexes = append(ra.credentialRegexes, re)
		}
	}

	// 预编译系统修改检测正则
	modifyPatterns := []string{
		`^(sed|awk|ed)\s+`,
		`^(chown|chmod|chgrp)\s+`,
		`^(usermod|useradd|userdel)\s+`,
		`^(systemctl|service)\s+(start|stop|restart|reload)`,
		`^(apt|yum|pacman)\s+(install|remove|upgrade)`,
		`^(systemctl|systemd)\s+`,
	}
	for _, pattern := range modifyPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			ra.modifyRegexes = append(ra.modifyRegexes, re)
		}
	}

	// 预编译网络访问检测正则
	networkPatterns := []string{
		`^(curl|wget|nc|netcat|socat|telnet)\s+`,
		`^(ss|netstat|lsof)\s+`,
		`^(iptables|firewall-cmd)\s+`,
		`^(ping|traceroute|mtr|nslookup|dig)\s+`,
	}
	for _, pattern := range networkPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			ra.networkRegexes = append(ra.networkRegexes, re)
		}
	}

	return ra
}

// AssessCommand 评估命令的风险
func (ra *RiskAssessor) AssessCommand(command string) *RiskAssessment {
	assessment := &RiskAssessment{
		Score:   0,
		Factors: []RiskFactor{},
	}

	// 1. 检查禁用命令
	if ra.detectBannedCommand(command) {
		assessment.Factors = append(assessment.Factors, RiskFactor{
			Name:     "banned_command",
			Weight:   40,
			Evidence: "命令在禁用列表中",
		})
	}

	// 2. 检查敏感路径访问
	if ra.detectSensitivePathAccess(command) {
		assessment.Factors = append(assessment.Factors, RiskFactor{
			Name:     "sensitive_path_access",
			Weight:   25,
			Evidence: "访问系统敏感路径",
		})
	}

	// 3. 检查凭证泄露风险
	if ra.detectCredentialExposure(command) {
		assessment.Factors = append(assessment.Factors, RiskFactor{
			Name:     "credential_exposure",
			Weight:   50,
			Evidence: "检测到潜在凭证信息",
		})
	}

	// 4. 检查系统修改操作
	if ra.detectSystemModification(command) {
		assessment.Factors = append(assessment.Factors, RiskFactor{
			Name:     "system_modification",
			Weight:   30,
			Evidence: "执行系统修改操作",
		})
	}

	// 5. 检查网络访问
	if ra.detectNetworkAccess(command) {
		assessment.Factors = append(assessment.Factors, RiskFactor{
			Name:     "network_access",
			Weight:   15,
			Evidence: "尝试进行网络访问",
		})
	}

	// 计算总分
	for _, factor := range assessment.Factors {
		assessment.Score += factor.Weight
	}

	// 限制分数在 0-100
	if assessment.Score > 100 {
		assessment.Score = 100
	}

	// 分级和决策
	ra.categorizeRisk(assessment)

	return assessment
}

// AssessPermissionRequest assesses the risk of a permission request for a tool/resource combination.
func (ra *RiskAssessor) AssessPermissionRequest(toolName, resourcePath string) *RiskAssessment {
	assessment := ra.AssessCommand(toolName)

	// 添加资源特定的风险评估
	if isSystemCriticalResource(resourcePath) {
		assessment.Factors = append(assessment.Factors, RiskFactor{
			Name:     "critical_resource",
			Weight:   20,
			Evidence: "访问关键系统资源",
		})
		assessment.Score += 20
		if assessment.Score > 100 {
			assessment.Score = 100
		}
	}

	ra.categorizeRisk(assessment)
	return assessment
}

// 私有辅助方法

// detectBannedCommand 检查禁用命令
func (ra *RiskAssessor) detectBannedCommand(cmd string) bool {
	cmdLower := strings.ToLower(cmd)
	parts := strings.Fields(cmdLower)
	if len(parts) == 0 {
		return false
	}

	cmdBase := parts[0]
	// 提取基础命令名 (e.g., /bin/rm -> rm)
	if idx := strings.LastIndex(cmdBase, "/"); idx != -1 {
		cmdBase = cmdBase[idx+1:]
	}

	for _, banned := range ra.config.BannedCommands {
		if cmdBase == banned || strings.HasPrefix(cmdBase, banned) {
			return true
		}
	}
	return false
}

// detectSensitivePathAccess 检查敏感路径访问
func (ra *RiskAssessor) detectSensitivePathAccess(cmd string) bool {
	cmdLower := strings.ToLower(cmd)
	for _, path := range ra.config.SensitivePaths {
		pathLower := strings.ToLower(path)
		if strings.Contains(cmdLower, pathLower) {
			return true
		}
	}
	return false
}

// detectCredentialExposure 检查凭证泄露
func (ra *RiskAssessor) detectCredentialExposure(cmd string) bool {
	for _, re := range ra.credentialRegexes {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// detectSystemModification 检查系统修改
func (ra *RiskAssessor) detectSystemModification(cmd string) bool {
	for _, re := range ra.modifyRegexes {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// detectNetworkAccess 检查网络访问
func (ra *RiskAssessor) detectNetworkAccess(cmd string) bool {
	for _, re := range ra.networkRegexes {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// categorizeRisk 根据分数对风险进行分级
func (ra *RiskAssessor) categorizeRisk(assessment *RiskAssessment) {
	switch {
	case assessment.Score >= ra.config.BlockThreshold:
		assessment.Level = RiskLevelCritical
		assessment.Action = RiskActionBlock
		assessment.Details = "风险评分过高，操作被阻止"

	case assessment.Score >= ra.config.AdminReviewThreshold:
		assessment.Level = RiskLevelHigh
		assessment.Action = RiskActionAdminReview
		assessment.Details = "风险评分较高，需要管理员审查"

	case assessment.Score >= ra.config.UserConfirmThreshold:
		assessment.Level = RiskLevelMedium
		assessment.Action = RiskActionUserConfirm
		assessment.Details = "风险评分中等，需要用户确认"

	default:
		assessment.Level = RiskLevelLow
		assessment.Action = RiskActionAutoApprove
		assessment.Details = "风险评分较低，自动批准"
	}
}

// 辅助函数

// isSystemCriticalResource 判断是否是关键系统资源
func isSystemCriticalResource(resource string) bool {
	criticalResources := []string{
		"/etc",
		"/sys",
		"/proc",
		"/boot",
		"/root",
		"/var/lib/mysql",
		"/var/lib/postgresql",
	}

	for _, cr := range criticalResources {
		if strings.HasPrefix(resource, cr) {
			return true
		}
	}
	return false
}
