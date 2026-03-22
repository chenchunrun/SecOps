package secops

import (
	"fmt"
	"regexp"
)

// SecretAuditParams for scanning for leaked credentials
type SecretAuditParams struct {
	TargetPath string `json:"target_path"` // directory or repo to scan
	ScanType   string `json:"scan_type"`  // "pattern", "entropy", "ai"
	Severity   string `json:"severity"`   // filter: CRITICAL, HIGH, MEDIUM
}

// SecretFinding 密钥发现
type SecretFinding struct {
	File        string
	Line        int
	Type        string  // "api_key", "password", "private_key", "token"
	Redacted    string  // e.g. "ghp_****"
	Severity   string
	Description string
}

// SecretAuditResult 密钥审计结果
type SecretAuditResult struct {
	TotalScanned int
	Findings     []SecretFinding
	HighSeverity int
}

// SecretAuditTool 密钥审计工具
type SecretAuditTool struct {
	registry *SecOpsToolRegistry
}

// NewSecretAuditTool 创建密钥审计工具
func NewSecretAuditTool(registry *SecOpsToolRegistry) *SecretAuditTool {
	return &SecretAuditTool{registry: registry}
}

// Type 实现 Tool.Type
func (sat *SecretAuditTool) Type() ToolType {
	return ToolTypeSecretAudit
}

// Name 实现 Tool.Name
func (sat *SecretAuditTool) Name() string {
	return "Secret Audit"
}

// Description 实现 Tool.Description
func (sat *SecretAuditTool) Description() string {
	return "Scan for leaked credentials, API keys, passwords, and private keys using regex patterns"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (sat *SecretAuditTool) RequiredCapabilities() []string {
	return []string{"security:scan", "filesystem:read"}
}

// ValidateParams 实现 Tool.ValidateParams
func (sat *SecretAuditTool) ValidateParams(params interface{}) error {
	p, ok := params.(*SecretAuditParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.TargetPath == "" {
		return fmt.Errorf("target_path is required")
	}

	validScanTypes := map[string]bool{
		"pattern": true,
		"entropy": true,
		"ai":     true,
	}
	if p.ScanType != "" && !validScanTypes[p.ScanType] {
		return fmt.Errorf("unsupported scan_type: %s", p.ScanType)
	}

	validSeverities := map[string]bool{
		"CRITICAL": true,
		"HIGH":     true,
		"MEDIUM":   true,
		"LOW":      true,
	}
	if p.Severity != "" && !validSeverities[p.Severity] {
		return fmt.Errorf("unsupported severity: %s", p.Severity)
	}

	return nil
}

// Execute 实现 Tool.Execute
func (sat *SecretAuditTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*SecretAuditParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := sat.ValidateParams(p); err != nil {
		return nil, err
	}

	return sat.performAudit(p), nil
}

// secretPatterns 定义密钥检测正则表达式
var secretPatterns = []struct {
	Type        string
	Severity    string
	Pattern     *regexp.Regexp
	Description string
}{
	{
		Type:        "github_token",
		Severity:    "CRITICAL",
		Pattern:     regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}`),
		Description: "GitHub Personal Access Token",
	},
	{
		Type:        "aws_access_key",
		Severity:    "CRITICAL",
		Pattern:     regexp.MustCompile(`(?i)(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}`),
		Description: "AWS Access Key ID",
	},
	{
		Type:        "aws_secret_key",
		Severity:    "CRITICAL",
		Pattern:     regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`),
		Description: "AWS Secret Access Key",
	},
	{
		Type:        "password",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['"]?[^\s'"]{8,}`),
		Description: "Hardcoded password",
	},
	{
		Type:        "private_key",
		Severity:    "CRITICAL",
		Pattern:     regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Description: "Private key in file",
	},
	{
		Type:        "api_key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}`),
		Description: "Generic API key",
	},
	{
		Type:        "token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`(?i)(bearer_token|auth_token|access_token)\s*[=:]\s*['"]?[A-Za-z0-9_\-\.]{20,}`),
		Description: "Authentication token",
	},
	{
		Type:        "database_password",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`(?i)(db_pass|mysql_pass|postgres_pass|pg_pass|redis_pass)\s*[=:]\s*['"]?[^\s'"]{6,}`),
		Description: "Database password",
	},
	{
		Type:        "slack_token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
		Description: "Slack API token",
	},
	{
		Type:        "stripe_key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`(?i)sk_live_[0-9a-zA-Z]{24,}`),
		Description: "Stripe secret key",
	},
}

// redacted 将密钥脱敏显示
func redacted(original string, secretType string) string {
	switch secretType {
	case "github_token":
		if len(original) >= 8 {
			return original[:4] + "****" + original[len(original)-4:]
		}
	case "aws_access_key":
		if len(original) >= 8 {
			return original[:4] + "************" + original[len(original)-4:]
		}
	case "password", "database_password":
		return "********"
	case "private_key":
		return "-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----"
	default:
		if len(original) >= 8 {
			return original[:4] + "****" + original[len(original)-4:]
		}
	}
	return "****"
}

// performAudit 执行密钥扫描
func (sat *SecretAuditTool) performAudit(params *SecretAuditParams) *SecretAuditResult {
	result := &SecretAuditResult{
		Findings: make([]SecretFinding, 0),
	}

	// 模拟扫描结果（真实实现会扫描文件系统）
	mockFindings := []SecretFinding{
		{
			File:        "config/prod.env",
			Line:        15,
			Type:        "aws_access_key",
			Redacted:    "AKIA************ABCD",
			Severity:    "CRITICAL",
			Description: "AWS Access Key ID exposed in configuration file",
		},
		{
			File:        "scripts/deploy.sh",
			Line:        42,
			Type:        "password",
			Redacted:    "********",
			Severity:    "HIGH",
			Description: "Hardcoded password in deployment script",
		},
		{
			File:        ".env.local",
			Line:        3,
			Type:        "github_token",
			Redacted:    "ghp_****************************abcd",
			Severity:    "CRITICAL",
			Description: "GitHub Personal Access Token in environment file",
		},
		{
			File:        "keys/ssh.pem",
			Line:        1,
			Type:        "private_key",
			Redacted:    "-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----",
			Severity:    "CRITICAL",
			Description: "Private key committed to repository",
		},
		{
			File:        "config/database.yml",
			Line:        8,
			Type:        "database_password",
			Redacted:    "********",
			Severity:    "HIGH",
			Description: "Database password in YAML configuration",
		},
	}

	// 按严重级别过滤
	severityRank := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
	}

	minRank := 0
	if params.Severity != "" {
		minRank = severityRank[params.Severity]
	}

	for _, f := range mockFindings {
		findingsRank := severityRank[f.Severity]
		if findingsRank >= minRank {
			result.Findings = append(result.Findings, f)
		}
	}

	result.TotalScanned = 127
	for _, f := range result.Findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			result.HighSeverity++
		}
	}

	return result
}
