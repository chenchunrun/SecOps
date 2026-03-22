package secops

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// MaxFileSize is the maximum file size to scan (1 MB).
const MaxFileSize = 1 << 20

// Directories excluded from scanning.
var skipDirs = map[string]bool{
	".git":           true,
	"node_modules":   true,
	"vendor":         true,
	".svn":           true,
	"__pycache__":    true,
	".pytest_cache":  true,
	"_site":          true,
	".tox":           true,
	"dist":           true,
	"build":          true,
	".venv":          true,
	"venv":           true,
	".idea":          true,
	".vscode":        true,
	".dart_tool":     true,
	".flutter_tools": true,
}

// skipSuffixes contains file extensions that are almost certainly binary
// and should not be scanned for secrets.
var skipSuffixes = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".ico": true, ".svg": true, ".webp": true, ".bmp": true,
	".pdf": true, ".zip": true, ".tar": true, ".gz": true,
	".tgz": true, ".bz2": true, ".xz": true, ".rar": true,
	".7z": true, ".exe": true, ".dll": true, ".so": true,
	".dylib": true, ".a": true, ".o": true, ".obj": true,
	".class": true, ".jar": true, ".war": true, ".ear": true,
	".pyc": true, ".pyo": true, ".pyd": true,
	".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".ppt": true, ".pptx": true,
	".ttf": true, ".otf": true, ".woff": true, ".woff2": true,
	".eot": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
	".wmv": true, ".flv": true, ".mkv": true,
	".iso": true, ".img": true,
	".lock": true, ".sum": true,
}

// SecretAuditParams for scanning for leaked credentials
type SecretAuditParams struct {
	TargetPath string `json:"target_path"` // directory or repo to scan
	ScanType   string `json:"scan_type"`   // "pattern", "entropy", "ai"
	Severity   string `json:"severity"`    // filter: CRITICAL, HIGH, MEDIUM
}

// SecretFinding 密钥发现
type SecretFinding struct {
	File        string
	Line        int
	Type        string // "api_key", "password", "private_key", "token"
	Redacted    string // e.g. "ghp_****"
	Severity    string
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

	if strings.TrimSpace(p.TargetPath) == "" {
		return fmt.Errorf("target_path is required")
	}

	p.ScanType = strings.ToLower(strings.TrimSpace(p.ScanType))
	validScanTypes := map[string]bool{
		"pattern": true,
		"entropy": true,
		"ai":      true,
	}
	if p.ScanType != "" && !validScanTypes[p.ScanType] {
		return fmt.Errorf("unsupported scan_type: %s", p.ScanType)
	}

	p.Severity = strings.ToUpper(strings.TrimSpace(p.Severity))
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
		Pattern:     regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`),
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
		Pattern:     regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+[A-Za-z0-9_\-\.=+/]{20,}|(?:bearer_token|auth_token|access_token)\s*[=:]\s*['"]?[A-Za-z0-9_\-\.=+/]{20,})`),
		Description: "Authentication token",
	},
	{
		Type:        "database_password",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`(?i)((db_pass|mysql_pass|postgres_pass|pg_pass|redis_pass|db_password|database_password)\s*[=:]\s*['"]?[^\s'"]{6,}|(mysql|postgres(?:ql)?|mongodb|redis)://[^\s'"]+)`),
		Description: "Database password or DSN",
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
		Pattern:     regexp.MustCompile(`(?i)sk_(live|test)_[0-9a-zA-Z]{24,}`),
		Description: "Stripe secret key",
	},
	{
		Type:        "url_password",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`(?i)[?&](password|pass|pwd)=[^&\s'"]+`),
		Description: "Password embedded in URL",
	},
	{
		Type:        "gcp_credential",
		Severity:    "CRITICAL",
		Pattern:     regexp.MustCompile(`(?i)(gcp_[A-Za-z0-9_\-]{20,}|GOOGLE_[A-Z0-9_]{8,}|\"type\"\s*:\s*\"service_account\")`),
		Description: "GCP credential material",
	},
	{
		Type:        "jwt_token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`(?i)eyJ[a-zA-Z0-9_\-]+=*\.[a-zA-Z0-9_\-]+=*\.[a-zA-Z0-9_\-]+=*`),
		Description: "JWT token",
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
	case "stripe_key":
		if len(original) >= 12 {
			return original[:8] + "****" + original[len(original)-4:]
		}
	case "url_password":
		if idx := strings.Index(original, "="); idx >= 0 {
			return original[:idx+1] + "********"
		}
		return "********"
	default:
		if len(original) >= 8 {
			return original[:4] + "****" + original[len(original)-4:]
		}
	}
	return "****"
}

// performAudit walks params.TargetPath and scans every text file for secrets.
func (sat *SecretAuditTool) performAudit(params *SecretAuditParams) *SecretAuditResult {
	result := &SecretAuditResult{
		Findings: make([]SecretFinding, 0),
	}

	severityRank := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
	}
	minRank := severityRank[params.Severity]

	absPath := params.TargetPath
	info, err := os.Stat(absPath)
	if err != nil {
		result.Findings = append(result.Findings, SecretFinding{
			File:        absPath,
			Line:        0,
			Type:        "scan_error",
			Redacted:    "",
			Severity:    "HIGH",
			Description: "Failed to access path: " + err.Error(),
		})
		result.TotalScanned = 0
		return result
	}

	if info.IsDir() {
		filepath.Walk(absPath, sat.makeWalker(absPath, result, severityRank, minRank))
	} else {
		sat.scanFile(absPath, absPath, result, severityRank, minRank)
	}

	// Count high-severity findings.
	for _, f := range result.Findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			result.HighSeverity++
		}
	}

	return result
}

// makeWalker returns a filepath.WalkFunc that skips ignored directories and
// scans each regular text file for secrets.
func (sat *SecretAuditTool) makeWalker(
	root string,
	result *SecretAuditResult,
	severityRank map[string]int,
	minRank int,
) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			_, name := filepath.Split(path)
			if skipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		return sat.scanFile(root, path, result, severityRank, minRank)
	}
}

// scanFile reads a single file and records any secret findings.
func (sat *SecretAuditTool) scanFile(
	root, path string,
	result *SecretAuditResult,
	severityRank map[string]int,
	minRank int,
) error {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	if info.Size() > MaxFileSize {
		return nil
	}
	ext := strings.ToLower(filepath.Ext(path))
	if skipSuffixes[ext] {
		return nil
	}

	// Binary check: look for null bytes in first 512 bytes.
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	header := make([]byte, 512)
	n, _ := f.Read(header)
	f.Close()
	if n > 0 && containsNonText(header[:n]) {
		return nil
	}

	// Line-by-line scan.
	f2, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f2.Close()

	scanner := bufio.NewScanner(f2)
	const maxLineSize = 512 * 1024
	scanner.Buffer(make([]byte, maxLineSize), maxLineSize)

	relPath := path
	if root != "" {
		relPath, _ = filepath.Rel(root, path)
	}

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		lowerLine := strings.ToLower(string(line))
		for _, pat := range secretPatterns {
			idx := pat.Pattern.FindIndex(line)
			if idx == nil {
				continue
			}
			// Avoid duplicate findings for database-specific password keys
			// that are also matched by the generic password pattern.
			if pat.Type == "password" && isDatabasePasswordLine(lowerLine) {
				continue
			}
			match := string(line[idx[0]:idx[1]])
			finding := SecretFinding{
				File:        relPath,
				Line:        lineNum,
				Type:        pat.Type,
				Redacted:    redacted(match, pat.Type),
				Severity:    pat.Severity,
				Description: pat.Description,
			}
			if severityRank[finding.Severity] >= minRank {
				result.Findings = append(result.Findings, finding)
			}
		}
	}

	result.TotalScanned++
	return nil
}

func isDatabasePasswordLine(line string) bool {
	dbKeys := []string{
		"db_pass",
		"db_password",
		"database_password",
		"mysql_pass",
		"postgres_pass",
		"pg_pass",
		"redis_pass",
	}
	for _, key := range dbKeys {
		if strings.Contains(line, key) {
			return true
		}
	}
	return strings.Contains(line, "mysql://") ||
		strings.Contains(line, "postgres://") ||
		strings.Contains(line, "postgresql://") ||
		strings.Contains(line, "mongodb://") ||
		strings.Contains(line, "redis://")
}

// containsNonText reports whether b contains a null byte or has a high density
// of non-printable, non-ASCII bytes, indicating binary content.
func containsNonText(b []byte) bool {
	nonPrintable := 0
	for _, c := range b {
		if c == 0 {
			return true
		}
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			nonPrintable++
		}
	}
	// Flag as binary if >30% of sample bytes are non-printable control chars.
	return len(b) > 0 && (nonPrintable*10)/len(b) > 3
}
