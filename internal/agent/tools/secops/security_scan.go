package secops

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ScannerType 扫描器类型
type ScannerType string

const (
	ScannerTrivy  ScannerType = "trivy"
	ScannerGrype  ScannerType = "grype"
	ScannerNuclei ScannerType = "nuclei"
	ScannerClamAV ScannerType = "clamav"
)

// VulnerabilityLevel 漏洞级别
type VulnerabilityLevel string

const (
	VulnCritical VulnerabilityLevel = "CRITICAL"
	VulnHigh     VulnerabilityLevel = "HIGH"
	VulnMedium   VulnerabilityLevel = "MEDIUM"
	VulnLow      VulnerabilityLevel = "LOW"
)

// ScanTarget 扫描目标类型
type ScanTarget string

const (
	TargetImage      ScanTarget = "image"
	TargetFilesystem ScanTarget = "filesystem"
	TargetGit        ScanTarget = "git"
	TargetURL        ScanTarget = "url"
)

// SecurityScanParams 安全扫描参数
type SecurityScanParams struct {
	Scanner    ScannerType `json:"scanner"`
	Target     ScanTarget  `json:"target"`
	TargetPath string      `json:"target_path"`
	ScanType   string      `json:"scan_type,omitempty"` // vuln, config, secret, all
	Severity   string      `json:"severity,omitempty"`  // 最小严重级别
	Full       bool        `json:"full,omitempty"`
	FixVulns   bool        `json:"fix_vulns,omitempty"`
}

// Vulnerability 漏洞信息
type Vulnerability struct {
	ID          string             `json:"id"`
	Title       string             `json:"title"`
	Description string             `json:"description"`
	Severity    VulnerabilityLevel `json:"severity"`
	Package     string             `json:"package"`
	Version     string             `json:"version"`
	CVE         string             `json:"cve"`
	CVSS        float64            `json:"cvss"`
	Reference   string             `json:"reference"`
	Fix         *Fix               `json:"fix,omitempty"`
	FoundAt     time.Time          `json:"found_at"`
}

// Fix 修复信息
type Fix struct {
	Available bool   `json:"available"`
	Version   string `json:"version"`
	URL       string `json:"url"`
}

// ScanResult 扫描结果
type ScanResult struct {
	Scanner              ScannerType      `json:"scanner"`
	Target               string           `json:"target"`
	ScanTime             time.Time        `json:"scan_time"`
	TotalVulnerabilities int              `json:"total_vulnerabilities"`
	CriticalCount        int              `json:"critical_count"`
	HighCount            int              `json:"high_count"`
	MediumCount          int              `json:"medium_count"`
	LowCount             int              `json:"low_count"`
	Vulnerabilities      []*Vulnerability `json:"vulnerabilities"`
	Stats                *ScanStats       `json:"stats,omitempty"`
	Recommendations      []string         `json:"recommendations,omitempty"`
}

// ScanStats 扫描统计
type ScanStats struct {
	Duration      int     `json:"duration"` // 秒
	FilesScanned  int     `json:"files_scanned"`
	PackagesFound int     `json:"packages_found"`
	RiskScore     float64 `json:"risk_score"` // 0-10
}

// SecurityScanTool 安全扫描工具
type SecurityScanTool struct {
	registry *SecOpsToolRegistry
	runCmd   func(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

// NewSecurityScanTool 创建安全扫描工具
func NewSecurityScanTool(registry *SecOpsToolRegistry) *SecurityScanTool {
	return &SecurityScanTool{
		registry: registry,
		runCmd:   runCommand,
	}
}

// Type 实现 Tool.Type
func (sst *SecurityScanTool) Type() ToolType {
	return ToolTypeSecurityScan
}

// Name 实现 Tool.Name
func (sst *SecurityScanTool) Name() string {
	return "Security Scan"
}

// Description 实现 Tool.Description
func (sst *SecurityScanTool) Description() string {
	return "Scan for vulnerabilities using multiple scanners (Trivy, Grype, Nuclei)"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (sst *SecurityScanTool) RequiredCapabilities() []string {
	return []string{
		"security:scan",
		"security:analyze",
	}
}

// ValidateParams 实现 Tool.ValidateParams
func (sst *SecurityScanTool) ValidateParams(params interface{}) error {
	p, ok := params.(*SecurityScanParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.Scanner == "" {
		return fmt.Errorf("scanner is required")
	}

	if p.Target == "" {
		return fmt.Errorf("target is required")
	}

	if p.TargetPath == "" {
		return fmt.Errorf("target_path is required")
	}

	validScanners := map[ScannerType]bool{
		ScannerTrivy:  true,
		ScannerGrype:  true,
		ScannerNuclei: true,
		ScannerClamAV: true,
	}
	if !validScanners[p.Scanner] {
		return fmt.Errorf("unsupported scanner: %s", p.Scanner)
	}

	validTargets := map[ScanTarget]bool{
		TargetImage:      true,
		TargetFilesystem: true,
		TargetGit:        true,
		TargetURL:        true,
	}
	if !validTargets[p.Target] {
		return fmt.Errorf("unsupported target: %s", p.Target)
	}

	return nil
}

// Execute 实现 Tool.Execute
func (sst *SecurityScanTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*SecurityScanParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := sst.ValidateParams(p); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := sst.performScan(ctx, p)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// 私有方法

// performScan 执行扫描
func (sst *SecurityScanTool) performScan(ctx context.Context, params *SecurityScanParams) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:         params.Scanner,
		Target:          params.TargetPath,
		ScanTime:        time.Now(),
		Vulnerabilities: make([]*Vulnerability, 0),
		Recommendations: make([]string, 0),
	}

	// 根据扫描器执行扫描
	var err error
	switch params.Scanner {
	case ScannerTrivy:
		err = sst.scanWithTrivy(ctx, params, result)
	case ScannerGrype:
		err = sst.scanWithGrype(ctx, params, result)
	case ScannerNuclei:
		err = sst.scanWithNuclei(ctx, params, result)
	case ScannerClamAV:
		err = sst.scanWithClamAV(ctx, params, result)
	default:
		err = fmt.Errorf("unsupported scanner: %s", params.Scanner)
	}
	if err != nil {
		return nil, err
	}

	// 统计结果
	sst.statisticsVulnerabilities(result)

	// 生成建议
	result.Recommendations = sst.generateRecommendations(result)

	return result, nil
}

// scanWithTrivy Trivy 扫描
func (sst *SecurityScanTool) scanWithTrivy(ctx context.Context, params *SecurityScanParams, result *ScanResult) error {
	mode := "image"
	switch params.Target {
	case TargetImage:
		mode = "image"
	case TargetFilesystem, TargetGit:
		mode = "fs"
	case TargetURL:
		return fmt.Errorf("trivy does not support url target directly")
	}

	args := []string{mode, "--format", "json", "--quiet"}
	if scanner := normalizeScanType(params.ScanType); scanner != "" {
		args = append(args, "--scanners", scanner)
	}
	if sev := strings.TrimSpace(strings.ToUpper(params.Severity)); sev != "" {
		args = append(args, "--severity", sev)
	}
	args = append(args, params.TargetPath)

	stdout, stderr, err := sst.execScanner(ctx, "trivy", args...)
	if err != nil {
		return fmt.Errorf("trivy scan failed: %w (%s)", err, strings.TrimSpace(string(stderr)))
	}
	vulns, stats, err := parseTrivyOutput(stdout)
	if err != nil {
		return err
	}
	result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	result.Stats = mergeStats(result.Stats, stats)
	return nil
}

// scanWithGrype Grype 扫描
func (sst *SecurityScanTool) scanWithGrype(ctx context.Context, params *SecurityScanParams, result *ScanResult) error {
	if params.Target == TargetURL {
		return fmt.Errorf("grype does not support url target directly")
	}
	args := []string{params.TargetPath, "-o", "json"}
	if sev := strings.TrimSpace(strings.ToLower(params.Severity)); sev != "" {
		args = append(args, "--only-fixed=false", "--fail-on", sev)
	}
	stdout, stderr, err := sst.execScanner(ctx, "grype", args...)
	if err != nil {
		return fmt.Errorf("grype scan failed: %w (%s)", err, strings.TrimSpace(string(stderr)))
	}
	vulns, stats, err := parseGrypeOutput(stdout)
	if err != nil {
		return err
	}
	result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	result.Stats = mergeStats(result.Stats, stats)
	return nil
}

// scanWithNuclei Nuclei 扫描
func (sst *SecurityScanTool) scanWithNuclei(ctx context.Context, params *SecurityScanParams, result *ScanResult) error {
	target := params.TargetPath
	switch params.Target {
	case TargetFilesystem, TargetGit:
		target = "file://" + params.TargetPath
	}
	args := []string{"-target", target, "-jsonl", "-silent"}
	stdout, stderr, err := sst.execScanner(ctx, "nuclei", args...)
	if err != nil {
		return fmt.Errorf("nuclei scan failed: %w (%s)", err, strings.TrimSpace(string(stderr)))
	}
	vulns, stats, err := parseNucleiOutput(stdout)
	if err != nil {
		return err
	}
	result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	result.Stats = mergeStats(result.Stats, stats)
	return nil
}

// scanWithClamAV ClamAV 扫描
func (sst *SecurityScanTool) scanWithClamAV(ctx context.Context, params *SecurityScanParams, result *ScanResult) error {
	args := []string{"-r", "--infected", "--no-summary", params.TargetPath}
	stdout, stderr, err := sst.execScanner(ctx, "clamscan", args...)
	if err != nil {
		return fmt.Errorf("clamav scan failed: %w (%s)", err, strings.TrimSpace(string(stderr)))
	}
	vulns, stats := parseClamAVOutput(stdout)
	result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	result.Stats = mergeStats(result.Stats, stats)
	return nil
}

func normalizeScanType(scanType string) string {
	switch strings.ToLower(strings.TrimSpace(scanType)) {
	case "", "all":
		return "vuln,config,secret"
	case "vuln":
		return "vuln"
	case "config":
		return "config"
	case "secret":
		return "secret"
	default:
		return ""
	}
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err == nil {
		return out, nil, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return out, ee.Stderr, err
	}
	return out, nil, err
}

func (sst *SecurityScanTool) execScanner(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	if sst.runCmd == nil {
		sst.runCmd = runCommand
	}
	return sst.runCmd(ctx, name, args...)
}

func parseTrivyOutput(out []byte) ([]*Vulnerability, *ScanStats, error) {
	type trivyVuln struct {
		ID           string                        `json:"VulnerabilityID"`
		Title        string                        `json:"Title"`
		Description  string                        `json:"Description"`
		Severity     string                        `json:"Severity"`
		Package      string                        `json:"PkgName"`
		Version      string                        `json:"InstalledVersion"`
		FixedVersion string                        `json:"FixedVersion"`
		PrimaryURL   string                        `json:"PrimaryURL"`
		CVSS         map[string]map[string]float64 `json:"CVSS"`
	}
	type trivyResult struct {
		Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
	}
	var payload struct {
		Results []trivyResult `json:"Results"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil, nil, fmt.Errorf("parse trivy output: %w", err)
	}

	vulns := make([]*Vulnerability, 0)
	for _, res := range payload.Results {
		for _, v := range res.Vulnerabilities {
			cvss := 0.0
			for _, source := range v.CVSS {
				if score, ok := source["V3Score"]; ok && score > cvss {
					cvss = score
				}
			}
			fix := &Fix{Available: v.FixedVersion != "", Version: v.FixedVersion}
			vulns = append(vulns, &Vulnerability{
				ID:          v.ID,
				Title:       v.Title,
				Description: v.Description,
				Severity:    parseSeverity(v.Severity),
				Package:     v.Package,
				Version:     v.Version,
				CVE:         v.ID,
				CVSS:        cvss,
				Reference:   v.PrimaryURL,
				Fix:         fix,
				FoundAt:     time.Now(),
			})
		}
	}

	return vulns, &ScanStats{FilesScanned: len(payload.Results)}, nil
}

func parseGrypeOutput(out []byte) ([]*Vulnerability, *ScanStats, error) {
	type match struct {
		Vulnerability struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
			DataSource  string `json:"dataSource"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	}
	var payload struct {
		Matches []match `json:"matches"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil, nil, fmt.Errorf("parse grype output: %w", err)
	}

	vulns := make([]*Vulnerability, 0, len(payload.Matches))
	for _, m := range payload.Matches {
		vulns = append(vulns, &Vulnerability{
			ID:          m.Vulnerability.ID,
			Title:       m.Vulnerability.ID,
			Description: m.Vulnerability.Description,
			Severity:    parseSeverity(m.Vulnerability.Severity),
			Package:     m.Artifact.Name,
			Version:     m.Artifact.Version,
			CVE:         m.Vulnerability.ID,
			Reference:   m.Vulnerability.DataSource,
			FoundAt:     time.Now(),
		})
	}
	return vulns, &ScanStats{PackagesFound: len(payload.Matches)}, nil
}

func parseNucleiOutput(out []byte) ([]*Vulnerability, *ScanStats, error) {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	vulns := make([]*Vulnerability, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var evt struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name        string `json:"name"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
			} `json:"info"`
			MatchedAt string `json:"matched-at"`
		}
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			return nil, nil, fmt.Errorf("parse nuclei output: %w", err)
		}
		vulns = append(vulns, &Vulnerability{
			ID:          evt.TemplateID,
			Title:       evt.Info.Name,
			Description: evt.Info.Description,
			Severity:    parseSeverity(evt.Info.Severity),
			Package:     evt.MatchedAt,
			CVE:         evt.TemplateID,
			FoundAt:     time.Now(),
		})
	}
	return vulns, &ScanStats{FilesScanned: len(lines)}, nil
}

func parseClamAVOutput(out []byte) ([]*Vulnerability, *ScanStats) {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	vulns := make([]*Vulnerability, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, " FOUND") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		path := strings.TrimSpace(parts[0])
		sig := "malware"
		if len(parts) == 2 {
			sig = strings.TrimSpace(strings.TrimSuffix(parts[1], "FOUND"))
		}
		vulns = append(vulns, &Vulnerability{
			ID:          "CLAMAV-" + strings.ToUpper(strings.ReplaceAll(sig, " ", "_")),
			Title:       "Malware detected",
			Description: sig,
			Severity:    VulnHigh,
			Package:     path,
			CVE:         "",
			FoundAt:     time.Now(),
		})
	}
	return vulns, &ScanStats{FilesScanned: len(lines)}
}

func parseSeverity(s string) VulnerabilityLevel {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return VulnCritical
	case "HIGH":
		return VulnHigh
	case "MEDIUM":
		return VulnMedium
	default:
		return VulnLow
	}
}

func mergeStats(existing, incoming *ScanStats) *ScanStats {
	if existing == nil {
		existing = &ScanStats{}
	}
	if incoming == nil {
		return existing
	}
	existing.Duration += incoming.Duration
	existing.FilesScanned += incoming.FilesScanned
	existing.PackagesFound += incoming.PackagesFound
	if incoming.RiskScore > existing.RiskScore {
		existing.RiskScore = incoming.RiskScore
	}
	return existing
}

// statisticsVulnerabilities 统计漏洞
func (sst *SecurityScanTool) statisticsVulnerabilities(result *ScanResult) {
	for _, vuln := range result.Vulnerabilities {
		result.TotalVulnerabilities++

		switch vuln.Severity {
		case VulnCritical:
			result.CriticalCount++
		case VulnHigh:
			result.HighCount++
		case VulnMedium:
			result.MediumCount++
		case VulnLow:
			result.LowCount++
		}
	}

	// 计算风险评分
	if len(result.Vulnerabilities) > 0 {
		riskScore := float64(result.CriticalCount)*10 + float64(result.HighCount)*8 +
			float64(result.MediumCount)*5 + float64(result.LowCount)*2
		riskScore = riskScore / float64(len(result.Vulnerabilities))
		if riskScore > 10 {
			riskScore = 10
		}

		if result.Stats == nil {
			result.Stats = &ScanStats{}
		}
		result.Stats.RiskScore = riskScore
	}
}

// generateRecommendations 生成建议
func (sst *SecurityScanTool) generateRecommendations(result *ScanResult) []string {
	recommendations := make([]string, 0)

	if result.CriticalCount > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("CRITICAL: Fix %d critical vulnerabilities immediately", result.CriticalCount))
	}

	if result.HighCount > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("HIGH: Patch %d high-severity vulnerabilities within 30 days", result.HighCount))
	}

	if result.MediumCount > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("MEDIUM: Schedule patches for %d medium-severity vulnerabilities", result.MediumCount))
	}

	if result.TotalVulnerabilities == 0 {
		recommendations = append(recommendations, "No vulnerabilities detected. Keep monitoring.")
	}

	return recommendations
}
