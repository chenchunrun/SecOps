package secops

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// 本测试文件提升 configuration_audit.go / security_scan.go /
// compliance_check.go 的测试覆盖率。
//
// 关键技巧：SecurityScanTool 与 ComplianceCheckTool 均暴露可覆盖的 runCmd
// 字段，scanWith* 与远程 stat/cat 经此注入确定性输出（无真实 CLI/网络）。
// ConfigurationAuditTool 的远程读取经由包级 runRemoteCommand，但其本地分支
// 与规则访问器可直接覆盖。

func TestConfigurationAudit_auditRule_本地分支覆盖(t *testing.T) {
	// 本地分支（RemoteHost 为空）会落到真实的系统读取；此处仅确保各 case 被执行
	// 并产出合法状态，不假定具体取值。覆盖 auditRule 本地路径的语句。
	tool := NewConfigurationAuditTool(nil)
	rules := tool.getSSHRules(&ConfigAuditParams{})
	for _, r := range rules {
		tool.auditRule(r, &ConfigAuditParams{})
		if r.Status == "" {
			t.Fatalf("rule %s 状态未设置", r.ID)
		}
	}
	for _, r := range tool.getSudoRules(&ConfigAuditParams{}) {
		tool.auditRule(r, &ConfigAuditParams{})
	}
	for _, r := range tool.getFirewallRules(&ConfigAuditParams{}) {
		tool.auditRule(r, &ConfigAuditParams{})
	}
	for _, r := range tool.getKernelRules(&ConfigAuditParams{}) {
		tool.auditRule(r, &ConfigAuditParams{})
	}
	for _, r := range tool.getSysctlRules(&ConfigAuditParams{}) {
		tool.auditRule(r, &ConfigAuditParams{})
	}
}

func TestConfigurationAudit_本地辅助读取函数(t *testing.T) {
	// 直接覆盖本地读取助手，确保各分支被执行。
	t.Run("readFileMode", func(t *testing.T) {
		// 已知存在路径
		if mode, ok := readFileMode("/etc/passwd"); !ok {
			_ = mode // 容许读取失败（部分沙箱），只要函数不 panic 即可
		}
		// 不存在路径
		if _, ok := readFileMode("/this/does/not/exist/12345"); ok {
			t.Fatal("期望对不存在路径返回 ok=false")
		}
	})

	t.Run("readSSHDConfigValue", func(t *testing.T) {
		// 调用一次以覆盖（macOS 可能存在 /etc/ssh/sshd_config）
		_, _ = readSSHDConfigValue("PermitRootLogin")
	})

	t.Run("readSysctlValue", func(t *testing.T) {
		_, _ = readSysctlValue("kernel.randomize_va_space")
	})

	t.Run("hasSudoLogOutput/hasSudoNoPassword", func(t *testing.T) {
		_, _ = hasSudoLogOutput()
		_, _ = hasSudoNoPassword()
	})

	t.Run("firewallEnabled/defaultInboundDrop", func(t *testing.T) {
		_, _ = firewallEnabled()
		_, _ = defaultInboundDrop()
	})
}

// =====================================================================
// ConfigurationAuditTool: 规则集访问器（此前 0%）
// =====================================================================

func TestConfigurationAudit_规则集访问器(t *testing.T) {
	tool := NewConfigurationAuditTool(nil)
	params := &ConfigAuditParams{}

	if len(tool.getFilePermRules(params)) == 0 {
		t.Fatal("期望文件权限规则非空")
	}
	if len(tool.getKernelRules(params)) == 0 {
		t.Fatal("期望内核规则非空")
	}
	if len(tool.getSysctlRules(params)) == 0 {
		t.Fatal("期望 sysctl 规则非空")
	}
	// getRulesForTarget 默认分支（非法目标返回空切片）
	if got := tool.getRulesForTarget(ConfigAuditTarget("bogus"), params); len(got) != 0 {
		t.Fatalf("期望非法目标返回空切片，got %d", len(got))
	}
	// isValidTarget 的 false 分支
	if tool.isValidTarget(ConfigAuditTarget("bogus")) {
		t.Fatal("期望非法目标 isValidTarget 返回 false")
	}
}

// =====================================================================
// ConfigurationAuditTool: runRemoteCommand 边界（此前 70%）
// =====================================================================

func TestConfigurationAudit_runRemoteCommand_边界(t *testing.T) {
	if _, ok := runRemoteCommand(nil, "echo hi"); ok {
		t.Fatal("期望 nil params 返回 false")
	}
	if _, ok := runRemoteCommand(&ConfigAuditParams{}, "echo hi"); ok {
		t.Fatal("期望空 RemoteHost 返回 false")
	}
}

func TestConfigurationAudit_auditShellQuote(t *testing.T) {
	if got := auditShellQuote(""); got != "''" {
		t.Fatalf("空串引用 = %q", got)
	}
	if got := auditShellQuote("a'b"); !strings.Contains(got, `'"'"'`) {
		t.Fatalf("单引号转义缺失: %q", got)
	}
}

// =====================================================================
// SecurityScanTool: normalizeScanType / parseSeverity（纯函数）
// =====================================================================

func TestSecurityScan_normalizeScanType(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "vuln,config,secret"},
		{"  ", "vuln,config,secret"},
		{"ALL", "vuln,config,secret"},
		{"vuln", "vuln"},
		{"VULN", "vuln"},
		{"config", "config"},
		{"secret", "secret"},
		{"unknown", ""},
		{"  vuln  ", "vuln"},
	}
	for _, tc := range cases {
		if got := normalizeScanType(tc.in); got != tc.want {
			t.Errorf("normalizeScanType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSecurityScan_parseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want VulnerabilityLevel
	}{
		{"CRITICAL", VulnCritical},
		{"critical", VulnCritical},
		{"  High ", VulnHigh},
		{"MEDIUM", VulnMedium},
		{"anything-else", VulnLow},
		{"", VulnLow},
	}
	for _, tc := range cases {
		if got := parseSeverity(tc.in); got != tc.want {
			t.Errorf("parseSeverity(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// =====================================================================
// SecurityScanTool: scanWith* CLI 运行器（runCmd 覆盖）
// =====================================================================

func TestSecurityScan_scanWithNuclei(t *testing.T) {
	const nucleiJSONL = `{"template-id":"CVE-2021-1","info":{"name":"RCE","severity":"critical","description":"rce"},"matched-at":"http://example.com"}
{"template-id":"CVE-2021-2","info":{"name":"InfoLeak","severity":"info"},"matched-at":"http://example.com"}
`
	tool := NewSecurityScanTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return []byte(nucleiJSONL), nil, nil
	}

	result := &ScanResult{Vulnerabilities: make([]*Vulnerability, 0)}
	err := tool.scanWithNuclei(context.Background(), &SecurityScanParams{
		Scanner: ScannerNuclei, Target: TargetURL, TargetPath: "http://example.com",
	}, result)
	if err != nil {
		t.Fatalf("scanWithNuclei: %v", err)
	}
	if len(result.Vulnerabilities) != 2 {
		t.Fatalf("期望 2 个漏洞，got %d", len(result.Vulnerabilities))
	}
	if result.Vulnerabilities[0].Severity != VulnCritical {
		t.Fatalf("期望第一个为 CRITICAL，got %v", result.Vulnerabilities[0].Severity)
	}

	// filesystem target 命中 file:// 前缀分支
	fsResult := &ScanResult{Vulnerabilities: make([]*Vulnerability, 0)}
	if err := tool.scanWithNuclei(context.Background(), &SecurityScanParams{
		Scanner: ScannerNuclei, Target: TargetFilesystem, TargetPath: "/tmp/scan",
	}, fsResult); err != nil {
		t.Fatalf("scanWithNuclei fs: %v", err)
	}

	// 命令失败路径
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, []byte("boom"), errors.New("exec failed")
	}
	if err := tool.scanWithNuclei(context.Background(), &SecurityScanParams{
		Scanner: ScannerNuclei, Target: TargetURL, TargetPath: "http://example.com",
	}, &ScanResult{Vulnerabilities: make([]*Vulnerability, 0)}); err == nil {
		t.Fatal("期望 nuclei 命令失败返回 error")
	}
}

func TestSecurityScan_scanWithGrype(t *testing.T) {
	const grypeJSON = `{"matches":[{"vulnerability":{"id":"CVE-2022-2","severity":"High","description":"dos","dataSource":"https://nvd"},"artifact":{"name":"log4j","version":"2.14"}}]}`
	tool := NewSecurityScanTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return []byte(grypeJSON), nil, nil
	}

	// image 目标 + severity 过滤
	result := &ScanResult{Vulnerabilities: make([]*Vulnerability, 0)}
	err := tool.scanWithGrype(context.Background(), &SecurityScanParams{
		Scanner: ScannerGrype, Target: TargetImage, TargetPath: "log4j:2.14", Severity: "high",
	}, result)
	if err != nil {
		t.Fatalf("scanWithGrype: %v", err)
	}
	if len(result.Vulnerabilities) != 1 || result.Vulnerabilities[0].Package != "log4j" {
		t.Fatalf("意外结果: %+v", result.Vulnerabilities)
	}

	// URL 目标直接报错
	if err := tool.scanWithGrype(context.Background(), &SecurityScanParams{
		Scanner: ScannerGrype, Target: TargetURL, TargetPath: "http://x",
	}, result); err == nil {
		t.Fatal("期望 grype 对 URL 目标报错")
	}

	// 命令失败路径
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, []byte("boom"), errors.New("exec failed")
	}
	if err := tool.scanWithGrype(context.Background(), &SecurityScanParams{
		Scanner: ScannerGrype, Target: TargetImage, TargetPath: "x",
	}, result); err == nil {
		t.Fatal("期望 grype 命令失败返回 error")
	}
}

func TestSecurityScan_scanWithClamAV(t *testing.T) {
	const clamOut = `/tmp/infected.exe: Win.Test.EICAR FOUND
/var/clean.txt: OK
`
	tool := NewSecurityScanTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return []byte(clamOut), nil, nil
	}

	result := &ScanResult{Vulnerabilities: make([]*Vulnerability, 0)}
	if err := tool.scanWithClamAV(context.Background(), &SecurityScanParams{
		Scanner: ScannerClamAV, Target: TargetFilesystem, TargetPath: "/tmp",
	}, result); err != nil {
		t.Fatalf("scanWithClamAV: %v", err)
	}
	if len(result.Vulnerabilities) != 1 {
		t.Fatalf("期望 1 个恶意软件，got %d", len(result.Vulnerabilities))
	}
	if result.Vulnerabilities[0].Severity != VulnHigh {
		t.Fatalf("期望 HIGH，got %v", result.Vulnerabilities[0].Severity)
	}

	// 命令失败路径（clamav 即使 stderr 也包装 error）
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, []byte("scan failed"), errors.New("exec failed")
	}
	if err := tool.scanWithClamAV(context.Background(), &SecurityScanParams{
		Scanner: ScannerClamAV, Target: TargetFilesystem, TargetPath: "/tmp",
	}, result); err == nil {
		t.Fatal("期望 clamav 命令失败返回 error")
	}
}

func TestSecurityScan_scanWithTrivy_URL与空结果(t *testing.T) {
	tool := NewSecurityScanTool(nil)
	// URL 目标直接返回错误
	if err := tool.scanWithTrivy(context.Background(), &SecurityScanParams{
		Scanner: ScannerTrivy, Target: TargetURL, TargetPath: "http://x",
	}, &ScanResult{Vulnerabilities: make([]*Vulnerability, 0)}); err == nil {
		t.Fatal("期望 trivy 对 URL 目标报错")
	}

	// 空结果 + 默认 scan_type
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return []byte(`{"Results":[]}`), nil, nil
	}
	result := &ScanResult{Vulnerabilities: make([]*Vulnerability, 0)}
	if err := tool.scanWithTrivy(context.Background(), &SecurityScanParams{
		Scanner: ScannerTrivy, Target: TargetFilesystem, TargetPath: "/tmp", ScanType: "all", Severity: "high",
	}, result); err != nil {
		t.Fatalf("scanWithTrivy 空结果: %v", err)
	}
}

// =====================================================================
// SecurityScanTool: 暴露方法（此前 0%）
// =====================================================================

func TestSecurityScan_暴露方法(t *testing.T) {
	tool := NewSecurityScanTool(nil)
	if tool.Name() == "" {
		t.Fatal("期望非空 Name")
	}
	if tool.Description() == "" {
		t.Fatal("期望非空 Description")
	}
	if len(tool.RequiredCapabilities()) == 0 {
		t.Fatal("期望非空 RequiredCapabilities")
	}
}

// =====================================================================
// ComplianceCheckTool: evalCISFilesystem / evalCISIPForward（远程分支驱动）
// =====================================================================

func TestComplianceCheck_evalCISFilesystem_远程分支(t *testing.T) {
	cases := []struct {
		name     string
		statOut  string // "类型|大小|权限"
		statFail bool
		want     ComplianceStatus
	}{
		{"权限受限命中 passed", "regular file|123|644", false, StatusPassed},
		{"全局可写命中 failed", "regular file|123|646", false, StatusFailed},
		{"stat 失败命中 warning", "", true, StatusWarning},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool := NewComplianceCheckTool(nil)
			tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if tc.statFail {
					return nil, errors.New("remote stat failed")
				}
				return []byte(tc.statOut), nil
			}
			rule := &ComplianceRule{ID: "cis_1_1"}
			tool.evalCISFilesystem(rule, &ComplianceCheckParams{RemoteHost: "10.0.0.60"})
			if rule.Status != tc.want {
				t.Fatalf("status = %v, want %v (evidence=%s)", rule.Status, tc.want, rule.Evidence)
			}
		})
	}
}

func TestComplianceCheck_evalCISIPForward_远程分支(t *testing.T) {
	cases := []struct {
		name     string
		out      string
		fail     bool
		want     ComplianceStatus
	}{
		{"值为 0 命中 passed", "0\n", false, StatusPassed},
		{"值为 1 命中 warning", "1\n", false, StatusWarning},
		{"读取失败命中 warning", "", true, StatusWarning},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool := NewComplianceCheckTool(nil)
			tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if tc.fail {
					return nil, errors.New("remote cat failed")
				}
				return []byte(tc.out), nil
			}
			rule := &ComplianceRule{ID: "cis_3_1"}
			tool.evalCISIPForward(rule, &ComplianceCheckParams{RemoteHost: "10.0.0.61"})
			if rule.Status != tc.want {
				t.Fatalf("status = %v, want %v (evidence=%s)", rule.Status, tc.want, rule.Evidence)
			}
		})
	}
}

// =====================================================================
// ComplianceCheckTool: runComplianceCommand（此前 0%，包级默认实现）
// =====================================================================

func TestComplianceCheck_runComplianceCommand(t *testing.T) {
	ctx := context.Background()
	// 不存在的命令：应返回 error
	if _, err := runComplianceCommand(ctx, "nonexistent-cmd-xyz", "arg"); err == nil {
		t.Fatal("期望对不存在命令返回 error")
	}
}
