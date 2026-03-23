package secops

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CertificateAuditParams 证书审计参数
type CertificateAuditParams struct {
	// 证书来源
	Paths        []string `json:"paths,omitempty"`         // 证书文件路径
	SearchDirs   []string `json:"search_dirs,omitempty"`   // 搜索目录
	ServicePorts []string `json:"service_ports,omitempty"` // 服务端口

	// 检查选项
	CheckExpiry      bool `json:"check_expiry,omitempty"`       // 检查过期
	CheckKeyStrength bool `json:"check_key_strength,omitempty"` // 检查密钥强度
	CheckChain       bool `json:"check_chain,omitempty"`        // 检查证书链
	CheckRevocation  bool `json:"check_revocation,omitempty"`   // 检查撤销

	// 警告阈值
	ExpiryWarningDays int    `json:"expiry_warning_days,omitempty"` // 默认 30 天
	MinKeyLength      int    `json:"min_key_length,omitempty"`      // 最小密钥长度，默认 2048
	RemoteHost        string `json:"remote_host,omitempty"`
	RemoteUser        string `json:"remote_user,omitempty"`
	RemotePort        int    `json:"remote_port,omitempty"`
	RemoteKeyPath     string `json:"remote_key_path,omitempty"`
	RemoteProxyJump   string `json:"remote_proxy_jump,omitempty"`
}

// CertificateInfo 证书信息
type CertificateInfo struct {
	Path            string       `json:"path"`
	Subject         string       `json:"subject"`
	Issuer          string       `json:"issuer"`
	NotBefore       time.Time    `json:"not_before"`
	NotAfter        time.Time    `json:"not_after"`
	SerialNumber    string       `json:"serial_number"`
	KeyType         string       `json:"key_type"`   // RSA, ECDSA, etc.
	KeyLength       int          `json:"key_length"` // bits
	SignatureAlg    string       `json:"signature_alg"`
	IsSelfSigned    bool         `json:"is_self_signed"`
	SANs            []string     `json:"sans"`   // Subject Alternative Names
	Status          string       `json:"status"` // valid, expired, expiring_soon
	DaysUntilExpiry int          `json:"days_until_expiry"`
	Issues          []*CertIssue `json:"issues,omitempty"`
}

// CertIssue 证书问题
type CertIssue struct {
	Type        string `json:"type"`     // expiry, weak_key, self_signed, chain_error
	Severity    string `json:"severity"` // critical, warning, info
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// CertificateAuditResult 证书审计结果
type CertificateAuditResult struct {
	Timestamp            time.Time          `json:"timestamp"`
	TotalCertificates    int                `json:"total_certificates"`
	ValidCertificates    int                `json:"valid_certificates"`
	ExpiredCertificates  int                `json:"expired_certificates"`
	ExpiringCertificates int                `json:"expiring_certificates"`
	WeakCertificates     int                `json:"weak_certificates"`
	SelfSignedCerts      int                `json:"self_signed_certs"`
	Certificates         []*CertificateInfo `json:"certificates"`
	Issues               []*CertIssue       `json:"issues,omitempty"`
}

// CertificateAuditTool 证书审计工具
type CertificateAuditTool struct {
	registry *SecOpsToolRegistry
	runCmd   func(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

// NewCertificateAuditTool 创建证书审计工具
func NewCertificateAuditTool(registry *SecOpsToolRegistry) *CertificateAuditTool {
	return &CertificateAuditTool{
		registry: registry,
		runCmd:   runCertCommand,
	}
}

// Type 实现 Tool.Type
func (cat *CertificateAuditTool) Type() ToolType {
	return ToolTypeCertificateAudit
}

// Name 实现 Tool.Name
func (cat *CertificateAuditTool) Name() string {
	return "Certificate Auditor"
}

// Description 实现 Tool.Description
func (cat *CertificateAuditTool) Description() string {
	return "Audit SSL/TLS certificates for expiry, strength, and validity"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (cat *CertificateAuditTool) RequiredCapabilities() []string {
	return []string{
		"file:read",
		"compliance:check",
	}
}

// ValidateParams 实现 Tool.ValidateParams
func (cat *CertificateAuditTool) ValidateParams(params interface{}) error {
	p, ok := params.(*CertificateAuditParams)
	if !ok {
		return ErrInvalidParams
	}

	// 至少需要一种证书来源
	if len(p.Paths) == 0 && len(p.SearchDirs) == 0 && len(p.ServicePorts) == 0 {
		return fmt.Errorf("at least one of paths, search_dirs, or service_ports is required")
	}

	// 验证密钥长度
	if p.MinKeyLength == 0 {
		p.MinKeyLength = 2048 // 默认
	}

	if p.MinKeyLength < 1024 {
		return fmt.Errorf("minimum key length should be at least 1024")
	}

	// 验证过期警告天数
	if p.ExpiryWarningDays == 0 {
		p.ExpiryWarningDays = 30 // 默认 30 天
	}

	if p.ExpiryWarningDays < 0 {
		return fmt.Errorf("expiry warning days must be positive")
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
func (cat *CertificateAuditTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*CertificateAuditParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := cat.ValidateParams(p); err != nil {
		return nil, err
	}

	result := &CertificateAuditResult{
		Timestamp:    time.Now(),
		Certificates: make([]*CertificateInfo, 0),
		Issues:       make([]*CertIssue, 0),
	}

	// 收集证书
	certs := cat.collectCertificates(p)

	// 审计证书
	for _, cert := range certs {
		cat.auditCertificate(cert, p)
		result.Certificates = append(result.Certificates, cert)

		// 统计
		result.TotalCertificates++
		switch cert.Status {
		case "valid":
			result.ValidCertificates++
		case "expired":
			result.ExpiredCertificates++
		case "expiring_soon":
			result.ExpiringCertificates++
		}

		if cat.hasWeakKey(cert) {
			result.WeakCertificates++
		}

		if cert.IsSelfSigned {
			result.SelfSignedCerts++
		}
	}

	// 生成问题列表
	result.Issues = cat.generateIssues(result, p)

	return result, nil
}

// 私有方法

// collectCertificates 收集证书
func (cat *CertificateAuditTool) collectCertificates(params *CertificateAuditParams) []*CertificateInfo {
	certs := make([]*CertificateInfo, 0)
	seen := make(map[string]struct{})

	appendCert := func(cert *CertificateInfo) {
		if cert == nil {
			return
		}
		key := cert.Path + "|" + cert.SerialNumber
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		certs = append(certs, cert)
	}

	// 从指定路径收集
	for _, path := range params.Paths {
		cert := cat.parseCertificateFile(path)
		appendCert(cert)
	}

	// 从搜索目录收集
	for _, dir := range params.SearchDirs {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d == nil || d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".crt" && ext != ".pem" && ext != ".cer" {
				return nil
			}
			appendCert(cat.parseCertificateFile(path))
			return nil
		})
	}

	// 从服务端口收集
	for _, service := range params.ServicePorts {
		cert := cat.fetchCertificateFromService(service, params)
		appendCert(cert)
	}

	return certs
}

// parseCertificateFile 解析证书文件
func (cat *CertificateAuditTool) parseCertificateFile(path string) *CertificateInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var cert *x509.Certificate
	rest := data
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		parsed, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			continue
		}
		cert = parsed
		break
	}

	if cert == nil {
		parsed, parseErr := x509.ParseCertificate(data)
		if parseErr != nil {
			return nil
		}
		cert = parsed
	}

	return cat.certificateToInfo(path, cert)
}

// auditCertificate 审计单个证书
func (cat *CertificateAuditTool) auditCertificate(cert *CertificateInfo, params *CertificateAuditParams) {
	now := time.Now()

	// 检查过期
	if params.CheckExpiry {
		cert.DaysUntilExpiry = int(cert.NotAfter.Sub(now).Hours() / 24)

		if cert.NotAfter.Before(now) {
			cert.Status = "expired"
			cert.Issues = append(cert.Issues, &CertIssue{
				Type:        "expiry",
				Severity:    "critical",
				Description: "Certificate has expired",
				Remediation: "Renew the certificate immediately",
			})
		} else if cert.DaysUntilExpiry < params.ExpiryWarningDays {
			cert.Status = "expiring_soon"
		} else {
			cert.Status = "valid"
		}
	}

	// 检查密钥强度
	if params.CheckKeyStrength && cat.hasWeakKey(cert) {
		cert.Issues = append(cert.Issues, &CertIssue{
			Type:        "weak_key",
			Severity:    "critical",
			Description: fmt.Sprintf("Key length %d is less than minimum %d", cert.KeyLength, params.MinKeyLength),
			Remediation: fmt.Sprintf("Regenerate certificate with at least %d-bit key", params.MinKeyLength),
		})
	}
}

// hasWeakKey 检查是否有弱密钥
func (cat *CertificateAuditTool) hasWeakKey(cert *CertificateInfo) bool {
	return cert.KeyLength < 2048 || cert.SignatureAlg == "SHA1-RSA"
}

// generateIssues 生成问题列表
func (cat *CertificateAuditTool) generateIssues(result *CertificateAuditResult, params *CertificateAuditParams) []*CertIssue {
	issues := make([]*CertIssue, 0)

	for _, cert := range result.Certificates {
		issues = append(issues, cert.Issues...)
	}

	return issues
}

// CheckCertificateChain 检查证书链
func (cat *CertificateAuditTool) CheckCertificateChain(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, fmt.Errorf("certificate is nil")
	}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}

	intermediates := x509.NewCertPool()
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		if cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
			return true, nil
		}
		return false, err
	}
	return true, nil
}

// CheckRSAKeyStrength 检查 RSA 密钥强度
func (cat *CertificateAuditTool) CheckRSAKeyStrength(key *rsa.PublicKey) bool {
	// RSA 密钥强度应该至少为 2048 位
	return key.N.BitLen() >= 2048
}

func (cat *CertificateAuditTool) fetchCertificateFromService(service string, params *CertificateAuditParams) *CertificateInfo {
	target := strings.TrimSpace(service)
	if target == "" {
		return nil
	}

	if !strings.Contains(target, ":") {
		target = net.JoinHostPort("127.0.0.1", target)
	}
	if params != nil && strings.TrimSpace(params.RemoteHost) != "" {
		return cat.fetchCertificateFromServiceRemote(target, params)
	}

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	return cat.certificateToInfo(target, state.PeerCertificates[0])
}

func (cat *CertificateAuditTool) fetchCertificateFromServiceRemote(target string, params *CertificateAuditParams) *CertificateInfo {
	if cat.runCmd == nil {
		cat.runCmd = runCertCommand
	}
	sshArgs, err := buildCertSSHArgs(params, buildRemoteTLSFetchCommand(target))
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stdout, _, cmdErr := cat.runCmd(ctx, "ssh", sshArgs...)
	if cmdErr != nil && len(stdout) == 0 {
		return nil
	}
	cert := parseFirstCertificateFromText(stdout)
	if cert == nil {
		return nil
	}
	return cat.certificateToInfo(target, cert)
}

func parseFirstCertificateFromText(data []byte) *x509.Certificate {
	rest := data
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			return cert
		}
	}
	return nil
}

func buildRemoteTLSFetchCommand(target string) string {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil && strings.TrimSpace(h) != "" {
		host = h
	}
	return "echo | openssl s_client -servername " + shellQuoteCert(host) + " -connect " + shellQuoteCert(target) + " 2>/dev/null"
}

func runCertCommand(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
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

func buildCertSSHArgs(params *CertificateAuditParams, remoteCmd string) ([]string, error) {
	if params == nil {
		return nil, fmt.Errorf("remote params are required")
	}
	host := strings.TrimSpace(params.RemoteHost)
	if host == "" {
		return nil, fmt.Errorf("remote_host is required")
	}
	target := host
	user := strings.TrimSpace(params.RemoteUser)
	if user != "" {
		target = user + "@" + host
	}
	sshArgs := []string{"-o", "BatchMode=yes"}
	if params.RemotePort > 0 {
		sshArgs = append(sshArgs, "-p", strconv.Itoa(params.RemotePort))
	}
	if key := strings.TrimSpace(params.RemoteKeyPath); key != "" {
		sshArgs = append(sshArgs, "-i", key)
	}
	if jump := strings.TrimSpace(params.RemoteProxyJump); jump != "" {
		sshArgs = append(sshArgs, "-J", jump)
	}
	sshArgs = append(sshArgs, target, "sh", "-lc", remoteCmd)
	return sshArgs, nil
}

func shellQuoteCert(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

func (cat *CertificateAuditTool) certificateToInfo(path string, cert *x509.Certificate) *CertificateInfo {
	keyType := "Unknown"
	keyLength := 0

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keyType = "RSA"
		keyLength = pub.N.BitLen()
	case *ecdsa.PublicKey:
		keyType = "ECDSA"
		keyLength = pub.Params().BitSize
	case ed25519.PublicKey:
		keyType = "Ed25519"
		keyLength = len(pub) * 8
	}

	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs))
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	return &CertificateInfo{
		Path:            path,
		Subject:         cert.Subject.String(),
		Issuer:          cert.Issuer.String(),
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		SerialNumber:    cert.SerialNumber.String(),
		KeyType:         keyType,
		KeyLength:       keyLength,
		SignatureAlg:    cert.SignatureAlgorithm.String(),
		IsSelfSigned:    cert.Subject.String() == cert.Issuer.String() && cert.CheckSignatureFrom(cert) == nil,
		SANs:            sans,
		DaysUntilExpiry: int(time.Until(cert.NotAfter).Hours() / 24),
		Issues:          make([]*CertIssue, 0),
	}
}
