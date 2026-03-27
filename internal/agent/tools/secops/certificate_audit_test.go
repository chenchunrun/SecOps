package secops

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertificateAuditTool_Type(t *testing.T) {
	tool := NewCertificateAuditTool(nil)
	if tool.Type() != ToolTypeCertificateAudit {
		t.Errorf("expected %v, got %v", ToolTypeCertificateAudit, tool.Type())
	}
}

func TestCertificateAuditTool_ValidateParams(t *testing.T) {
	tool := NewCertificateAuditTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name:    "valid with path",
			params:  &CertificateAuditParams{Paths: []string{"/etc/ssl/certs/cert.pem"}},
			wantErr: false,
		},
		{
			name:    "valid with search dir",
			params:  &CertificateAuditParams{SearchDirs: []string{"/etc/ssl/certs"}},
			wantErr: false,
		},
		{
			name:    "valid with service port",
			params:  &CertificateAuditParams{ServicePorts: []string{"443"}},
			wantErr: false,
		},
		{
			name:    "missing all sources",
			params:  &CertificateAuditParams{},
			wantErr: true,
		},
		{
			name:    "invalid type",
			params:  "invalid",
			wantErr: true,
		},
		{
			name: "invalid key length",
			params: &CertificateAuditParams{
				Paths:        []string{"/etc/ssl/certs/cert.pem"},
				MinKeyLength: 512,
			},
			wantErr: true,
		},
		{
			name: "invalid remote port",
			params: &CertificateAuditParams{
				ServicePorts: []string{"443"},
				RemoteHost:   "10.0.0.80",
				RemotePort:   70000,
			},
			wantErr: true,
		},
		{
			name: "remote option without host",
			params: &CertificateAuditParams{
				ServicePorts: []string{"443"},
				RemoteUser:   "ops",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tool.ValidateParams(tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCertificateAuditTool_Execute(t *testing.T) {
	tool := NewCertificateAuditTool(nil)
	certPath := writeTestCertificate(t, t.TempDir())

	params := &CertificateAuditParams{
		Paths:            []string{certPath},
		CheckExpiry:      true,
		CheckKeyStrength: true,
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	auditResult, ok := result.(*CertificateAuditResult)
	if !ok {
		t.Fatal("expected CertificateAuditResult")
	}

	if auditResult.TotalCertificates == 0 {
		t.Error("expected certificates")
	}

	if auditResult.ValidCertificates+auditResult.ExpiredCertificates+auditResult.ExpiringCertificates == 0 {
		t.Error("expected at least one certificate with status")
	}
}

func TestCertificateAuditTool_ParseCertificateFile(t *testing.T) {
	tool := NewCertificateAuditTool(nil)
	certPath := writeTestCertificate(t, t.TempDir())
	cert := tool.parseCertificateFile(certPath)

	if cert == nil {
		t.Fatal("expected parsed certificate")
	}

	if cert.Subject == "" || cert.Issuer == "" {
		t.Error("expected subject and issuer")
	}

	if cert.KeyLength < 2048 {
		t.Errorf("expected key length >= 2048, got %d", cert.KeyLength)
	}
	if !cert.TransportVerified {
		t.Fatal("expected file-parsed certificate to remain transport-verified")
	}
}

func TestCertificateAuditTool_HasWeakKey(t *testing.T) {
	tool := NewCertificateAuditTool(nil)

	tests := []struct {
		name     string
		keyLen   int
		sigAlg   string
		expected bool
	}{
		{
			name:     "strong key",
			keyLen:   2048,
			sigAlg:   "SHA256-RSA",
			expected: false,
		},
		{
			name:     "weak key length",
			keyLen:   1024,
			sigAlg:   "SHA256-RSA",
			expected: true,
		},
		{
			name:     "weak algorithm",
			keyLen:   2048,
			sigAlg:   "SHA1-RSA",
			expected: true,
		},
		{
			name:     "very weak",
			keyLen:   512,
			sigAlg:   "SHA1-RSA",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &CertificateInfo{
				KeyLength:    tt.keyLen,
				SignatureAlg: tt.sigAlg,
			}

			result := tool.hasWeakKey(cert)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCertificateAuditTool_AuditCertificate(t *testing.T) {
	tool := NewCertificateAuditTool(nil)

	now := time.Now()

	tests := []struct {
		name           string
		cert           *CertificateInfo
		params         *CertificateAuditParams
		expectedStatus string
	}{
		{
			name: "valid certificate",
			cert: &CertificateInfo{
				NotAfter:     now.AddDate(1, 0, 0),
				KeyLength:    2048,
				SignatureAlg: "SHA256-RSA",
				Issues:       make([]*CertIssue, 0),
			},
			params: &CertificateAuditParams{
				CheckExpiry:       true,
				CheckKeyStrength:  true,
				ExpiryWarningDays: 30,
				MinKeyLength:      2048,
			},
			expectedStatus: "valid",
		},
		{
			name: "expiring certificate",
			cert: &CertificateInfo{
				NotAfter:     now.AddDate(0, 0, 15),
				KeyLength:    2048,
				SignatureAlg: "SHA256-RSA",
				Issues:       make([]*CertIssue, 0),
			},
			params: &CertificateAuditParams{
				CheckExpiry:       true,
				CheckKeyStrength:  true,
				ExpiryWarningDays: 30,
				MinKeyLength:      2048,
			},
			expectedStatus: "expiring_soon",
		},
		{
			name: "expired certificate",
			cert: &CertificateInfo{
				NotAfter:     now.AddDate(-1, 0, 0),
				KeyLength:    2048,
				SignatureAlg: "SHA256-RSA",
				Issues:       make([]*CertIssue, 0),
			},
			params: &CertificateAuditParams{
				CheckExpiry:       true,
				CheckKeyStrength:  true,
				ExpiryWarningDays: 30,
				MinKeyLength:      2048,
			},
			expectedStatus: "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool.auditCertificate(tt.cert, tt.params)
			if tt.cert.Status != tt.expectedStatus {
				t.Errorf("expected status %s, got %s", tt.expectedStatus, tt.cert.Status)
			}
		})
	}
}

func TestCertificateAuditTool_DaysUntilExpiry(t *testing.T) {
	tool := NewCertificateAuditTool(nil)

	now := time.Now()

	cert := &CertificateInfo{
		NotAfter: now.AddDate(0, 0, 30),
		Issues:   make([]*CertIssue, 0),
	}

	params := &CertificateAuditParams{
		CheckExpiry:      true,
		CheckKeyStrength: false,
	}

	tool.auditCertificate(cert, params)

	if cert.DaysUntilExpiry < 29 || cert.DaysUntilExpiry > 31 {
		t.Errorf("expected days until expiry around 30, got %d", cert.DaysUntilExpiry)
	}
}

func TestCertificateAuditTool_Execute_RemoteService(t *testing.T) {
	tool := NewCertificateAuditTool(nil)
	certPath := writeTestCertificate(t, t.TempDir())
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert pem: %v", err)
	}

	var gotName string
	var gotArgs []string
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return pemBytes, nil, nil
	}

	result, err := tool.Execute(&CertificateAuditParams{
		ServicePorts:      []string{"443"},
		CheckExpiry:       true,
		CheckKeyStrength:  true,
		RemoteHost:        "10.0.0.80",
		RemoteUser:        "ops",
		RemotePort:        2222,
		RemoteKeyPath:     "/tmp/id_ed25519",
		RemoteProxyJump:   "bastion",
		ExpiryWarningDays: 30,
		MinKeyLength:      2048,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	ar, ok := result.(*CertificateAuditResult)
	if !ok {
		t.Fatal("expected CertificateAuditResult")
	}
	if ar.TotalCertificates == 0 {
		t.Fatal("expected remote certificate to be collected")
	}
	if ar.Certificates[0].TransportVerified {
		t.Fatal("expected remote-probed certificate to be marked transport-unverified")
	}
	if ar.Certificates[0].CollectionMethod != "remote_openssl_probe" {
		t.Fatalf("unexpected collection method: %q", ar.Certificates[0].CollectionMethod)
	}
	foundUnverifiedIssue := false
	for _, issue := range ar.Certificates[0].Issues {
		if issue.Type == "transport_unverified" {
			foundUnverifiedIssue = true
			break
		}
	}
	if !foundUnverifiedIssue {
		t.Fatal("expected transport_unverified issue on remote-probed certificate")
	}
	if gotName != "ssh" {
		t.Fatalf("expected ssh command, got %s", gotName)
	}
	if !strings.Contains(strings.Join(gotArgs, " "), "ops@10.0.0.80") {
		t.Fatalf("unexpected ssh args: %q", strings.Join(gotArgs, " "))
	}
}

func BenchmarkCertificateAuditTool_Execute(b *testing.B) {
	tool := NewCertificateAuditTool(nil)
	certPath := writeTestCertificateTB(b, b.TempDir())
	params := &CertificateAuditParams{
		Paths:            []string{certPath},
		CheckExpiry:      true,
		CheckKeyStrength: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}

func writeTestCertificate(t *testing.T, dir string) string {
	t.Helper()
	return writeTestCertificateTB(t, dir)
}

func writeTestCertificateTB(tb testing.TB, dir string) string {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName:   "test.local",
			Organization: []string{"SecOps Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.local"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create cert: %v", err)
	}

	path := filepath.Join(dir, "test-cert.pem")
	file, err := os.Create(path)
	if err != nil {
		tb.Fatalf("create cert file: %v", err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		tb.Fatalf("encode cert: %v", err)
	}
	return path
}
