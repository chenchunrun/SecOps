package secops

import (
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

	params := &CertificateAuditParams{
		Paths:            []string{"/etc/ssl/certs/cert.pem"},
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

func TestCertificateAuditTool_GetMockCertificates(t *testing.T) {
	tool := NewCertificateAuditTool(nil)
	certs := tool.getMockCertificates()

	if len(certs) != 3 {
		t.Errorf("expected 3 mock certificates, got %d", len(certs))
	}

	// 检查有效证书
	if certs[0].Status != "valid" {
		t.Errorf("expected first certificate to be valid, got %s", certs[0].Status)
	}

	// 检查即将过期的证书
	if certs[1].Status != "expiring_soon" {
		t.Errorf("expected second certificate to be expiring_soon, got %s", certs[1].Status)
	}

	// 检查弱密钥证书
	if certs[2].KeyLength != 1024 {
		t.Errorf("expected third certificate to have 1024-bit key, got %d", certs[2].KeyLength)
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
		name          string
		cert          *CertificateInfo
		params        *CertificateAuditParams
		expectedStatus string
	}{
		{
			name: "valid certificate",
			cert: &CertificateInfo{
				NotAfter:   now.AddDate(1, 0, 0),
				KeyLength:  2048,
				SignatureAlg: "SHA256-RSA",
				Issues:     make([]*CertIssue, 0),
			},
			params: &CertificateAuditParams{
				CheckExpiry:      true,
				CheckKeyStrength: true,
				ExpiryWarningDays: 30,
				MinKeyLength:     2048,
			},
			expectedStatus: "valid",
		},
		{
			name: "expiring certificate",
			cert: &CertificateInfo{
				NotAfter:   now.AddDate(0, 0, 15),
				KeyLength:  2048,
				SignatureAlg: "SHA256-RSA",
				Issues:     make([]*CertIssue, 0),
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
				NotAfter:   now.AddDate(-1, 0, 0),
				KeyLength:  2048,
				SignatureAlg: "SHA256-RSA",
				Issues:     make([]*CertIssue, 0),
			},
			params: &CertificateAuditParams{
				CheckExpiry:      true,
				CheckKeyStrength: true,
				ExpiryWarningDays: 30,
				MinKeyLength:     2048,
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

func BenchmarkCertificateAuditTool_Execute(b *testing.B) {
	tool := NewCertificateAuditTool(nil)
	params := &CertificateAuditParams{
		Paths:            []string{"/etc/ssl/certs/cert.pem"},
		CheckExpiry:      true,
		CheckKeyStrength: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}
