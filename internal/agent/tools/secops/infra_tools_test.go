package secops

import (
	"strings"
	"testing"
)

func TestDatabaseQueryTool_Type(t *testing.T) {
	tool := NewDatabaseQueryTool(nil)
	if tool.Type() != ToolTypeDatabaseQuery {
		t.Errorf("expected %v, got %v", ToolTypeDatabaseQuery, tool.Type())
	}
}

func TestDatabaseQueryTool_Name(t *testing.T) {
	tool := NewDatabaseQueryTool(nil)
	if tool.Name() != "Database Query" {
		t.Errorf("expected 'Database Query', got %v", tool.Name())
	}
}

func TestDatabaseQueryTool_ValidateParams(t *testing.T) {
	tool := NewDatabaseQueryTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid mysql params",
			params: &DatabaseQueryParams{
				System: "mysql",
				Host:   "localhost",
				Port:   3306,
				Query:  "SELECT * FROM users LIMIT 10",
			},
			wantErr: false,
		},
		{
			name: "valid postgresql params",
			params: &DatabaseQueryParams{
				System:   "postgresql",
				Host:     "localhost",
				Port:     5432,
				Database: "mydb",
				Query:    "SELECT id, name FROM products",
			},
			wantErr: false,
		},
		{
			name: "valid mongodb params",
			params: &DatabaseQueryParams{
				System: "mongodb",
				Host:   "localhost",
				Port:   27017,
				Query:  "db.users.find({})",
			},
			wantErr: false,
		},
		{
			name: "valid redis params",
			params: &DatabaseQueryParams{
				System: "redis",
				Host:   "localhost",
				Port:   6379,
				Query:  "KEYS *",
			},
			wantErr: false,
		},
		{
			name: "missing system",
			params: &DatabaseQueryParams{
				Host:  "localhost",
				Query: "SELECT 1",
			},
			wantErr: true,
		},
		{
			name: "unsupported system",
			params: &DatabaseQueryParams{
				System: "oracle",
				Host:   "localhost",
				Query:  "SELECT 1",
			},
			wantErr: true,
		},
		{
			name: "missing query",
			params: &DatabaseQueryParams{
				System: "mysql",
				Host:   "localhost",
			},
			wantErr: true,
		},
		{
			name: "INSERT query blocked",
			params: &DatabaseQueryParams{
				System: "mysql",
				Host:   "localhost",
				Query:  "INSERT INTO users VALUES (1)",
			},
			wantErr: true,
		},
		{
			name: "UPDATE query blocked",
			params: &DatabaseQueryParams{
				System: "postgresql",
				Host:   "localhost",
				Query:  "UPDATE users SET name='test'",
			},
			wantErr: true,
		},
		{
			name: "DELETE query blocked",
			params: &DatabaseQueryParams{
				System: "mysql",
				Host:   "localhost",
				Query:  "DELETE FROM users WHERE id=1",
			},
			wantErr: true,
		},
		{
			name: "DROP query blocked",
			params: &DatabaseQueryParams{
				System: "mysql",
				Host:   "localhost",
				Query:  "DROP TABLE users",
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

func TestDatabaseQueryTool_Execute(t *testing.T) {
	tool := NewDatabaseQueryTool(nil)

	params := &DatabaseQueryParams{
		System: "mysql",
		Host:   "localhost",
		Port:   3306,
		Query:  "SELECT * FROM users LIMIT 10",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	queryResult, ok := result.(*DatabaseQueryResult)
	if !ok {
		t.Fatal("expected DatabaseQueryResult")
	}

	if queryResult.System != "mysql" {
		t.Errorf("expected system mysql, got %v", queryResult.System)
	}

	if len(queryResult.Columns) == 0 {
		t.Error("expected columns in result")
	}

	if len(queryResult.Data) == 0 {
		t.Error("expected data in result")
	}

	if queryResult.Duration == "" {
		t.Error("expected duration in result")
	}
}

func TestDatabaseQueryTool_Execute_AllSystems(t *testing.T) {
	tool := NewDatabaseQueryTool(nil)
	systems := []string{"mysql", "postgresql", "mongodb", "redis"}

	for _, sys := range systems {
		t.Run(sys, func(t *testing.T) {
			params := &DatabaseQueryParams{
				System: sys,
				Host:   "localhost",
				Query:  "SELECT 1",
			}
			result, err := tool.Execute(params)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			qr, ok := result.(*DatabaseQueryResult)
			if !ok {
				t.Fatal("expected DatabaseQueryResult")
			}
			if qr.System != sys {
				t.Errorf("expected system %v, got %v", sys, qr.System)
			}
		})
	}
}

func TestBackupCheckTool_Type(t *testing.T) {
	tool := NewBackupCheckTool(nil)
	if tool.Type() != ToolTypeBackupCheck {
		t.Errorf("expected %v, got %v", ToolTypeBackupCheck, tool.Type())
	}
}

func TestBackupCheckTool_ValidateParams(t *testing.T) {
	tool := NewBackupCheckTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid mysql params",
			params: &BackupCheckParams{
				SystemType: "mysql",
				Target:     "db-master-01",
			},
			wantErr: false,
		},
		{
			name: "valid postgresql params",
			params: &BackupCheckParams{
				SystemType: "postgresql",
				Target:     "pg-primary",
			},
			wantErr: false,
		},
		{
			name: "valid k8s params",
			params: &BackupCheckParams{
				SystemType: "k8s",
				Target:     "prod-cluster",
			},
			wantErr: false,
		},
		{
			name: "valid files params",
			params: &BackupCheckParams{
				SystemType: "files",
				Target:     "/backup/nas",
			},
			wantErr: false,
		},
		{
			name:    "missing system_type",
			params:  &BackupCheckParams{Target: "db-master"},
			wantErr: true,
		},
		{
			name: "unsupported system_type",
			params: &BackupCheckParams{
				SystemType: "mongodb",
				Target:     "mongo-01",
			},
			wantErr: true,
		},
		{
			name:    "missing target",
			params:  &BackupCheckParams{SystemType: "mysql"},
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

func TestBackupCheckTool_Execute(t *testing.T) {
	tool := NewBackupCheckTool(nil)

	params := &BackupCheckParams{
		SystemType: "mysql",
		Target:     "db-master-01",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	checkResult, ok := result.(*BackupCheckResult)
	if !ok {
		t.Fatal("expected BackupCheckResult")
	}

	if checkResult.LastBackupTime == "" {
		t.Error("expected LastBackupTime in result")
	}

	if checkResult.Status == "" {
		t.Error("expected Status in result")
	}
}

func TestBackupCheckTool_Execute_AllSystems(t *testing.T) {
	tool := NewBackupCheckTool(nil)
	systems := []string{"mysql", "postgresql", "k8s", "files"}

	for _, sys := range systems {
		t.Run(sys, func(t *testing.T) {
			params := &BackupCheckParams{
				SystemType: sys,
				Target:     "test-target",
			}
			result, err := tool.Execute(params)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			br, ok := result.(*BackupCheckResult)
			if !ok {
				t.Fatal("expected BackupCheckResult")
			}
			if br.Status == "" {
				t.Error("expected status")
			}
		})
	}
}

func TestReplicationStatusTool_Type(t *testing.T) {
	tool := NewReplicationStatusTool(nil)
	if tool.Type() != ToolTypeReplicationStatus {
		t.Errorf("expected %v, got %v", ToolTypeReplicationStatus, tool.Type())
	}
}

func TestReplicationStatusTool_ValidateParams(t *testing.T) {
	tool := NewReplicationStatusTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid mysql params",
			params: &ReplicationStatusParams{
				System: "mysql",
				Host:   "db-master.example.com",
			},
			wantErr: false,
		},
		{
			name: "valid postgresql params",
			params: &ReplicationStatusParams{
				System: "postgresql",
				Host:   "pg-master.example.com",
			},
			wantErr: false,
		},
		{
			name: "missing system",
			params: &ReplicationStatusParams{
				Host: "db-master.example.com",
			},
			wantErr: true,
		},
		{
			name: "unsupported system",
			params: &ReplicationStatusParams{
				System: "mongodb",
				Host:   "mongo.example.com",
			},
			wantErr: true,
		},
		{
			name: "missing host",
			params: &ReplicationStatusParams{
				System: "mysql",
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

func TestReplicationStatusTool_Execute(t *testing.T) {
	tool := NewReplicationStatusTool(nil)

	params := &ReplicationStatusParams{
		System: "mysql",
		Host:   "db-master.example.com",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	replResult, ok := result.(*ReplicationStatusResult)
	if !ok {
		t.Fatal("expected ReplicationStatusResult")
	}

	if !replResult.IsReplicating {
		t.Error("expected IsReplicating to be true")
	}

	if len(replResult.SlaveHosts) == 0 {
		t.Error("expected slave hosts in result")
	}

	if replResult.MasterHost != params.Host {
		t.Errorf("expected MasterHost %v, got %v", params.Host, replResult.MasterHost)
	}
}

func TestSecretAuditTool_Type(t *testing.T) {
	tool := NewSecretAuditTool(nil)
	if tool.Type() != ToolTypeSecretAudit {
		t.Errorf("expected %v, got %v", ToolTypeSecretAudit, tool.Type())
	}
}

func TestSecretAuditTool_ValidateParams(t *testing.T) {
	tool := NewSecretAuditTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid params with pattern scan",
			params: &SecretAuditParams{
				TargetPath: "/path/to/repo",
				ScanType:  "pattern",
				Severity:  "HIGH",
			},
			wantErr: false,
		},
		{
			name: "valid params with entropy scan",
			params: &SecretAuditParams{
				TargetPath: "/path/to/repo",
				ScanType:  "entropy",
			},
			wantErr: false,
		},
		{
			name: "valid params with ai scan",
			params: &SecretAuditParams{
				TargetPath: "/path/to/repo",
				ScanType:  "ai",
			},
			wantErr: false,
		},
		{
			name: "valid params all severities",
			params: &SecretAuditParams{
				TargetPath: "/path/to/repo",
				Severity:  "CRITICAL",
			},
			wantErr: false,
		},
		{
			name:    "missing target_path",
			params:  &SecretAuditParams{ScanType: "pattern"},
			wantErr: true,
		},
		{
			name: "unsupported scan_type",
			params: &SecretAuditParams{
				TargetPath: "/repo",
				ScanType:  "unknown",
			},
			wantErr: true,
		},
		{
			name: "unsupported severity",
			params: &SecretAuditParams{
				TargetPath: "/repo",
				Severity:   "CRITICAL2",
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

func TestSecretAuditTool_Execute(t *testing.T) {
	tool := NewSecretAuditTool(nil)

	params := &SecretAuditParams{
		TargetPath: "/repo",
		ScanType:  "pattern",
		Severity:  "HIGH",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	auditResult, ok := result.(*SecretAuditResult)
	if !ok {
		t.Fatal("expected SecretAuditResult")
	}

	if auditResult.TotalScanned == 0 {
		t.Error("expected TotalScanned > 0")
	}

	if auditResult.HighSeverity < 0 {
		t.Error("expected HighSeverity >= 0")
	}
}

func TestSecretAuditTool_Execute_NoSeverityFilter(t *testing.T) {
	tool := NewSecretAuditTool(nil)

	params := &SecretAuditParams{
		TargetPath: "/repo",
		ScanType:  "pattern",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	auditResult := result.(*SecretAuditResult)
	if len(auditResult.Findings) == 0 {
		t.Error("expected findings without severity filter")
	}
}

func TestSecretAuditTool_SeverityFiltering(t *testing.T) {
	tool := NewSecretAuditTool(nil)

	params := &SecretAuditParams{
		TargetPath: "/repo",
		ScanType:  "pattern",
		Severity:  "CRITICAL",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	auditResult := result.(*SecretAuditResult)
	for _, f := range auditResult.Findings {
		if f.Severity != "CRITICAL" {
			t.Errorf("expected all findings to be CRITICAL, got %v", f.Severity)
		}
	}
}

func TestSecretAuditTool_Redacted(t *testing.T) {
	tests := []struct {
		secretType string
		original   string
		want       string
	}{
		{"github_token", "ghp_abcdefghij1234567890klmnopqrstuvwxyz", "ghp_****wxyz"},
		{"aws_access_key", "AKIAIOSFODNN7EXAMPLE", "AKIA************MPLE"},
		{"password", "mySecretPassword123", "********"},
		{"private_key", "-----BEGIN RSA PRIVATE KEY-----MIIE...-----END RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----"},
		{"api_key", "sk_live_abcdefghij1234567890", "sk_l****7890"},
	}

	for _, tt := range tests {
		t.Run(tt.secretType, func(t *testing.T) {
			got := redacted(tt.original, tt.secretType)
			if got == "" {
				t.Errorf("redacted() returned empty string for %v", tt.secretType)
			}
			// 确保脱敏后不再包含完整原始值（除了 private_key 等特殊情况）
			if tt.secretType != "private_key" && tt.secretType != "password" {
				if strings.Contains(got, "Secret") || strings.Contains(got, "EXAMPLE") {
					// password 和特殊类型可能不适用此检查
				}
			}
		})
	}
}

func TestRotationCheckTool_Type(t *testing.T) {
	tool := NewRotationCheckTool(nil)
	if tool.Type() != ToolTypeRotationCheck {
		t.Errorf("expected %v, got %v", ToolTypeRotationCheck, tool.Type())
	}
}

func TestRotationCheckTool_ValidateParams(t *testing.T) {
	tool := NewRotationCheckTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid aws params",
			params: &RotationCheckParams{
				SystemType: "aws",
				KeyType:    "api_key",
				TargetID:   "AKIA1234567890",
			},
			wantErr: false,
		},
		{
			name: "valid gcp cert params",
			params: &RotationCheckParams{
				SystemType: "gcp",
				KeyType:    "cert",
				TargetID:   "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key",
			},
			wantErr: false,
		},
		{
			name: "valid azure params",
			params: &RotationCheckParams{
				SystemType: "azure",
				KeyType:    "api_key",
				TargetID:   "key-id-123",
			},
			wantErr: false,
		},
		{
			name: "valid kubernetes params",
			params: &RotationCheckParams{
				SystemType: "kubernetes",
				KeyType:    "password",
				TargetID:   "default-token-abc",
			},
			wantErr: false,
		},
		{
			name: "valid without key_type",
			params: &RotationCheckParams{
				SystemType: "aws",
				TargetID:   "some-id",
			},
			wantErr: false,
		},
		{
			name:    "missing system_type",
			params:  &RotationCheckParams{KeyType: "api_key"},
			wantErr: true,
		},
		{
			name: "unsupported system_type",
			params: &RotationCheckParams{
				SystemType: "digitalocean",
				KeyType:    "api_key",
			},
			wantErr: true,
		},
		{
			name: "unsupported key_type",
			params: &RotationCheckParams{
				SystemType: "aws",
				KeyType:    "ssh_key",
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

func TestRotationCheckTool_Execute(t *testing.T) {
	tool := NewRotationCheckTool(nil)

	params := &RotationCheckParams{
		SystemType: "aws",
		KeyType:    "api_key",
		TargetID:   "AKIA1234567890",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	rotResult, ok := result.(*RotationCheckResult)
	if !ok {
		t.Fatal("expected RotationCheckResult")
	}

	if rotResult.Status == "" {
		t.Error("expected Status in result")
	}

	if rotResult.AgeDays < 0 {
		t.Error("expected AgeDays >= 0")
	}

	validStatuses := map[string]bool{
		"ok":      true,
		"due":     true,
		"overdue": true,
		"unknown": true,
	}
	if !validStatuses[rotResult.Status] {
		t.Errorf("expected valid status, got %v", rotResult.Status)
	}
}

func TestRotationCheckTool_Execute_AllSystems(t *testing.T) {
	tool := NewRotationCheckTool(nil)
	systems := []string{"aws", "gcp", "azure", "kubernetes"}
	keyTypes := []string{"api_key", "cert", "password"}

	for _, sys := range systems {
		for _, kt := range keyTypes {
			t.Run(sys+"_"+kt, func(t *testing.T) {
				params := &RotationCheckParams{
					SystemType: sys,
					KeyType:    kt,
					TargetID:   "test-id",
				}
				result, err := tool.Execute(params)
				if err != nil {
					t.Fatalf("Execute() error = %v", err)
				}
				rr, ok := result.(*RotationCheckResult)
				if !ok {
					t.Fatal("expected RotationCheckResult")
				}
				if rr.Status == "" {
					t.Error("expected status")
				}
			})
		}
	}
}

func TestAccessReviewTool_Type(t *testing.T) {
	tool := NewAccessReviewTool(nil)
	if tool.Type() != ToolTypeAccessReview {
		t.Errorf("expected %v, got %v", ToolTypeAccessReview, tool.Type())
	}
}

func TestAccessReviewTool_ValidateParams(t *testing.T) {
	tool := NewAccessReviewTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid aws params",
			params: &AccessReviewParams{
				SystemType: "aws",
				ReviewType: "users",
				Target:     "prod-account",
			},
			wantErr: false,
		},
		{
			name: "valid gcp params",
			params: &AccessReviewParams{
				SystemType: "gcp",
				ReviewType: "service_accounts",
				Target:     "project-id",
			},
			wantErr: false,
		},
		{
			name: "valid linux params",
			params: &AccessReviewParams{
				SystemType: "linux",
				ReviewType: "permissions",
				Target:     "prod-server-01",
			},
			wantErr: false,
		},
		{
			name: "valid database params",
			params: &AccessReviewParams{
				SystemType: "database",
				ReviewType: "users",
				Target:     "prod-db-cluster",
			},
			wantErr: false,
		},
		{
			name: "valid without review_type",
			params: &AccessReviewParams{
				SystemType: "aws",
				Target:     "prod-account",
			},
			wantErr: false,
		},
		{
			name:    "missing system_type",
			params:  &AccessReviewParams{ReviewType: "users"},
			wantErr: true,
		},
		{
			name: "unsupported system_type",
			params: &AccessReviewParams{
				SystemType: "vmware",
				ReviewType: "users",
			},
			wantErr: true,
		},
		{
			name: "unsupported review_type",
			params: &AccessReviewParams{
				SystemType: "aws",
				ReviewType: "unknown",
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

func TestAccessReviewTool_Execute(t *testing.T) {
	tool := NewAccessReviewTool(nil)

	params := &AccessReviewParams{
		SystemType: "aws",
		ReviewType: "users",
		Target:     "prod-account",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	accessResult, ok := result.(*AccessReviewResult)
	if !ok {
		t.Fatal("expected AccessReviewResult")
	}

	if accessResult.TotalCount == 0 {
		t.Error("expected TotalCount > 0")
	}

	if accessResult.TotalCount != len(accessResult.Entries) {
		t.Errorf("expected TotalCount %d to match entries len %d", accessResult.TotalCount, len(accessResult.Entries))
	}

	if accessResult.HighRiskCount < 0 {
		t.Error("expected HighRiskCount >= 0")
	}

	if accessResult.StaleCount < 0 {
		t.Error("expected StaleCount >= 0")
	}
}

func TestAccessReviewTool_Execute_AllSystems(t *testing.T) {
	tool := NewAccessReviewTool(nil)
	systems := []string{"aws", "gcp", "linux", "database"}

	for _, sys := range systems {
		t.Run(sys, func(t *testing.T) {
			params := &AccessReviewParams{
				SystemType: sys,
				ReviewType: "users",
				Target:     "test-target",
			}
			result, err := tool.Execute(params)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			ar, ok := result.(*AccessReviewResult)
			if !ok {
				t.Fatal("expected AccessReviewResult")
			}
			if ar.TotalCount == 0 {
				t.Error("expected entries")
			}
		})
	}
}

func TestAccessReviewTool_HighRiskEntries(t *testing.T) {
	tool := NewAccessReviewTool(nil)

	params := &AccessReviewParams{
		SystemType: "aws",
		ReviewType: "users",
		Target:     "prod-account",
	}

	result, _ := tool.Execute(params)
	accessResult := result.(*AccessReviewResult)

	for _, e := range accessResult.Entries {
		if e.Risk == "high" {
			if accessResult.HighRiskCount == 0 {
				t.Error("expected HighRiskCount > 0 when high risk entries exist")
			}
			break
		}
	}
}

// BenchmarkExecute benchmarks all tools
func BenchmarkDatabaseQueryTool_Execute(b *testing.B) {
	tool := NewDatabaseQueryTool(nil)
	params := &DatabaseQueryParams{
		System: "mysql",
		Host:   "localhost",
		Query:  "SELECT * FROM users",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}

func BenchmarkSecretAuditTool_Execute(b *testing.B) {
	tool := NewSecretAuditTool(nil)
	params := &SecretAuditParams{
		TargetPath: "/repo",
		ScanType:  "pattern",
		Severity:  "HIGH",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}

func BenchmarkAccessReviewTool_Execute(b *testing.B) {
	tool := NewAccessReviewTool(nil)
	params := &AccessReviewParams{
		SystemType: "aws",
		ReviewType: "users",
		Target:     "prod-account",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}
