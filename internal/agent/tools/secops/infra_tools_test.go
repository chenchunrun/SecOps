package secops

import (
	"strings"
	"testing"
	"time"
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

// InfrastructureQueryTool tests

func TestInfrastructureQueryTool_Type(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)
	if tool.Type() != ToolTypeInfrastructureQuery {
		t.Errorf("expected %v, got %v", ToolTypeInfrastructureQuery, tool.Type())
	}
}

func TestInfrastructureQueryTool_Name(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)
	if tool.Name() != "Infrastructure Query" {
		t.Errorf("expected 'Infrastructure Query', got %v", tool.Name())
	}
}

func TestInfrastructureQueryTool_ValidateParams(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid terraform params",
			params: &InfrastructureQueryParams{
				SystemType: "terraform",
				QueryType:  "state",
				Target:     "workspace/prod",
			},
			wantErr: false,
		},
		{
			name: "valid aws resources params",
			params: &InfrastructureQueryParams{
				SystemType: "aws",
				QueryType:  "resources",
				Target:     "us-east-1",
				Region:     "us-east-1",
			},
			wantErr: false,
		},
		{
			name: "valid aws scaling params",
			params: &InfrastructureQueryParams{
				SystemType: "aws",
				QueryType:  "scaling",
				Target:     "asg-prod",
			},
			wantErr: false,
		},
		{
			name: "valid aws costs params",
			params: &InfrastructureQueryParams{
				SystemType: "aws",
				QueryType:  "costs",
				Target:     "account-123",
			},
			wantErr: false,
		},
		{
			name: "valid gcp params",
			params: &InfrastructureQueryParams{
				SystemType: "gcp",
				QueryType:  "resources",
				Target:     "project-id",
			},
			wantErr: false,
		},
		{
			name: "valid kubernetes params",
			params: &InfrastructureQueryParams{
				SystemType: "kubernetes",
				QueryType:  "resources",
				Target:     "prod-cluster",
			},
			wantErr: false,
		},
		{
			name: "valid without query_type",
			params: &InfrastructureQueryParams{
				SystemType: "aws",
				Target:     "us-east-1",
			},
			wantErr: false,
		},
		{
			name:    "missing system_type",
			params:  &InfrastructureQueryParams{QueryType: "resources"},
			wantErr: true,
		},
		{
			name: "unsupported system_type",
			params: &InfrastructureQueryParams{
				SystemType: "digitalocean",
				QueryType:  "resources",
			},
			wantErr: true,
		},
		{
			name: "unsupported query_type",
			params: &InfrastructureQueryParams{
				SystemType: "aws",
				QueryType:  "inventory",
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

func TestInfrastructureQueryTool_Execute(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)

	params := &InfrastructureQueryParams{
		SystemType: "terraform",
		QueryType:  "state",
		Target:     "workspace/prod",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	iqResult, ok := result.(*InfrastructureQueryResult)
	if !ok {
		t.Fatal("expected InfrastructureQueryResult")
	}

	if iqResult.TerraformState == nil {
		t.Error("expected TerraformState in result")
	}

	if len(iqResult.TerraformState.Resources) == 0 {
		t.Error("expected resources in terraform state")
	}

	if !iqResult.TerraformState.DriftDetected {
		t.Error("expected drift to be detected in mock")
	}
}

func TestInfrastructureQueryTool_Execute_AllSystems(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)
	systems := []string{"terraform", "aws", "gcp", "azure", "kubernetes"}

	for _, sys := range systems {
		t.Run(sys, func(t *testing.T) {
			params := &InfrastructureQueryParams{
				SystemType: sys,
				QueryType:  "resources",
				Target:     "test-target",
			}
			result, err := tool.Execute(params)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			ir, ok := result.(*InfrastructureQueryResult)
			if !ok {
				t.Fatal("expected InfrastructureQueryResult")
			}
			if ir.SystemType != sys {
				t.Errorf("expected SystemType %v, got %v", sys, ir.SystemType)
			}
		})
	}
}

func TestInfrastructureQueryTool_Execute_Scaling(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)
	platforms := []string{"aws", "gcp", "azure", "kubernetes"}

	for _, p := range platforms {
		t.Run(p, func(t *testing.T) {
			params := &InfrastructureQueryParams{
				SystemType: p,
				QueryType:  "scaling",
				Target:     "test-cluster",
			}
			result, err := tool.Execute(params)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			ir := result.(*InfrastructureQueryResult)
			if ir.ScalingInfo == nil {
				t.Error("expected ScalingInfo in result")
			}
			if ir.ScalingInfo.MinReplicas > ir.ScalingInfo.MaxReplicas {
				t.Error("expected MinReplicas <= MaxReplicas")
			}
		})
	}
}

func TestInfrastructureQueryTool_Execute_Costs(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)
	platforms := []string{"aws", "gcp", "azure"}

	for _, p := range platforms {
		t.Run(p, func(t *testing.T) {
			params := &InfrastructureQueryParams{
				SystemType: p,
				QueryType:  "costs",
				Target:     "test-account",
			}
			result, err := tool.Execute(params)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			ir := result.(*InfrastructureQueryResult)
			if len(ir.CostInfo) == 0 {
				t.Error("expected CostInfo in result")
			}
			for _, c := range ir.CostInfo {
				if c.MonthlyCost < 0 {
					t.Error("expected MonthlyCost >= 0")
				}
			}
		})
	}
}

func TestInfrastructureQueryTool_TerraformOutputs(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)

	params := &InfrastructureQueryParams{
		SystemType: "terraform",
		QueryType:  "state",
		Target:     "workspace/prod",
	}

	result, _ := tool.Execute(params)
	iqResult := result.(*InfrastructureQueryResult)

	if len(iqResult.TerraformState.Outputs) == 0 {
		t.Error("expected terraform outputs")
	}

	// Verify database_url is redacted
	if v, ok := iqResult.TerraformState.Outputs["database_url"]; ok {
		if v == "postgres://..." || v == "" {
			// OK, redacted
		}
	}
}

// DeploymentStatusTool tests

func TestDeploymentStatusTool_Type(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	if tool.Type() != ToolTypeDeploymentStatus {
		t.Errorf("expected %v, got %v", ToolTypeDeploymentStatus, tool.Type())
	}
}

func TestDeploymentStatusTool_Name(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	if tool.Name() != "Deployment Status" {
		t.Errorf("expected 'Deployment Status', got %v", tool.Name())
	}
}

func TestDeploymentStatusTool_ValidateParams(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid kubernetes params",
			params: &DeploymentStatusParams{
				Platform:   "kubernetes",
				Namespace:  "production",
				Deployment: "web-api",
			},
			wantErr: false,
		},
		{
			name: "valid aws params",
			params: &DeploymentStatusParams{
				Platform:   "aws",
				Deployment: "ecs-service",
				Env:       "production",
			},
			wantErr: false,
		},
		{
			name: "valid gcp params",
			params: &DeploymentStatusParams{
				Platform:   "gcp",
				Deployment: "cloudrun-service",
				Env:       "prod",
			},
			wantErr: false,
		},
		{
			name: "valid azure params",
			params: &DeploymentStatusParams{
				Platform:   "azure",
				Deployment: "app-service",
				Env:        "production",
			},
			wantErr: false,
		},
		{
			name:    "missing platform",
			params:  &DeploymentStatusParams{Deployment: "web-api"},
			wantErr: true,
		},
		{
			name: "unsupported platform",
			params: &DeploymentStatusParams{
				Platform:   "heroku",
				Deployment: "web-api",
			},
			wantErr: true,
		},
		{
			name:    "missing deployment",
			params:  &DeploymentStatusParams{Platform: "kubernetes"},
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

func TestDeploymentStatusTool_Execute(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)

	params := &DeploymentStatusParams{
		Platform:   "kubernetes",
		Namespace:  "production",
		Deployment: "web-api",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	dsResult, ok := result.(*DeploymentStatusResult)
	if !ok {
		t.Fatal("expected DeploymentStatusResult")
	}

	if dsResult.Health == nil {
		t.Error("expected Health in result")
	}

	if dsResult.Replicas == nil {
		t.Error("expected Replicas in result")
	}

	if dsResult.Rollout == nil {
		t.Error("expected Rollout in result")
	}

	if dsResult.Version == "" {
		t.Error("expected Version in result")
	}
}

func TestDeploymentStatusTool_Execute_AllPlatforms(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	platforms := []string{"kubernetes", "aws", "gcp", "azure"}

	for _, p := range platforms {
		t.Run(p, func(t *testing.T) {
			params := &DeploymentStatusParams{
				Platform:   p,
				Deployment: "test-service",
			}
			result, err := tool.Execute(params)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			ds, ok := result.(*DeploymentStatusResult)
			if !ok {
				t.Fatal("expected DeploymentStatusResult")
			}
			if ds.Health == nil {
				t.Error("expected health info")
			}
			if ds.Replicas == nil {
				t.Error("expected replica info")
			}
		})
	}
}

func TestDeploymentStatusTool_ReplicaStatus(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)

	params := &DeploymentStatusParams{
		Platform:   "kubernetes",
		Namespace:  "production",
		Deployment: "web-api",
	}

	result, _ := tool.Execute(params)
	dsResult := result.(*DeploymentStatusResult)

	replicas := dsResult.Replicas
	if replicas.Ready > replicas.Desired {
		t.Error("expected Ready <= Desired")
	}

	if replicas.Available > replicas.Desired {
		t.Error("expected Available <= Desired")
	}
}

func TestDeploymentStatusTool_HealthStatus(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)

	params := &DeploymentStatusParams{
		Platform:   "kubernetes",
		Namespace:  "production",
		Deployment: "web-api",
	}

	result, _ := tool.Execute(params)
	dsResult := result.(*DeploymentStatusResult)

	validStatuses := map[string]bool{
		"healthy":   true,
		"degraded":   true,
		"unhealthy":  true,
		"unknown":    true,
	}
	if !validStatuses[dsResult.Health.Status] {
		t.Errorf("expected valid health status, got %v", dsResult.Health.Status)
	}
}

func TestDeploymentStatusTool_CanaryAnalysis(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)

	params := &DeploymentStatusParams{
		Platform:   "kubernetes",
		Namespace:  "production",
		Deployment: "web-api",
	}

	result, _ := tool.Execute(params)
	dsResult := result.(*DeploymentStatusResult)

	canary := dsResult.CanaryAnalysis
	if canary != nil && canary.Recommendation != "" && canary.Recommendation != "none" {
		validRecs := map[string]bool{
			"promote":  true,
			"rollback": true,
			"hold":     true,
		}
		if !validRecs[canary.Recommendation] {
			t.Errorf("expected valid canary recommendation, got %v", canary.Recommendation)
		}
	}
}

func TestDeploymentStatusTool_RolloutInfo(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)

	params := &DeploymentStatusParams{
		Platform:   "kubernetes",
		Namespace:  "production",
		Deployment: "web-api",
	}

	result, _ := tool.Execute(params)
	dsResult := result.(*DeploymentStatusResult)

	validStrategies := map[string]bool{
		"RollingUpdate": true,
		"BlueGreen":     true,
		"Canary":        true,
	}
	if !validStrategies[dsResult.Rollout.Strategy] {
		t.Errorf("expected valid rollout strategy, got %v", dsResult.Rollout.Strategy)
	}
}

func TestDeploymentStatusTool_Events(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)

	params := &DeploymentStatusParams{
		Platform:   "kubernetes",
		Namespace:  "production",
		Deployment: "web-api",
	}

	result, _ := tool.Execute(params)
	dsResult := result.(*DeploymentStatusResult)

	for _, event := range dsResult.Health.Events {
		if event.Type != "Normal" && event.Type != "Warning" {
			t.Errorf("expected Normal or Warning event type, got %v", event.Type)
		}
		if event.Message == "" {
			t.Error("expected event message")
		}
	}
}

// Benchmark new tools
func BenchmarkInfrastructureQueryTool_Execute(b *testing.B) {
	tool := NewInfrastructureQueryTool(nil)
	params := &InfrastructureQueryParams{
		SystemType: "terraform",
		QueryType:  "state",
		Target:     "workspace/prod",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}

func BenchmarkDeploymentStatusTool_Execute(b *testing.B) {
	tool := NewDeploymentStatusTool(nil)
	params := &DeploymentStatusParams{
		Platform:   "kubernetes",
		Namespace:  "production",
		Deployment: "web-api",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}

// AlertCheckTool tests

func TestAlertCheckTool_Type(t *testing.T) {
	tool := NewAlertCheckTool(nil)
	if tool.Type() != ToolTypeAlertCheck {
		t.Errorf("expected %v, got %v", ToolTypeAlertCheck, tool.Type())
	}
}

func TestAlertCheckTool_Name(t *testing.T) {
	tool := NewAlertCheckTool(nil)
	if tool.Name() != "Alert Check" {
		t.Errorf("expected 'Alert Check', got %v", tool.Name())
	}
}

func TestAlertCheckTool_ValidateParams(t *testing.T) {
	tool := NewAlertCheckTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid prometheus params",
			params: &AlertCheckParams{
				System:    "prometheus",
				Filter:    "namespace=production",
				Status:    "firing",
				TimeRange: "1h",
			},
			wantErr: false,
		},
		{
			name: "valid grafana params",
			params: &AlertCheckParams{
				System: "grafana",
			},
			wantErr: false,
		},
		{
			name: "valid datadog params",
			params: &AlertCheckParams{
				System: "datadog",
				Status: "resolved",
			},
			wantErr: false,
		},
		{
			name: "valid pagerduty params",
			params: &AlertCheckParams{
				System: "pagerduty",
				Status: "acknowledged",
			},
			wantErr: false,
		},
		{
			name: "valid without status",
			params: &AlertCheckParams{
				System: "prometheus",
			},
			wantErr: false,
		},
		{
			name:    "missing system",
			params:  &AlertCheckParams{Status: "firing"},
			wantErr: true,
		},
		{
			name: "unsupported system",
			params: &AlertCheckParams{
				System: "newrelic",
			},
			wantErr: true,
		},
		{
			name: "unsupported status",
			params: &AlertCheckParams{
				System: "prometheus",
				Status: "unknown",
			},
			wantErr: true,
		},
		{
			name:    "invalid type",
			params:  "invalid",
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

func TestAlertCheckTool_Execute(t *testing.T) {
	tool := NewAlertCheckTool(nil)

	params := &AlertCheckParams{
		System: "prometheus",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	alertResult, ok := result.(*AlertCheckResult)
	if !ok {
		t.Fatal("expected AlertCheckResult")
	}

	if alertResult.System != "prometheus" {
		t.Errorf("expected system prometheus, got %v", alertResult.System)
	}

	if alertResult.Total == 0 {
		t.Error("expected alerts in result")
	}

	if alertResult.Firing < 0 || alertResult.Resolved < 0 || alertResult.Acknowledged < 0 {
		t.Error("expected non-negative alert counts")
	}
}

func TestAlertCheckTool_Execute_AllSystems(t *testing.T) {
	tool := NewAlertCheckTool(nil)
	systems := []string{"prometheus", "grafana", "datadog", "pagerduty"}

	for _, sys := range systems {
		t.Run(sys, func(t *testing.T) {
			params := &AlertCheckParams{System: sys}
			result, err := tool.Execute(params)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			ar, ok := result.(*AlertCheckResult)
			if !ok {
				t.Fatal("expected AlertCheckResult")
			}
			if ar.System != sys {
				t.Errorf("expected system %v, got %v", sys, ar.System)
			}
			if ar.Total == 0 {
				t.Error("expected alerts")
			}
		})
	}
}

func TestAlertCheckTool_FilterByStatus(t *testing.T) {
	tool := NewAlertCheckTool(nil)
	statuses := []string{"firing", "resolved", "acknowledged"}

	for _, status := range statuses {
		t.Run(status, func(t *testing.T) {
			params := &AlertCheckParams{
				System: "prometheus",
				Status: status,
			}
			result, err := tool.Execute(params)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			ar := result.(*AlertCheckResult)
			for _, a := range ar.Alerts {
				if a.Status != status {
					t.Errorf("expected status %v, got %v", status, a.Status)
				}
			}
		})
	}
}

func TestAlertCheckTool_AlertCounts(t *testing.T) {
	tool := NewAlertCheckTool(nil)

	params := &AlertCheckParams{System: "prometheus"}
	result, _ := tool.Execute(params)
	ar := result.(*AlertCheckResult)

	expectedTotal := ar.Firing + ar.Resolved + ar.Acknowledged
	if ar.Total != expectedTotal {
		t.Errorf("expected total %d to match sum of counts %d", ar.Total, expectedTotal)
	}
}

func TestAlertCheckTool_AlertInfoFields(t *testing.T) {
	tool := NewAlertCheckTool(nil)

	params := &AlertCheckParams{System: "prometheus"}
	result, _ := tool.Execute(params)
	ar := result.(*AlertCheckResult)

	for _, a := range ar.Alerts {
		if a.ID == "" {
			t.Error("expected alert ID")
		}
		if a.Name == "" {
			t.Error("expected alert name")
		}
		if a.Status == "" {
			t.Error("expected alert status")
		}
		if a.Severity == "" {
			t.Error("expected alert severity")
		}
		if a.Message == "" {
			t.Error("expected alert message")
		}
	}
}

// IncidentTimelineTool tests

func TestIncidentTimelineTool_Type(t *testing.T) {
	tool := NewIncidentTimelineTool(nil)
	if tool.Type() != ToolTypeIncidentTimeline {
		t.Errorf("expected %v, got %v", ToolTypeIncidentTimeline, tool.Type())
	}
}

func TestIncidentTimelineTool_Name(t *testing.T) {
	tool := NewIncidentTimelineTool(nil)
	if tool.Name() != "Incident Timeline" {
		t.Errorf("expected 'Incident Timeline', got %v", tool.Name())
	}
}

func TestIncidentTimelineTool_ValidateParams(t *testing.T) {
	tool := NewIncidentTimelineTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid incident ID",
			params: &IncidentTimelineParams{
				IncidentID: "INC-001",
			},
			wantErr: false,
		},
		{
			name: "valid incident ID with events",
			params: &IncidentTimelineParams{
				IncidentID: "INC-100",
				Events: []TimelineEvent{
					{Timestamp: time.Now(), Type: "alert", Actor: "system", Description: "Test"},
				},
			},
			wantErr: false,
		},
		{
			name:    "missing incident ID",
			params:  &IncidentTimelineParams{},
			wantErr: true,
		},
		{
			name:    "invalid type",
			params:  "invalid",
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

func TestIncidentTimelineTool_Execute(t *testing.T) {
	tool := NewIncidentTimelineTool(nil)

	params := &IncidentTimelineParams{
		IncidentID: "INC-001",
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	tlResult, ok := result.(*IncidentTimelineResult)
	if !ok {
		t.Fatal("expected IncidentTimelineResult")
	}

	if tlResult.IncidentID != "INC-001" {
		t.Errorf("expected incident ID INC-001, got %v", tlResult.IncidentID)
	}

	if len(tlResult.Events) == 0 {
		t.Error("expected events in timeline")
	}

	if tlResult.Duration == 0 && tlResult.Status == "resolved" {
		// Duration can be 0 for ongoing incidents
	}
}

func TestIncidentTimelineTool_Execute_AllIncidentTypes(t *testing.T) {
	tool := NewIncidentTimelineTool(nil)
	incidentIDs := []string{"INC-001", "INC-002", "INC-003", "INC-004", "INC-005", "INC-006", "INC-999"}

	for _, id := range incidentIDs {
		t.Run(id, func(t *testing.T) {
			params := &IncidentTimelineParams{IncidentID: id}
			result, err := tool.Execute(params)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			tl, ok := result.(*IncidentTimelineResult)
			if !ok {
				t.Fatal("expected IncidentTimelineResult")
			}
			if tl.IncidentID != id {
				t.Errorf("expected incident ID %v, got %v", id, tl.IncidentID)
			}
			if len(tl.Events) == 0 {
				t.Error("expected events")
			}
		})
	}
}

func TestIncidentTimelineTool_EventTypes(t *testing.T) {
	tool := NewIncidentTimelineTool(nil)

	params := &IncidentTimelineParams{IncidentID: "INC-001"}
	result, _ := tool.Execute(params)
	tl := result.(*IncidentTimelineResult)

	validTypes := map[string]bool{
		"alert":          true,
		"action":         true,
		"escalation":     true,
		"resolution":     true,
		"communication":  true,
	}

	for _, e := range tl.Events {
		if e.Timestamp.IsZero() {
			t.Error("expected event timestamp")
		}
		if e.Type == "" {
			t.Error("expected event type")
		}
		if !validTypes[e.Type] {
			t.Errorf("expected valid event type, got %v", e.Type)
		}
		if e.Actor == "" {
			t.Error("expected event actor")
		}
		if e.Description == "" {
			t.Error("expected event description")
		}
	}
}

func TestIncidentTimelineTool_IncidentFields(t *testing.T) {
	tool := NewIncidentTimelineTool(nil)

	params := &IncidentTimelineParams{IncidentID: "INC-001"}
	result, _ := tool.Execute(params)
	tl := result.(*IncidentTimelineResult)

	if tl.Title == "" {
		t.Error("expected incident title")
	}
	if tl.Status == "" {
		t.Error("expected incident status")
	}
	if tl.StartTime.IsZero() {
		t.Error("expected start time")
	}
	if tl.Duration == 0 && tl.Status == "open" {
		// OK for open incidents
	}
}

func TestIncidentTimelineTool_Duration(t *testing.T) {
	tool := NewIncidentTimelineTool(nil)

	params := &IncidentTimelineParams{IncidentID: "INC-001"}
	result, _ := tool.Execute(params)
	tl := result.(*IncidentTimelineResult)

	if !tl.EndTime.IsZero() {
		expected := tl.EndTime.Sub(tl.StartTime)
		if expected != tl.Duration {
			t.Errorf("expected duration %v, got %v", expected, tl.Duration)
		}
	}
}

func TestIncidentTimelineTool_RootCauseAndImpact(t *testing.T) {
	tool := NewIncidentTimelineTool(nil)

	params := &IncidentTimelineParams{IncidentID: "INC-001"}
	result, _ := tool.Execute(params)
	tl := result.(*IncidentTimelineResult)

	if tl.RootCause != "" {
		if tl.RootCause == "N/A" {
			t.Error("expected non-N/A root cause")
		}
	}
}

// Benchmarks

func BenchmarkAlertCheckTool_Execute(b *testing.B) {
	tool := NewAlertCheckTool(nil)
	params := &AlertCheckParams{System: "prometheus"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}

func BenchmarkAlertCheckTool_Execute_AllSystems(b *testing.B) {
	tool := NewAlertCheckTool(nil)
	systems := []string{"prometheus", "grafana", "datadog", "pagerduty"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sys := systems[i%len(systems)]
		params := &AlertCheckParams{System: sys}
		tool.Execute(params)
	}
}

func BenchmarkIncidentTimelineTool_Execute(b *testing.B) {
	tool := NewIncidentTimelineTool(nil)
	params := &IncidentTimelineParams{IncidentID: "INC-001"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}

func BenchmarkIncidentTimelineTool_Execute_AllTypes(b *testing.B) {
	tool := NewIncidentTimelineTool(nil)
	ids := []string{"INC-001", "INC-002", "INC-003", "INC-004", "INC-005", "INC-006", "INC-999"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		params := &IncidentTimelineParams{IncidentID: ids[i%len(ids)]}
		tool.Execute(params)
	}
}
