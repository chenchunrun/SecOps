package security

import (
	"testing"
)

func TestRiskAssessor_AssessCommand(t *testing.T) {
	ra := NewRiskAssessor()

	tests := []struct {
		name          string
		command       string
		expectedLevel RiskLevel
		minScore      int
		hasFactors    bool // 是否应该有风险因子
	}{
		{
			name:          "安全命令",
			command:       "ls /tmp",
			expectedLevel: RiskLevelLow,
			minScore:      0,
			hasFactors:    false,
		},
		{
			name:          "敏感路径读取",
			command:       "cat /etc/shadow",
			expectedLevel: RiskLevelLow,  // 单个敏感路径访问（25）< 40
			minScore:      25,
			hasFactors:    true,
		},
		{
			name:          "禁用命令",
			command:       "rm -rf /",
			expectedLevel: RiskLevelMedium,  // 禁用命令（40）+ 敏感路径（可能检测到）
			minScore:      40,
			hasFactors:    true,
		},
		{
			name:          "凭证泄露",
			command:       "mysql -pSecretPassword123",
			expectedLevel: RiskLevelMedium,  // 凭证泄露（50）>= 40 且 < 60
			minScore:      50,
			hasFactors:    true,
		},
		{
			name:          "系统修改",
			command:       "chmod 777 /etc/passwd",
			expectedLevel: RiskLevelMedium,  // 系统修改（30）+ 敏感路径（25）>= 40
			minScore:      55,  // 应该同时检测到系统修改和敏感路径
			hasFactors:    true,
		},
		{
			name:          "网络访问",
			command:       "curl http://example.com/api",
			expectedLevel: RiskLevelLow,
			minScore:      15,
			hasFactors:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ra.AssessCommand(tt.command)

			if result.Level != tt.expectedLevel {
				t.Errorf("expected level %s, got %s", tt.expectedLevel, result.Level)
			}

			if result.Score < tt.minScore {
				t.Errorf("expected score >= %d, got %d", tt.minScore, result.Score)
			}

			if tt.hasFactors && len(result.Factors) == 0 {
				t.Errorf("expected at least one risk factor, got none")
			}

			if !tt.hasFactors && len(result.Factors) > 0 {
				t.Errorf("expected no risk factors, got %d", len(result.Factors))
			}
		})
	}
}

func TestRiskAssessor_RiskCategories(t *testing.T) {
	tests := []struct {
		name          string
		config        *RiskAssessorConfig
		score         int
		expectedLevel RiskLevel
		expectedAction RiskAction
	}{
		{
			name:           "Critical score",
			config:         DefaultRiskAssessorConfig(),
			score:          85,
			expectedLevel:  RiskLevelCritical,
			expectedAction: RiskActionBlock,
		},
		{
			name:           "High score",
			config:         DefaultRiskAssessorConfig(),
			score:          70,
			expectedLevel:  RiskLevelHigh,
			expectedAction: RiskActionAdminReview,
		},
		{
			name:           "Medium score",
			config:         DefaultRiskAssessorConfig(),
			score:          50,
			expectedLevel:  RiskLevelMedium,
			expectedAction: RiskActionUserConfirm,
		},
		{
			name:           "Low score",
			config:         DefaultRiskAssessorConfig(),
			score:          10,
			expectedLevel:  RiskLevelLow,
			expectedAction: RiskActionAutoApprove,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assessment := &RiskAssessment{
				Score: tt.score,
			}

			ra := NewRiskAssessorWithConfig(tt.config)
			ra.categorizeRisk(assessment)

			if assessment.Level != tt.expectedLevel {
				t.Errorf("expected level %s, got %s", tt.expectedLevel, assessment.Level)
			}

			if assessment.Action != tt.expectedAction {
				t.Errorf("expected action %s, got %s", tt.expectedAction, assessment.Action)
			}
		})
	}
}

func TestRiskAssessor_DetectBannedCommand(t *testing.T) {
	ra := NewRiskAssessor()

	tests := []struct {
		name    string
		command string
		expected bool
	}{
		{"rm command", "rm file.txt", true},
		{"dd command", "dd if=/dev/zero of=/dev/sda", true},
		{"mkfs command", "mkfs.ext4 /dev/sda1", true},
		{"ls command", "ls /tmp", false},
		{"cat command", "cat /var/log/messages", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ra.detectBannedCommand(tt.command)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRiskAssessor_DetectCredentialExposure(t *testing.T) {
	ra := NewRiskAssessor()

	tests := []struct {
		name    string
		command string
		expected bool
	}{
		{"password in mysql", "mysql -pMyPassword", true},
		{"password pattern", "password = secret", true},
		{"api_key pattern", "api_key = abc123", true},
		{"token pattern", "token = xyz789", true},
		{"safe command", "ls /tmp", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ra.detectCredentialExposure(tt.command)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRiskAssessor_DetectSensitivePathAccess(t *testing.T) {
	ra := NewRiskAssessor()

	tests := []struct {
		name    string
		command string
		expected bool
	}{
		{"shadow file", "cat /etc/shadow", true},
		{"passwd file", "cat /etc/passwd", true},
		{"aws credentials", "cat ~/.aws/credentials", true},
		{"kube config", "cat ~/.kube/config", true},
		{"normal log", "cat /var/log/syslog", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ra.detectSensitivePathAccess(tt.command)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRiskAssessor_DetectSystemModification(t *testing.T) {
	ra := NewRiskAssessor()

	tests := []struct {
		name    string
		command string
		expected bool
	}{
		{"chmod command", "chmod 777 /etc/passwd", true},
		{"chown command", "chown root:root file.txt", true},
		{"useradd command", "useradd newuser", true},
		{"systemctl restart", "systemctl restart nginx", true},
		{"apt install", "apt install curl", true},
		{"ls command", "ls /tmp", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ra.detectSystemModification(tt.command)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCapabilityManager_CheckCapability(t *testing.T) {
	cm := NewCapabilityManager()

	// 设置角色继承关系：admin <- operator <- viewer
	cm.SetRoleHierarchy("operator", "viewer")
	cm.SetRoleHierarchy("admin", "operator")

	// 设置角色策略
	viewerPolicy := &CapabilityPolicy{
		Role: "viewer",
		Mode: "allowlist",
		Capabilities: []*Capability{
			{Name: "file:read"},
			{Name: "log:read"},
		},
	}

	operatorPolicy := &CapabilityPolicy{
		Role: "operator",
		Mode: "allowlist",
		Capabilities: []*Capability{
			{Name: "file:write"},
			{Name: "process:query"},
		},
	}

	cm.SetRolePolicy(viewerPolicy)
	cm.SetRolePolicy(operatorPolicy)

	tests := []struct {
		name       string
		role       string
		capability string
		expected   bool
	}{
		{"viewer can read file", "viewer", "file:read", true},
		{"viewer cannot write file", "viewer", "file:write", false},
		{"operator can write file", "operator", "file:write", true},
		{"operator can read file (inherited)", "operator", "file:read", true},
		{"admin can write file (inherited from operator)", "admin", "file:write", true},
		{"admin can read file (inherited from viewer)", "admin", "file:read", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cm.CheckCapability(tt.role, tt.capability)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func BenchmarkRiskAssessor_AssessCommand(b *testing.B) {
	ra := NewRiskAssessor()
	command := "cat /etc/shadow"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ra.AssessCommand(command)
	}
}

func BenchmarkCapabilityManager_CheckCapability(b *testing.B) {
	cm := NewCapabilityManager()
	cm.SetRoleHierarchy("operator", "viewer")

	policy := &CapabilityPolicy{
		Role: "viewer",
		Mode: "allowlist",
		Capabilities: []*Capability{
			{Name: "file:read"},
		},
	}
	cm.SetRolePolicy(policy)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cm.CheckCapability("operator", "file:read")
	}
}
