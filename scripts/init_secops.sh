#!/bin/bash
# SecOps-Agent 项目初始化脚本

set -e

echo "🚀 SecOps-Agent 项目初始化"
echo "================================"

# 1. 创建项目目录结构
echo "创建项目目录结构..."
mkdir -p internal/security/scanner
mkdir -p internal/security/frameworks
mkdir -p internal/audit/templates
mkdir -p internal/compliance/templates
mkdir -p internal/monitoring
mkdir -p scripts/deployment
mkdir -p tests/{unit,integration,e2e}
mkdir -p docs/examples/workflows

echo "✓ 目录结构创建完成"

# 2. 创建初始 Go 文件
echo "创建初始代码文件..."

cat > internal/security/capability.go << 'EOF'
package security

// CapabilityPolicy 定义能力策略
type CapabilityPolicy struct {
	Mode  string   // "allowlist" 或 "blocklist"
	Rules []string // 能力规则列表
}

// CheckCapability 检查用户是否拥有指定能力
func CheckCapability(userRole, capability string) bool {
	// TODO: 实现能力检查逻辑
	return false
}
EOF

cat > internal/security/risk_assessment.go << 'EOF'
package security

// RiskAssessment 风险评估结果
type RiskAssessment struct {
	Score   int       // 0-100
	Level   string    // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Factors []RiskFactor
	Action  string    // "auto_approve", "user_confirm", "admin_review", "block"
}

// RiskFactor 单个风险因子
type RiskFactor struct {
	Name     string // 因子名称
	Weight   int    // 权重
	Evidence string // 证据
}

// RiskAssessor 风险评估器
type RiskAssessor struct{}

// AssessCommand 评估命令的风险
func (ra *RiskAssessor) AssessCommand(cmd string) RiskAssessment {
	// TODO: 实现风险评估逻辑
	return RiskAssessment{
		Score: 0,
		Level: "LOW",
		Action: "auto_approve",
	}
}
EOF

cat > internal/audit/audit.go << 'EOF'
package audit

import "time"

// AuditEvent 审计事件
type AuditEvent struct {
	ID          string
	Timestamp   time.Time
	SessionID   string
	UserID      string
	Action      string
	ResourceType string
	ResourceName string
	Result      string
	RiskScore   int
	SourceIP    string
}
EOF

echo "✓ 初始代码文件创建完成"

# 3. 显示后续步骤
echo ""
echo "================================"
echo "✓ 项目初始化完成！"
echo "================================"
echo ""
echo "后续步骤："
echo ""
echo "1. 创建 Phase 1 分支："
echo "   git checkout -b claude/phase1-permission-isolation"
echo ""
echo "2. 开始实现权限系统："
echo "   - 编辑 internal/permission/permission.go"
echo "   - 编辑 internal/security/capability.go"
echo "   - 编辑 internal/security/risk_assessment.go"
echo ""
echo "3. 运行测试："
echo "   go test ./..."
echo ""
echo "4. 提交代码："
echo "   git commit -m \"[SecOps] feat: implement phase 1\""
echo ""
