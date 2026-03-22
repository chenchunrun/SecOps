package permission

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// SecOpsService 权限服务接口
type SecOpsService interface {
	// 请求权限
	Request(req *PermissionRequest) error

	// 检查权限
	Check(sessionID, toolName string) (bool, error)

	// 检查能力
	CheckCapability(userID, capability string) (bool, error)

	// 评估风险
	EvaluateRisk(req *PermissionRequest) (int, Severity, error)

	// 获取决策
	MakeDecision(req *PermissionRequest) (PermissionDecision, error)

	// 审计记录
	AuditLog(req *PermissionRequest, decision PermissionDecision) error
}

// permissionEntry 已批准权限的内部记录
type permissionEntry struct {
	ToolName  string
	Decision  PermissionDecision
	ExpiresAt time.Time
}

// capabilityEntry 用户能力映射
type capabilityEntry struct {
	Capabilities map[string]bool
}

// auditRecord 审计日志记录
type auditRecord struct {
	Request   *PermissionRequest
	Decision  PermissionDecision
	Timestamp time.Time
}

// 资源类型到严重级别的映射
var resourceSeverity = map[ResourceType]Severity{
	ResourceTypeSystem:   SeverityCritical,
	ResourceTypeDatabase: SeverityHigh,
	ResourceTypeProcess:  SeverityHigh,
	ResourceTypeNetwork:  SeverityMedium,
	ResourceTypeFile:     SeverityMedium,
	ResourceTypeCommand:  SeverityLow,
}

// 操作到基础风险分数的映射
var actionRiskBase = map[string]int{
	"delete":  40,
	"execute": 30,
	"write":   20,
	"read":    5,
	"query":   5,
}

// 敏感路径前缀
var sensitivePaths = []string{
	"/etc/shadow", "/etc/sudoers", "/root/.ssh",
	"/.aws/credentials", "/.kube/config", "/etc/ssl/private",
}

// DefaultService 默认权限服务实现
type DefaultService struct {
	mu           sync.RWMutex
	permissions  map[string]*permissionEntry  // key: sessionID:toolName
	capabilities map[string]*capabilityEntry  // key: userID
	auditLog     []auditRecord
}

// NewDefaultService 创建默认权限服务
func NewDefaultService() *DefaultService {
	return &DefaultService{
		permissions:  make(map[string]*permissionEntry),
		capabilities: make(map[string]*capabilityEntry),
		auditLog:     make([]auditRecord, 0),
	}
}

// Request 实现 Service.Request - 处理权限请求
func (ds *DefaultService) Request(req *PermissionRequest) error {
	if req == nil {
		return fmt.Errorf("permission request cannot be nil")
	}
	if req.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	if req.ToolName == "" {
		return fmt.Errorf("tool_name is required")
	}

	// 评估风险
	riskScore, severity, err := ds.EvaluateRisk(req)
	if err != nil {
		return fmt.Errorf("risk evaluation failed: %w", err)
	}
	req.RiskScore = riskScore
	req.Severity = severity

	// 做出决策
	decision, err := ds.MakeDecision(req)
	if err != nil {
		return fmt.Errorf("decision failed: %w", err)
	}
	req.Decision = decision

	// 记录权限条目
	if decision == DecisionAutoApprove {
		ds.mu.Lock()
		key := req.SessionID + ":" + req.ToolName
		ds.permissions[key] = &permissionEntry{
			ToolName:  req.ToolName,
			Decision:  decision,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		ds.mu.Unlock()
	}

	// 记录审计
	_ = ds.AuditLog(req, decision)

	return nil
}

// Check 实现 Service.Check - 检查权限是否已批准
func (ds *DefaultService) Check(sessionID, toolName string) (bool, error) {
	if sessionID == "" || toolName == "" {
		return false, fmt.Errorf("sessionID and toolName are required")
	}

	ds.mu.RLock()
	defer ds.mu.RUnlock()

	key := sessionID + ":" + toolName
	entry, exists := ds.permissions[key]
	if !exists {
		return false, nil
	}

	// 检查是否已过期
	if time.Now().After(entry.ExpiresAt) {
		return false, nil
	}

	return entry.Decision == DecisionAutoApprove, nil
}

// CheckCapability 实现 Service.CheckCapability - 检查用户是否有指定能力
func (ds *DefaultService) CheckCapability(userID, capability string) (bool, error) {
	if userID == "" || capability == "" {
		return false, fmt.Errorf("userID and capability are required")
	}

	ds.mu.RLock()
	defer ds.mu.RUnlock()

	entry, exists := ds.capabilities[userID]
	if !exists {
		return false, nil
	}

	return entry.Capabilities[capability], nil
}

// GrantCapability 授予用户能力
func (ds *DefaultService) GrantCapability(userID, capability string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	entry, exists := ds.capabilities[userID]
	if !exists {
		entry = &capabilityEntry{
			Capabilities: make(map[string]bool),
		}
		ds.capabilities[userID] = entry
	}
	entry.Capabilities[capability] = true
}

// RevokeCapability 撤销用户能力
func (ds *DefaultService) RevokeCapability(userID, capability string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if entry, exists := ds.capabilities[userID]; exists {
		delete(entry.Capabilities, capability)
	}
}

// EvaluateRisk 实现 Service.EvaluateRisk - 评估请求风险
func (ds *DefaultService) EvaluateRisk(req *PermissionRequest) (int, Severity, error) {
	if req == nil {
		return 0, SeverityLow, fmt.Errorf("request cannot be nil")
	}

	score := 0

	// 1. 基于操作类型的基础风险
	if base, ok := actionRiskBase[req.Action]; ok {
		score += base
	}

	// 2. 基于资源类型的风险
	switch req.ResourceType {
	case ResourceTypeSystem:
		score += 30
	case ResourceTypeDatabase:
		score += 25
	case ResourceTypeProcess:
		score += 20
	case ResourceTypeNetwork:
		score += 15
	case ResourceTypeFile:
		score += 10
	}

	// 3. 敏感路径访问风险
	path := req.ResourcePath
	if path == "" {
		path = req.Path
	}
	for _, sp := range sensitivePaths {
		if strings.Contains(strings.ToLower(path), strings.ToLower(sp)) {
			score += 25
			break
		}
	}

	// 限制分数在 0-100
	if score > 100 {
		score = 100
	}

	// 根据分数确定严重级别
	var severity Severity
	switch {
	case score >= 80:
		severity = SeverityCritical
	case score >= 60:
		severity = SeverityHigh
	case score >= 40:
		severity = SeverityMedium
	default:
		severity = SeverityLow
	}

	return score, severity, nil
}

// MakeDecision 实现 Service.MakeDecision - 做出权限决策
func (ds *DefaultService) MakeDecision(req *PermissionRequest) (PermissionDecision, error) {
	if req == nil {
		return DecisionDeny, fmt.Errorf("request cannot be nil")
	}

	score := req.RiskScore

	switch {
	case score >= 80:
		return DecisionDeny, nil
	case score >= 60:
		return DecisionAdminReview, nil
	case score >= 40:
		return DecisionUserConfirm, nil
	default:
		return DecisionAutoApprove, nil
	}
}

// AuditLog implements Service.AuditLog - records audit log.
// Params is never stored; only metadata (tool name, action, resource path,
// risk score, decision) is persisted to prevent credential exposure.
func (ds *DefaultService) AuditLog(req *PermissionRequest, decision PermissionDecision) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	// Store a sanitized copy — never persist raw Params which may contain
	// credentials, secrets, or other sensitive input values.
	sanitized := *req
	sanitized.Params = nil
	// Derive a safe command fingerprint from the description for auditability.
	if req.Action == "execute" && req.Description != "" {
		desc := req.Description
		if len(desc) > 64 {
			desc = desc[:64]
		}
		sanitized.Description = desc
	}

	ds.auditLog = append(ds.auditLog, auditRecord{
		Request:   &sanitized,
		Decision:  decision,
		Timestamp: time.Now(),
	})

	return nil
}

// GetAuditLog 获取审计日志（用于测试和查询）
func (ds *DefaultService) GetAuditLog() []auditRecord {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	result := make([]auditRecord, len(ds.auditLog))
	copy(result, ds.auditLog)
	return result
}
