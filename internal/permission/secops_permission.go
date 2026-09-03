package permission

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
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

	// 授予能力
	GrantCapability(userID, capability string)

	// 撤销能力
	RevokeCapability(userID, capability string)

	// ListCapabilities lists persistent capabilities for a subject.
	ListCapabilities(userID string) []string

	// GrantSessionCapability grants a target-scoped capability for one session.
	GrantSessionCapability(grant CapabilityGrant) error

	// RevokeSessionCapability revokes matching grants and returns removed entries.
	RevokeSessionCapability(sessionID, subject, capability, target string) []CapabilityGrant

	// ListSessionCapabilities lists active grants for a session and subject.
	ListSessionCapabilities(sessionID, subject string) []CapabilityGrant

	// FindSessionCapability resolves an active grant for a target.
	FindSessionCapability(sessionID, subject, capability, target string) (CapabilityGrant, bool)

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

// CapabilityGrant is a temporary, session-bound and target-scoped grant.
type CapabilityGrant struct {
	SessionID       string    `json:"session_id"`
	Subject         string    `json:"subject"`
	Capability      string    `json:"capability"`
	Target          string    `json:"target"`
	AuthorizationID string    `json:"authorization_id,omitempty"`
	GrantedBy       string    `json:"granted_by"`
	GrantedAt       time.Time `json:"granted_at"`
	ExpiresAt       time.Time `json:"expires_at"`
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
	mu            sync.RWMutex
	permissions   map[string]*permissionEntry // key: sessionID:toolName
	capabilities  map[string]*capabilityEntry // key: userID
	sessionGrants []CapabilityGrant
	auditLog      []auditRecord
}

// maxAuditLogEntries caps the in-memory audit log to prevent unbounded memory growth.
const maxAuditLogEntries = 10000

const maxSessionCapabilityGrants = 1024

// NewDefaultService 创建默认权限服务
func NewDefaultService() *DefaultService {
	return &DefaultService{
		permissions:   make(map[string]*permissionEntry),
		capabilities:  make(map[string]*capabilityEntry),
		sessionGrants: make([]CapabilityGrant, 0),
		auditLog:      make([]auditRecord, 0),
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

// ListCapabilities lists persistent capabilities for a subject.
func (ds *DefaultService) ListCapabilities(userID string) []string {
	userID = strings.ToLower(strings.TrimSpace(userID))
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	entry, ok := ds.capabilities[userID]
	if !ok {
		return nil
	}
	capabilities := make([]string, 0, len(entry.Capabilities))
	for capability, granted := range entry.Capabilities {
		if granted {
			capabilities = append(capabilities, capability)
		}
	}
	return capabilities
}

// GrantSessionCapability grants a temporary capability with an exact target scope.
func (ds *DefaultService) GrantSessionCapability(grant CapabilityGrant) error {
	grant.SessionID = strings.TrimSpace(grant.SessionID)
	grant.Subject = strings.ToLower(strings.TrimSpace(grant.Subject))
	grant.Capability = strings.ToLower(strings.TrimSpace(grant.Capability))
	grant.Target = normalizeCapabilityTarget(grant.Target)
	grant.GrantedBy = strings.TrimSpace(grant.GrantedBy)
	if grant.SessionID == "" || grant.Subject == "" || grant.Capability == "" || grant.Target == "" {
		return fmt.Errorf("session_id, subject, capability, and target are required")
	}
	if grant.Target == "*" {
		return fmt.Errorf("target must be bounded")
	}
	if grant.GrantedBy == "" {
		return fmt.Errorf("granted_by is required")
	}
	if grant.GrantedAt.IsZero() {
		grant.GrantedAt = time.Now().UTC()
	}
	if grant.ExpiresAt.IsZero() || !grant.ExpiresAt.After(grant.GrantedAt) {
		return fmt.Errorf("expires_at must be after granted_at")
	}
	if !time.Now().UTC().Before(grant.ExpiresAt) {
		return fmt.Errorf("expires_at must be in the future")
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()
	now := time.Now().UTC()
	ds.pruneSessionGrantsLocked(now)
	for i := range ds.sessionGrants {
		existing := &ds.sessionGrants[i]
		if existing.SessionID == grant.SessionID && existing.Subject == grant.Subject &&
			existing.Capability == grant.Capability && existing.Target == grant.Target {
			*existing = grant
			return nil
		}
	}
	if len(ds.sessionGrants) >= maxSessionCapabilityGrants {
		return fmt.Errorf("session capability grant limit reached")
	}
	ds.sessionGrants = append(ds.sessionGrants, grant)
	return nil
}

// RevokeSessionCapability revokes matching temporary grants.
// An empty target revokes every matching target scope.
func (ds *DefaultService) RevokeSessionCapability(sessionID, subject, capability, target string) []CapabilityGrant {
	sessionID = strings.TrimSpace(sessionID)
	subject = strings.ToLower(strings.TrimSpace(subject))
	capability = strings.ToLower(strings.TrimSpace(capability))
	target = normalizeCapabilityTarget(target)

	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.pruneSessionGrantsLocked(time.Now().UTC())
	kept := ds.sessionGrants[:0]
	var removed []CapabilityGrant
	for _, grant := range ds.sessionGrants {
		matches := grant.SessionID == sessionID && grant.Subject == subject && grant.Capability == capability
		if matches && (target == "" || grant.Target == target) {
			removed = append(removed, grant)
			continue
		}
		kept = append(kept, grant)
	}
	ds.sessionGrants = kept
	return removed
}

// ListSessionCapabilities lists active temporary grants.
func (ds *DefaultService) ListSessionCapabilities(sessionID, subject string) []CapabilityGrant {
	sessionID = strings.TrimSpace(sessionID)
	subject = strings.ToLower(strings.TrimSpace(subject))
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.pruneSessionGrantsLocked(time.Now().UTC())
	grants := make([]CapabilityGrant, 0, len(ds.sessionGrants))
	for _, grant := range ds.sessionGrants {
		if grant.SessionID == sessionID && (subject == "" || grant.Subject == subject) {
			grants = append(grants, grant)
		}
	}
	return grants
}

// FindSessionCapability resolves a temporary grant whose target scope matches.
func (ds *DefaultService) FindSessionCapability(sessionID, subject, capability, target string) (CapabilityGrant, bool) {
	sessionID = strings.TrimSpace(sessionID)
	subject = strings.ToLower(strings.TrimSpace(subject))
	capability = strings.ToLower(strings.TrimSpace(capability))
	target = normalizeCapabilityTarget(target)
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.pruneSessionGrantsLocked(time.Now().UTC())
	for _, grant := range ds.sessionGrants {
		if grant.SessionID == sessionID && grant.Subject == subject && grant.Capability == capability &&
			capabilityTargetMatches(target, grant.Target) {
			return grant, true
		}
	}
	return CapabilityGrant{}, false
}

func (ds *DefaultService) pruneSessionGrantsLocked(now time.Time) {
	kept := ds.sessionGrants[:0]
	for _, grant := range ds.sessionGrants {
		if now.Before(grant.ExpiresAt) {
			kept = append(kept, grant)
		}
	}
	ds.sessionGrants = kept
}

func normalizeCapabilityTarget(target string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" {
		target = parsed.Hostname()
	}
	if at := strings.LastIndex(target, "@"); at >= 0 {
		target = target[at+1:]
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}
	return strings.Trim(target, "[]")
}

func capabilityTargetMatches(target, allowed string) bool {
	if target == "" || allowed == "" {
		return false
	}
	if allowed == "*" || target == allowed {
		return true
	}
	if prefix, err := netip.ParsePrefix(allowed); err == nil {
		address, err := netip.ParseAddr(target)
		return err == nil && prefix.Contains(address)
	}
	if strings.HasPrefix(allowed, "*.") {
		suffix := strings.TrimPrefix(allowed, "*")
		return strings.HasSuffix(target, suffix) && target != strings.TrimPrefix(suffix, ".")
	}
	return false
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

	// Evict oldest entries when the cap is exceeded to prevent unbounded memory growth.
	if len(ds.auditLog) > maxAuditLogEntries {
		ds.auditLog = ds.auditLog[len(ds.auditLog)-maxAuditLogEntries:]
	}

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
