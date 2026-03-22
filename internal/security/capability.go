package security

import (
	"fmt"
	"strings"
)

// Capability 能力定义
type Capability struct {
	Name        string   // 能力名称 (e.g., "file:read:/var/log/*")
	Description string   // 描述
	ResourceType string   // 资源类型 (file, network, process, database, command)
	Action      string    // 操作 (read, write, execute, delete, query)
	Pattern     string    // 资源模式 (支持 glob)
	RequiredRole string   // 所需角色
}

// CapabilitySet 能力集合
type CapabilitySet struct {
	capabilities map[string]*Capability
}

// NewCapabilitySet 创建新的能力集合
func NewCapabilitySet() *CapabilitySet {
	return &CapabilitySet{
		capabilities: make(map[string]*Capability),
	}
}

// AddCapability 添加能力
func (cs *CapabilitySet) AddCapability(cap *Capability) error {
	if cap.Name == "" {
		return fmt.Errorf("capability name is required")
	}
	cs.capabilities[cap.Name] = cap
	return nil
}

// HasCapability 检查是否拥有某个能力
func (cs *CapabilitySet) HasCapability(name string) bool {
	_, exists := cs.capabilities[name]
	return exists
}

// GetCapability 获取能力定义
func (cs *CapabilitySet) GetCapability(name string) (*Capability, bool) {
	cap, exists := cs.capabilities[name]
	return cap, exists
}

// GetAllCapabilities 获取所有能力
func (cs *CapabilitySet) GetAllCapabilities() []*Capability {
	caps := make([]*Capability, 0, len(cs.capabilities))
	for _, cap := range cs.capabilities {
		caps = append(caps, cap)
	}
	return caps
}

// ListCapabilitiesByRole 按角色列出能力
func (cs *CapabilitySet) ListCapabilitiesByRole(role string) []*Capability {
	var caps []*Capability
	for _, cap := range cs.capabilities {
		if cap.RequiredRole == "" || cap.RequiredRole == role {
			caps = append(caps, cap)
		}
	}
	return caps
}

// CapabilityPolicy 能力策略
type CapabilityPolicy struct {
	Role          string // 角色
	Mode          string // "allowlist" 或 "blocklist"
	Capabilities  []*Capability
	IncludeParent bool // 是否继承父角色的能力
}

// CapabilityManager 能力管理器
type CapabilityManager struct {
	rolePolicies map[string]*CapabilityPolicy
	hierarchy    map[string]string // 角色继承关系 (child -> parent)
}

// NewCapabilityManager 创建能力管理器
func NewCapabilityManager() *CapabilityManager {
	return &CapabilityManager{
		rolePolicies: make(map[string]*CapabilityPolicy),
		hierarchy:    make(map[string]string),
	}
}

// SetRolePolicy 设置角色策略
func (cm *CapabilityManager) SetRolePolicy(policy *CapabilityPolicy) error {
	if policy.Role == "" {
		return fmt.Errorf("role is required")
	}
	cm.rolePolicies[policy.Role] = policy
	return nil
}

// SetRoleHierarchy 设置角色继承关系
// parent 是当前角色继承的父角色
func (cm *CapabilityManager) SetRoleHierarchy(role, parent string) {
	cm.hierarchy[role] = parent
}

// CheckCapability 检查用户是否拥有指定能力
func (cm *CapabilityManager) CheckCapability(role, capability string) bool {
	// 检查当前角色
	if policy, exists := cm.rolePolicies[role]; exists {
		if cm.hasCapabilityInPolicy(policy, capability) {
			return true
		}
	}

	// 检查父角色（递归）
	if parent, exists := cm.hierarchy[role]; exists {
		return cm.CheckCapability(parent, capability)
	}

	return false
}

// hasCapabilityInPolicy 检查策略中是否有某个能力
func (cm *CapabilityManager) hasCapabilityInPolicy(policy *CapabilityPolicy, capability string) bool {
	for _, cap := range policy.Capabilities {
		if cap.Name == capability {
			if policy.Mode == "allowlist" {
				return true
			} else {
				return false
			}
		}
	}

	// 如果在列表中未找到
	if policy.Mode == "allowlist" {
		return false
	} else {
		return true // blocklist 模式，未列出的默认允许
	}
}

// GetCapabilitiesForRole 获取角色的所有能力
func (cm *CapabilityManager) GetCapabilitiesForRole(role string) []string {
	var caps []string
	seen := make(map[string]bool)

	// 递归收集能力
	cm.collectCapabilities(role, &caps, seen)
	return caps
}

// collectCapabilities 递归收集能力
func (cm *CapabilityManager) collectCapabilities(role string, caps *[]string, seen map[string]bool) {
	if seen[role] {
		return // 避免循环
	}
	seen[role] = true

	// 收集当前角色的能力
	if policy, exists := cm.rolePolicies[role]; exists {
		for _, cap := range policy.Capabilities {
			*caps = append(*caps, cap.Name)
		}
	}

	// 收集父角色的能力
	if parent, exists := cm.hierarchy[role]; exists {
		cm.collectCapabilities(parent, caps, seen)
	}
}

// MatchCapabilityPattern 检查能力是否匹配模式
// 支持 * (匹配单层) 和 ** (匹配多层) 通配符
// 例如：能力 "file:read:/var/log/*" 匹配 "file:read:/var/log/syslog"
// 例如：能力 "file:read:/var/**" 匹配 "file:read:/var/log/deep/nested"
func MatchCapabilityPattern(pattern, request string) bool {
	patternParts := strings.Split(pattern, "/")
	requestParts := strings.Split(request, "/")

	return matchParts(patternParts, requestParts)
}

// matchParts 递归匹配路径部分
func matchParts(pattern, request []string) bool {
	pi, ri := 0, 0

	for pi < len(pattern) && ri < len(request) {
		p := pattern[pi]

		if p == "**" {
			// ** 匹配零个或多个路径段
			// 如果 ** 是最后一个 pattern 部分，匹配所有剩余
			if pi == len(pattern)-1 {
				return true
			}
			// 尝试匹配零个到所有剩余请求段
			for skip := 0; skip <= len(request)-ri; skip++ {
				if matchParts(pattern[pi+1:], request[ri+skip:]) {
					return true
				}
			}
			return false
		}

		if p == "*" {
			// * 匹配任意单个路径段
			pi++
			ri++
			continue
		}

		// 精确匹配
		if p != request[ri] {
			return false
		}
		pi++
		ri++
	}

	// 处理尾部的 **
	for pi < len(pattern) && pattern[pi] == "**" {
		pi++
	}

	return pi == len(pattern) && ri == len(request)
}

// Predefined capability policies
var (
	// OpsCapabilities is the Ops role capability policy set (allowlist mode)
	OpsCapabilities *CapabilitySet
	// SecurityCapabilities is the Security role capability policy set (allowlist mode)
	SecurityCapabilities *CapabilitySet
)

func init() {
	// Initialize OpsCapabilities
	OpsCapabilities = NewCapabilitySet()

	// Viewer role: read-only log and monitoring access
	_ = OpsCapabilities.AddCapability(&Capability{Name: "log:read", Description: "Read log files", ResourceType: "file", Action: "read", Pattern: "/var/log/**", RequiredRole: "viewer"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "log:read:/var/log/*", Description: "Read log files", ResourceType: "file", Action: "read", Pattern: "/var/log/*", RequiredRole: "viewer"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "monitoring:query", Description: "Query monitoring data", ResourceType: "network", Action: "query", Pattern: "*", RequiredRole: "viewer"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "file:read:/var/tmp/*", Description: "Read temp files", ResourceType: "file", Action: "read", Pattern: "/var/tmp/*", RequiredRole: "viewer"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "file:read:/home/*", Description: "Read user home files", ResourceType: "file", Action: "read", Pattern: "/home/*", RequiredRole: "viewer"})

	// Operator role: adds log analysis, process management, monitoring alerts
	_ = OpsCapabilities.AddCapability(&Capability{Name: "log:analyze", Description: "Analyze log patterns", ResourceType: "file", Action: "execute", Pattern: "/var/log/**", RequiredRole: "operator"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "process:query", Description: "Query running processes", ResourceType: "process", Action: "query", Pattern: "*", RequiredRole: "operator"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "process:kill", Description: "Kill processes", ResourceType: "process", Action: "execute", Pattern: "*", RequiredRole: "operator"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "monitoring:alert", Description: "Manage monitoring alerts", ResourceType: "network", Action: "execute", Pattern: "*", RequiredRole: "operator"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "network:diagnose", Description: "Run network diagnostics", ResourceType: "network", Action: "execute", Pattern: "*", RequiredRole: "operator"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "network:trace", Description: "Run traceroute", ResourceType: "network", Action: "execute", Pattern: "*", RequiredRole: "operator"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "shell:read-only", Description: "Execute read-only shell commands", ResourceType: "command", Action: "execute", Pattern: "*", RequiredRole: "operator"})

	// Admin role: full ops access including system modifications and export
	_ = OpsCapabilities.AddCapability(&Capability{Name: "log:export", Description: "Export log data", ResourceType: "file", Action: "write", Pattern: "*", RequiredRole: "admin"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "file:read", Description: "Read any file", ResourceType: "file", Action: "read", Pattern: "**", RequiredRole: "admin"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "file:write", Description: "Write any file", ResourceType: "file", Action: "write", Pattern: "**", RequiredRole: "admin"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "shell:read-write", Description: "Execute any shell command", ResourceType: "command", Action: "execute", Pattern: "*", RequiredRole: "admin"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "process:manage", Description: "Manage processes", ResourceType: "process", Action: "execute", Pattern: "*", RequiredRole: "admin"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "compliance:check", Description: "Run compliance checks", ResourceType: "database", Action: "execute", Pattern: "*", RequiredRole: "admin"})
	_ = OpsCapabilities.AddCapability(&Capability{Name: "compliance:report", Description: "Generate compliance reports", ResourceType: "database", Action: "execute", Pattern: "*", RequiredRole: "admin"})

	// Initialize SecurityCapabilities
	SecurityCapabilities = NewCapabilitySet()

	// Analyst role: read-only security scanning and audit
	_ = SecurityCapabilities.AddCapability(&Capability{Name: "security:scan", Description: "Run security scans", ResourceType: "command", Action: "execute", Pattern: "*", RequiredRole: "analyst"})
	_ = SecurityCapabilities.AddCapability(&Capability{Name: "security:audit", Description: "Audit security configuration", ResourceType: "file", Action: "read", Pattern: "/etc/**", RequiredRole: "analyst"})
	_ = SecurityCapabilities.AddCapability(&Capability{Name: "security:analyze", Description: "Analyze security findings", ResourceType: "database", Action: "query", Pattern: "*", RequiredRole: "analyst"})
	_ = SecurityCapabilities.AddCapability(&Capability{Name: "file:read:/var/log/**", Description: "Read log files for analysis", ResourceType: "file", Action: "read", Pattern: "/var/log/**", RequiredRole: "analyst"})
	_ = SecurityCapabilities.AddCapability(&Capability{Name: "compliance:report", Description: "View compliance reports", ResourceType: "database", Action: "query", Pattern: "*", RequiredRole: "analyst"})

	// Responder role: adds active response capabilities
	_ = SecurityCapabilities.AddCapability(&Capability{Name: "network:scan", Description: "Run network scans", ResourceType: "network", Action: "execute", Pattern: "*", RequiredRole: "responder"})
	_ = SecurityCapabilities.AddCapability(&Capability{Name: "process:kill", Description: "Kill suspicious processes", ResourceType: "process", Action: "execute", Pattern: "*", RequiredRole: "responder"})
	_ = SecurityCapabilities.AddCapability(&Capability{Name: "file:delete", Description: "Delete malicious files", ResourceType: "file", Action: "delete", Pattern: "*", RequiredRole: "responder"})
	_ = SecurityCapabilities.AddCapability(&Capability{Name: "compliance:check", Description: "Run compliance checks", ResourceType: "database", Action: "execute", Pattern: "*", RequiredRole: "responder"})
	_ = SecurityCapabilities.AddCapability(&Capability{Name: "security:incident", Description: "Manage security incidents", ResourceType: "database", Action: "execute", Pattern: "*", RequiredRole: "responder"})
}

// CheckCapability checks if a user role has the specified capability.
// It checks both OpsCapabilities and SecurityCapabilities.
func CheckCapability(userRole, capability string) bool {
	if OpsCapabilities.HasCapability(capability) {
		for _, cap := range OpsCapabilities.GetAllCapabilities() {
			if cap.Name == capability && (cap.RequiredRole == "" || cap.RequiredRole == userRole) {
				return true
			}
		}
	}
	if SecurityCapabilities.HasCapability(capability) {
		for _, cap := range SecurityCapabilities.GetAllCapabilities() {
			if cap.Name == capability && (cap.RequiredRole == "" || cap.RequiredRole == userRole) {
				return true
			}
		}
	}
	return false
}

// GetCapabilitiesForRole returns all capabilities available to a given role.
func GetCapabilitiesForRole(role string) []*Capability {
	var caps []*Capability
	seen := make(map[string]bool)

	for _, cap := range OpsCapabilities.GetAllCapabilities() {
		if (cap.RequiredRole == "" || cap.RequiredRole == role) && !seen[cap.Name] {
			caps = append(caps, cap)
			seen[cap.Name] = true
		}
	}
	for _, cap := range SecurityCapabilities.GetAllCapabilities() {
		if (cap.RequiredRole == "" || cap.RequiredRole == role) && !seen[cap.Name] {
			caps = append(caps, cap)
			seen[cap.Name] = true
		}
	}
	return caps
}

// Predefined capability constants
const (
	// 文件操作
	CapabilityFileRead    = "file:read"
	CapabilityFileWrite   = "file:write"
	CapabilityFileDelete  = "file:delete"
	CapabilityFileExecute = "file:execute"

	// 日志操作
	CapabilityLogRead    = "log:read"
	CapabilityLogAnalyze = "log:analyze"
	CapabilityLogExport  = "log:export"

	// 监控操作
	CapabilityMonitoringQuery = "monitoring:query"
	CapabilityMonitoringAlert = "monitoring:alert"

	// 合规操作
	CapabilityComplianceCheck   = "compliance:check"
	CapabilityComplianceReport  = "compliance:report"

	// 安全操作
	CapabilitySecurityScan     = "security:scan"
	CapabilitySecurityAudit    = "security:audit"
	CapabilitySecurityAnalyze  = "security:analyze"

	// 网络操作
	CapabilityNetworkDiag      = "network:diagnose"
	CapabilityNetworkTrace     = "network:trace"
	CapabilityNetworkScan      = "network:scan"

	// 系统操作
	CapabilityShellReadOnly    = "shell:read-only"
	CapabilityShellReadWrite   = "shell:read-write"
	CapabilityProcessQuery     = "process:query"
	CapabilityProcessKill      = "process:kill"

	// 数据库操作
	CapabilityDatabaseQuery    = "database:query"
	CapabilityDatabaseModify   = "database:modify"
)
