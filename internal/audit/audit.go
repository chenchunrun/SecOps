package audit

import (
	"crypto/rand"
	"fmt"
	"time"
)

// AuditEventType 审计事件类型
type AuditEventType string

const (
	EventTypePermissionRequest AuditEventType = "permission_request"
	EventTypePermissionApproved AuditEventType = "permission_approved"
	EventTypePermissionDenied AuditEventType = "permission_denied"
	EventTypeCommandExecuted AuditEventType = "command_executed"
	EventTypeCommandFailed AuditEventType = "command_failed"
	EventTypeLoginSuccess AuditEventType = "login_success"
	EventTypeLoginFailure AuditEventType = "login_failure"
	EventTypeDataAccess AuditEventType = "data_access"
	EventTypeConfigChange AuditEventType = "config_change"
	EventTypeSecurityAlert AuditEventType = "security_alert"
)

// AuditResult 审计结果
type AuditResult string

const (
	ResultSuccess AuditResult = "success"
	ResultFailure AuditResult = "failure"
	ResultDenied  AuditResult = "denied"
	ResultError   AuditResult = "error"
)

// AuditEvent 审计事件
type AuditEvent struct {
	// 基础字段
	ID        string         `json:"id"`
	EventType AuditEventType `json:"event_type"`
	Timestamp time.Time      `json:"timestamp"`

	// 用户和会话信息
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	SourceIP  string `json:"source_ip"`

	// 操作信息
	Action       string `json:"action"`       // 执行的操作
	ResourceType string `json:"resource_type"` // 资源类型
	ResourceName string `json:"resource_name"` // 资源名称
	ResourcePath string `json:"resource_path"` // 资源路径
	Transport    string `json:"transport,omitempty"`    // local / ssh / docker
	TargetHost   string `json:"target_host,omitempty"`  // remote target host/user@host
	TargetEnv    string `json:"target_env,omitempty"`   // prod / staging / dev
	TargetID     string `json:"target_id,omitempty"`    // profile id or target group

	// 结果信息
	Result   AuditResult `json:"result"`
	ErrorMsg string      `json:"error_msg,omitempty"`

	// 安全信息
	RiskScore  int    `json:"risk_score"`
	RiskLevel  string `json:"risk_level"`
	Severity   string `json:"severity"`

	// 详细信息
	Details    map[string]interface{} `json:"details,omitempty"`
	ChangeData *ChangeData            `json:"change_data,omitempty"`

	// 合规和审批信息
	ApprovalID   string    `json:"approval_id,omitempty"`
	ApprovedBy   string    `json:"approved_by,omitempty"`
	ApprovedAt   time.Time `json:"approved_at,omitempty"`
	Reason       string    `json:"reason,omitempty"`

	// 签名和完整性（供未来使用）
	Signature string `json:"signature,omitempty"`
}

// ChangeData 变更数据
type ChangeData struct {
	FieldName string      `json:"field_name"`
	OldValue  interface{} `json:"old_value"`
	NewValue  interface{} `json:"new_value"`
}

// AuditLogger 审计日志接口
type AuditLogger interface {
	// 记录审计事件
	Log(event *AuditEvent) error

	// 查询审计事件
	Query(filter *AuditFilter) ([]*AuditEvent, error)

	// 获取事件计数
	Count(filter *AuditFilter) (int, error)

	// 导出审计日志
	Export(filter *AuditFilter, format string) (interface{}, error)

	// 清理过期日志
	Cleanup(olderThan time.Duration) error
}

// AuditFilter 审计过滤器
type AuditFilter struct {
	// 时间范围
	StartTime time.Time
	EndTime   time.Time

	// 用户和会话
	SessionID string
	UserID    string
	Username  string

	// 操作和资源
	EventType    AuditEventType
	Action       string
	ResourceType string
	ResourceName string

	// 结果过滤
	Result AuditResult

	// 安全级别
	MinRiskScore int

	// 分页
	Offset int
	Limit  int
}

// AuditStore 审计存储接口
type AuditStore interface {
	// 保存事件
	SaveEvent(event *AuditEvent) error

	// 获取事件
	GetEvent(id string) (*AuditEvent, error)

	// 列表查询
	ListEvents(filter *AuditFilter) ([]*AuditEvent, error)

	// 计数
	CountEvents(filter *AuditFilter) (int, error)

	// 删除事件
	DeleteEvent(id string) error

	// 删除过期事件
	DeleteExpiredEvents(olderThan time.Duration) error
}

// DefaultAuditEvent 创建默认的审计事件
func DefaultAuditEvent(eventType AuditEventType) *AuditEvent {
	return &AuditEvent{
		ID:        generateID(),
		EventType: eventType,
		Timestamp: time.Now().UTC(),
		Details:   make(map[string]interface{}),
	}
}

// 辅助函数

// generateID 生成事件ID（使用 crypto/rand UUID v4）
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// fallback to timestamp-based ID
		return fmt.Sprintf("evt_%d_%d", time.Now().Unix(), time.Now().Nanosecond())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 2
	return fmt.Sprintf("evt_%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// BuildAuditEvent 构建审计事件（便利函数）
type AuditEventBuilder struct {
	event *AuditEvent
}

// NewAuditEventBuilder 创建审计事件构建器
func NewAuditEventBuilder(eventType AuditEventType) *AuditEventBuilder {
	return &AuditEventBuilder{
		event: DefaultAuditEvent(eventType),
	}
}

// WithSession 设置会话信息
func (b *AuditEventBuilder) WithSession(sessionID string) *AuditEventBuilder {
	b.event.SessionID = sessionID
	return b
}

// WithUser 设置用户信息
func (b *AuditEventBuilder) WithUser(userID, username string) *AuditEventBuilder {
	b.event.UserID = userID
	b.event.Username = username
	return b
}

// WithSourceIP 设置源IP
func (b *AuditEventBuilder) WithSourceIP(ip string) *AuditEventBuilder {
	b.event.SourceIP = ip
	return b
}

// WithAction 设置操作
func (b *AuditEventBuilder) WithAction(action string) *AuditEventBuilder {
	b.event.Action = action
	return b
}

// WithResource 设置资源信息
func (b *AuditEventBuilder) WithResource(resourceType, resourceName, resourcePath string) *AuditEventBuilder {
	b.event.ResourceType = resourceType
	b.event.ResourceName = resourceName
	b.event.ResourcePath = resourcePath
	return b
}

// WithRemoteTarget sets transport and remote target metadata.
func (b *AuditEventBuilder) WithRemoteTarget(transport, targetHost, targetEnv, targetID string) *AuditEventBuilder {
	b.event.Transport = transport
	b.event.TargetHost = targetHost
	b.event.TargetEnv = targetEnv
	b.event.TargetID = targetID
	return b
}

// WithResult 设置结果
func (b *AuditEventBuilder) WithResult(result AuditResult) *AuditEventBuilder {
	b.event.Result = result
	return b
}

// WithError 设置错误信息
func (b *AuditEventBuilder) WithError(errMsg string) *AuditEventBuilder {
	b.event.ErrorMsg = errMsg
	return b
}

// WithRiskScore 设置风险评分
func (b *AuditEventBuilder) WithRiskScore(score int, level string) *AuditEventBuilder {
	b.event.RiskScore = score
	b.event.RiskLevel = level
	return b
}

// WithApproval 设置审批信息
func (b *AuditEventBuilder) WithApproval(approvalID, approvedBy string) *AuditEventBuilder {
	b.event.ApprovalID = approvalID
	b.event.ApprovedBy = approvedBy
	b.event.ApprovedAt = time.Now().UTC()
	return b
}

// WithDetail 添加详细信息
func (b *AuditEventBuilder) WithDetail(key string, value interface{}) *AuditEventBuilder {
	b.event.Details[key] = value
	return b
}

// Build 构建事件
func (b *AuditEventBuilder) Build() *AuditEvent {
	return b.event
}
