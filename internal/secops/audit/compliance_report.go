package audit

import (
	"fmt"
	"sort"
	"time"
)

// ComplianceFramework 合规框架
type ComplianceFramework string

const (
	FrameworkSOC2     ComplianceFramework = "soc2"
	FrameworkHIPAA    ComplianceFramework = "hipaa"
	FrameworkGDPR     ComplianceFramework = "gdpr"
	FrameworkPCIDSS   ComplianceFramework = "pci_dss"
	FrameworkISO27001 ComplianceFramework = "iso27001"
)

// ComplianceReport 合规报告
type ComplianceReport struct {
	// 报告元数据
	ID            string              `json:"id"`
	Framework     ComplianceFramework `json:"framework"`
	GeneratedAt   time.Time           `json:"generated_at"`
	ReportPeriod  *TimePeriod         `json:"report_period"`
	ReportedBy    string              `json:"reported_by,omitempty"`

	// 合规度量
	TotalEvents        int              `json:"total_events"`
	SuccessfulEvents   int              `json:"successful_events"`
	FailedEvents       int              `json:"failed_events"`
	DeniedEvents       int              `json:"denied_events"`
	ComplianceScore    float64          `json:"compliance_score"` // 0-100
	ComplianceStatus   string           `json:"compliance_status"` // pass, fail, warning

	// 风险分析
	TotalRiskScore     int              `json:"total_risk_score"`
	HighRiskEvents     int              `json:"high_risk_events"`
	CriticalRiskEvents int              `json:"critical_risk_events"`
	RiskTrend          string           `json:"risk_trend"` // increasing, decreasing, stable

	// 用户活动
	UniqueUsers        int              `json:"unique_users"`
	UniqueSessionIDs   int              `json:"unique_sessions"`
	TopUsers           []*UserActivity  `json:"top_users,omitempty"`

	// 操作统计
	OperationStats     map[string]int   `json:"operation_stats"`
	EventTypeStats     map[string]int   `json:"event_type_stats"`

	// 合规性详情
	ViolatedControls   []*ComplianceControl `json:"violated_controls,omitempty"`
	PassedControls     []*ComplianceControl `json:"passed_controls,omitempty"`

	// 建议
	Recommendations    []string         `json:"recommendations,omitempty"`

	// 审计追踪
	SuspiciousEvents   []*SuspiciousEvent `json:"suspicious_events,omitempty"`
}

// TimePeriod 时间周期
type TimePeriod struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

// UserActivity 用户活动
type UserActivity struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	EventCount int    `json:"event_count"`
	RiskScore int    `json:"risk_score"`
}

// ComplianceControl 合规控制
type ComplianceControl struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Framework   string `json:"framework"`
	Status      string `json:"status"`        // pass, fail, warning
	Severity    string `json:"severity"`      // critical, high, medium, low
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation,omitempty"`
}

// SuspiciousEvent 可疑事件
type SuspiciousEvent struct {
	EventID      string    `json:"event_id"`
	EventType    string    `json:"event_type"`
	Timestamp    time.Time `json:"timestamp"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	Reason       string    `json:"reason"`
	RiskScore    int       `json:"risk_score"`
	Details      string    `json:"details,omitempty"`
}

// ComplianceReportGenerator 合规报告生成器
type ComplianceReportGenerator struct {
	store *InMemoryAuditStore
}

// NewComplianceReportGenerator 创建合规报告生成器
func NewComplianceReportGenerator(store *InMemoryAuditStore) *ComplianceReportGenerator {
	return &ComplianceReportGenerator{
		store: store,
	}
}

// GenerateReport 生成合规报告
func (g *ComplianceReportGenerator) GenerateReport(framework ComplianceFramework, startTime, endTime time.Time) (*ComplianceReport, error) {
	filter := &AuditFilter{
		StartTime: startTime,
		EndTime:   endTime,
	}

	events, err := g.store.ListEvents(filter)
	if err != nil {
		return nil, err
	}

	report := &ComplianceReport{
		ID:            fmt.Sprintf("rpt_%d", time.Now().Unix()),
		Framework:     framework,
		GeneratedAt:   time.Now(),
		ReportPeriod:  &TimePeriod{StartTime: startTime, EndTime: endTime},
		OperationStats: make(map[string]int),
		EventTypeStats: make(map[string]int),
		TopUsers:       make([]*UserActivity, 0),
		PassedControls: make([]*ComplianceControl, 0),
		ViolatedControls: make([]*ComplianceControl, 0),
		Recommendations: make([]string, 0),
		SuspiciousEvents: make([]*SuspiciousEvent, 0),
	}

	if len(events) == 0 {
		report.ComplianceStatus = "pass"
		report.ComplianceScore = 100
		return report, nil
	}

	// 分析事件
	g.analyzeEvents(report, events)

	// 计算合规度评分
	report.ComplianceScore = g.calculateComplianceScore(report)
	report.ComplianceStatus = g.determineComplianceStatus(report)

	// 生成合规控制结果
	g.evaluateControls(report, framework)

	// 生成建议
	report.Recommendations = g.generateRecommendations(report)

	return report, nil
}

// analyzeEvents 分析审计事件
func (g *ComplianceReportGenerator) analyzeEvents(report *ComplianceReport, events []*AuditEvent) {
	userStats := make(map[string]*UserActivity)

	for _, event := range events {
		report.TotalEvents++

		// 统计结果
		switch event.Result {
		case ResultSuccess:
			report.SuccessfulEvents++
		case ResultFailure:
			report.FailedEvents++
		case ResultDenied:
			report.DeniedEvents++
		}

		// 统计风险
		report.TotalRiskScore += event.RiskScore
		if event.RiskLevel == "high" {
			report.HighRiskEvents++
		}
		if event.RiskLevel == "critical" {
			report.CriticalRiskEvents++
		}

		// 统计操作
		if event.Action != "" {
			report.OperationStats[event.Action]++
		}

		// 统计事件类型
		report.EventTypeStats[string(event.EventType)]++

		// 用户统计
		if event.UserID != "" {
			if _, exists := userStats[event.UserID]; !exists {
				userStats[event.UserID] = &UserActivity{
					UserID:   event.UserID,
					Username: event.Username,
				}
			}
			userStats[event.UserID].EventCount++
			userStats[event.UserID].RiskScore += event.RiskScore
		}

		// 检查可疑事件
		if event.RiskScore > 70 || event.Result == ResultDenied {
			report.SuspiciousEvents = append(report.SuspiciousEvents, &SuspiciousEvent{
				EventID:   event.ID,
				EventType: string(event.EventType),
				Timestamp: event.Timestamp,
				UserID:    event.UserID,
				Username:  event.Username,
				Reason:    fmt.Sprintf("High risk score: %d", event.RiskScore),
				RiskScore: event.RiskScore,
			})
		}
	}

	// 生成高风险用户列表
	for _, user := range userStats {
		report.TopUsers = append(report.TopUsers, user)
	}

	// 排序并限制大小
	sort.SliceStable(report.TopUsers, func(i, j int) bool {
		return report.TopUsers[i].EventCount > report.TopUsers[j].EventCount
	})

	if len(report.TopUsers) > 10 {
		report.TopUsers = report.TopUsers[:10]
	}

	// 统计唯一用户和会话
	uniqueUsers := make(map[string]bool)
	uniqueSessions := make(map[string]bool)

	for _, event := range events {
		if event.UserID != "" {
			uniqueUsers[event.UserID] = true
		}
		if event.SessionID != "" {
			uniqueSessions[event.SessionID] = true
		}
	}

	report.UniqueUsers = len(uniqueUsers)
	report.UniqueSessionIDs = len(uniqueSessions)
}

// calculateComplianceScore 计算合规度
func (g *ComplianceReportGenerator) calculateComplianceScore(report *ComplianceReport) float64 {
	if report.TotalEvents == 0 {
		return 100
	}

	successRate := float64(report.SuccessfulEvents) / float64(report.TotalEvents) * 100
	failureRate := float64(report.FailedEvents) / float64(report.TotalEvents) * 100

	// 合规度 = 成功率 - 失败率 * 2
	score := successRate - (failureRate * 2)

	// 考虑高风险事件
	if report.CriticalRiskEvents > 0 {
		score -= float64(report.CriticalRiskEvents) * 5
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// determineComplianceStatus 确定合规状态
func (g *ComplianceReportGenerator) determineComplianceStatus(report *ComplianceReport) string {
	if report.CriticalRiskEvents > 0 || report.ComplianceScore < 60 {
		return "fail"
	}

	if report.HighRiskEvents > 0 || report.ComplianceScore < 80 {
		return "warning"
	}

	return "pass"
}

// evaluateControls 评估合规控制
func (g *ComplianceReportGenerator) evaluateControls(report *ComplianceReport, framework ComplianceFramework) {
	// 定义框架的控制点
	controls := g.getFrameworkControls(framework)

	for _, control := range controls {
		// 根据报告内容评估控制
		if report.DeniedEvents > 0 && control.ID == "ACCESS_CONTROL_001" {
			control.Status = "pass"
		} else if report.TotalEvents > 0 && control.ID == "AUDIT_LOGGING_001" {
			control.Status = "pass"
		} else if report.CriticalRiskEvents > 0 && control.ID == "INCIDENT_RESPONSE_001" {
			control.Status = "fail"
			control.Remediation = "Implement incident response procedures"
		} else {
			control.Status = "pass"
		}

		if control.Status == "pass" {
			report.PassedControls = append(report.PassedControls, control)
		} else {
			report.ViolatedControls = append(report.ViolatedControls, control)
		}
	}
}

// getFrameworkControls 获取框架的控制点
func (g *ComplianceReportGenerator) getFrameworkControls(framework ComplianceFramework) []*ComplianceControl {
	switch framework {
	case FrameworkSOC2:
		return g.getSOC2Controls()
	case FrameworkHIPAA:
		return g.getHIPAAControls()
	case FrameworkGDPR:
		return g.getGDPRControls()
	case FrameworkPCIDSS:
		return g.getPCIDSSControls()
	case FrameworkISO27001:
		return g.getISO27001Controls()
	default:
		return []*ComplianceControl{}
	}
}

// getSOC2Controls SOC2 控制点
func (g *ComplianceReportGenerator) getSOC2Controls() []*ComplianceControl {
	return []*ComplianceControl{
		{
			ID:          "AUDIT_LOGGING_001",
			Name:        "Audit Logging",
			Framework:   "soc2",
			Severity:    "critical",
			Description: "System generates and records information about user access",
		},
		{
			ID:          "ACCESS_CONTROL_001",
			Name:        "Access Control",
			Framework:   "soc2",
			Severity:    "critical",
			Description: "System prevents unauthorized access to resources",
		},
		{
			ID:          "INCIDENT_RESPONSE_001",
			Name:        "Incident Response",
			Framework:   "soc2",
			Severity:    "high",
			Description: "Organization responds to security incidents",
		},
	}
}

// getHIPAAControls HIPAA 控制点
func (g *ComplianceReportGenerator) getHIPAAControls() []*ComplianceControl {
	return []*ComplianceControl{
		{
			ID:          "AUDIT_TRAIL_001",
			Name:        "Audit Trail",
			Framework:   "hipaa",
			Severity:    "critical",
			Description: "Maintain audit trail of access to PHI",
		},
		{
			ID:          "ENCRYPTION_001",
			Name:        "Encryption",
			Framework:   "hipaa",
			Severity:    "critical",
			Description: "Encrypt PHI at rest and in transit",
		},
	}
}

// getGDPRControls GDPR 控制点
func (g *ComplianceReportGenerator) getGDPRControls() []*ComplianceControl {
	return []*ComplianceControl{
		{
			ID:          "DATA_PROTECTION_001",
			Name:        "Data Protection",
			Framework:   "gdpr",
			Severity:    "critical",
			Description: "Protect personal data of EU residents",
		},
	}
}

// getPCIDSSControls PCI-DSS 控制点
func (g *ComplianceReportGenerator) getPCIDSSControls() []*ComplianceControl {
	return []*ComplianceControl{
		{
			ID:          "CARDHOLDER_DATA_001",
			Name:        "Cardholder Data Protection",
			Framework:   "pci_dss",
			Severity:    "critical",
			Description: "Protect cardholder data",
		},
	}
}

// getISO27001Controls ISO27001 控制点
func (g *ComplianceReportGenerator) getISO27001Controls() []*ComplianceControl {
	return []*ComplianceControl{
		{
			ID:          "INFORMATION_SECURITY_001",
			Name:        "Information Security",
			Framework:   "iso27001",
			Severity:    "critical",
			Description: "Implement information security management system",
		},
	}
}

// generateRecommendations 生成建议
func (g *ComplianceReportGenerator) generateRecommendations(report *ComplianceReport) []string {
	recommendations := make([]string, 0)

	if report.CriticalRiskEvents > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("CRITICAL: Investigate %d critical risk events immediately", report.CriticalRiskEvents))
	}

	if report.HighRiskEvents > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("HIGH: Review and mitigate %d high-risk events", report.HighRiskEvents))
	}

	if report.FailedEvents > 0 && float64(report.FailedEvents)/float64(report.TotalEvents) > 0.1 {
		recommendations = append(recommendations,
			fmt.Sprintf("WARNING: High failure rate (%.1f%%), investigate root causes",
				float64(report.FailedEvents)/float64(report.TotalEvents)*100))
	}

	if len(report.ViolatedControls) > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("COMPLIANCE: Address %d violated controls", len(report.ViolatedControls)))
	}

	if report.ComplianceScore < 60 {
		recommendations = append(recommendations,
			"Compliance score is below acceptable threshold - immediate action required")
	}

	return recommendations
}
