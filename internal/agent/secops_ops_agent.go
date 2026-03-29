package agent

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// AgentRole 代理角色
type AgentRole string

const (
	RoleOpsAgent      AgentRole = "ops_agent"
	RoleSecurityAgent AgentRole = "security_expert_agent"
	RoleCoordinator   AgentRole = "coordinator"
)

// AgentCapability 代理能力
type AgentCapability string

const (
	CapLogAnalysis  AgentCapability = "log_analysis"
	CapMonitoring   AgentCapability = "monitoring"
	CapCompliance   AgentCapability = "compliance_check"
	CapVulnScan     AgentCapability = "vulnerability_scan"
	CapCertAudit    AgentCapability = "certificate_audit"
	CapConfigAudit  AgentCapability = "configuration_audit"
	CapNetworkDiag  AgentCapability = "network_diagnostic"
	CapRiskAssess   AgentCapability = "risk_assessment"
	CapIncidentResp AgentCapability = "incident_response"
)

// AgentTask 代理任务
type AgentTask struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`   // incident, investigation, audit, diagnostic
	Status      string                 `json:"status"` // pending, in_progress, completed, failed
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CompletedAt time.Time              `json:"completed_at,omitempty"`
	Priority    string                 `json:"priority"` // critical, high, medium, low
	Severity    string                 `json:"severity"`
	AssignedTo  string                 `json:"assigned_to"`
	Result      interface{}            `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AgentResponse 代理响应
type AgentResponse struct {
	AgentRole       AgentRole                `json:"agent_role"`
	TaskID          string                   `json:"task_id"`
	Status          string                   `json:"status"`
	Action          string                   `json:"action"`           // 建议的操作
	Reasoning       string                   `json:"reasoning"`        // 推理过程
	Findings        []string                 `json:"findings"`         // 发现
	Alerts          []string                 `json:"alerts"`           // 告警
	Recommendations []string                 `json:"recommendations"`  // 建议
	ConfidenceScore float64                  `json:"confidence_score"` // 置信度 0-1
	NextSteps       []string                 `json:"next_steps"`
	WorkflowSummary *SecurityWorkflowSummary `json:"workflow_summary,omitempty"`
	ResponseTime    int                      `json:"response_time"` // 毫秒
	Error           string                   `json:"error,omitempty"`
}

type SecurityWorkflowSummary struct {
	PrimaryTool      string   `json:"primary_tool"`
	FollowupTools    []string `json:"followup_tools,omitempty"`
	EvidenceSources  []string `json:"evidence_sources,omitempty"`
	ContainmentFocus []string `json:"containment_focus,omitempty"`
	Status           string   `json:"status,omitempty"`
	Reason           string   `json:"reason"`
}

func (r *AgentResponse) RenderWorkflowSummary() string {
	if r == nil || r.WorkflowSummary == nil {
		return ""
	}

	summary := r.WorkflowSummary
	lines := []string{
		fmt.Sprintf("Recommended Tool: %s", summary.PrimaryTool),
		fmt.Sprintf("Reason: %s", summary.Reason),
	}
	if summary.Status != "" {
		lines = append(lines, fmt.Sprintf("Workflow Status: %s", summary.Status))
	}

	if len(summary.FollowupTools) > 0 {
		lines = append(lines, fmt.Sprintf("Recommended Follow-up Tools: %s", strings.Join(summary.FollowupTools, ", ")))
	}
	if len(summary.EvidenceSources) > 0 {
		lines = append(lines, fmt.Sprintf("Evidence Sources: %s", strings.Join(summary.EvidenceSources, ", ")))
	}
	if len(summary.ContainmentFocus) > 0 {
		lines = append(lines, fmt.Sprintf("Containment Focus: %s", strings.Join(summary.ContainmentFocus, "; ")))
	}

	return strings.Join(lines, "\n")
}

func (r *AgentResponse) RenderSecurityAssessment() string {
	if r == nil {
		return ""
	}

	lines := make([]string, 0, 8)
	if r.Action != "" {
		lines = append(lines, fmt.Sprintf("Action: %s", r.Action))
	}
	if r.Reasoning != "" {
		lines = append(lines, fmt.Sprintf("Reasoning: %s", r.Reasoning))
	}
	if r.ConfidenceScore > 0 {
		lines = append(lines, fmt.Sprintf("Confidence: %.2f", r.ConfidenceScore))
	}
	if workflow := r.RenderWorkflowSummary(); workflow != "" {
		lines = append(lines, "Workflow Summary:")
		lines = append(lines, workflow)
	}
	if len(r.Alerts) > 0 {
		lines = append(lines, fmt.Sprintf("Alerts: %s", strings.Join(r.Alerts, " | ")))
	}
	if len(r.Findings) > 0 {
		lines = append(lines, fmt.Sprintf("Findings: %s", strings.Join(r.Findings, " | ")))
	}
	if len(r.Recommendations) > 0 {
		lines = append(lines, fmt.Sprintf("Recommendations: %s", strings.Join(r.Recommendations, " | ")))
	}
	if len(r.NextSteps) > 0 {
		lines = append(lines, fmt.Sprintf("Next Steps: %s", strings.Join(r.NextSteps, " | ")))
	}

	return strings.Join(lines, "\n")
}

// OpsAgent 运维代理
type OpsAgent struct {
	mu           sync.RWMutex
	ID           string
	Role         AgentRole
	Capabilities []AgentCapability
	State        AgentState
	Knowledge    map[string]interface{}
}

// AgentState 代理状态
type AgentState struct {
	Status         string
	LastActivity   time.Time
	ActiveTasks    int
	CompletedTasks int
	FailedTasks    int
}

// NewOpsAgent 创建运维代理
func NewOpsAgent(id string) *OpsAgent {
	return &OpsAgent{
		ID:   id,
		Role: RoleOpsAgent,
		Capabilities: []AgentCapability{
			CapLogAnalysis,
			CapMonitoring,
			CapCompliance,
			CapNetworkDiag,
			CapRiskAssess,
		},
		State: AgentState{
			Status:       "ready",
			LastActivity: time.Now(),
		},
		Knowledge: make(map[string]interface{}),
	}
}

// ProcessTask 处理任务
func (a *OpsAgent) ProcessTask(task *AgentTask) *AgentResponse {
	startTime := time.Now()

	task.Status = "in_progress"
	task.UpdatedAt = time.Now()
	task.AssignedTo = a.ID

	response := &AgentResponse{
		AgentRole:       a.Role,
		TaskID:          task.ID,
		Status:          "processing",
		Findings:        make([]string, 0),
		Alerts:          make([]string, 0),
		Recommendations: make([]string, 0),
		NextSteps:       make([]string, 0),
	}

	// 根据任务类型处理
	switch task.Type {
	case "incident":
		response = a.handleIncident(task)
	case "investigation":
		response = a.handleInvestigation(task)
	case "audit":
		response = a.handleAudit(task)
	case "diagnostic":
		response = a.handleDiagnostic(task)
	default:
		response.Status = "failed"
		response.Error = "unknown task type"
	}

	if response.Status != "failed" {
		task.Status = "completed"
		task.Result = response
	} else {
		task.Status = "failed"
		task.Error = response.Error
	}

	task.CompletedAt = time.Now()

	// 更新统计（加锁保护共享状态）
	a.mu.Lock()
	if task.Status == "completed" {
		a.State.CompletedTasks++
	} else {
		a.State.FailedTasks++
	}
	a.State.LastActivity = time.Now()
	a.mu.Unlock()

	response.ResponseTime = int(time.Since(startTime).Milliseconds())

	return response
}

// handleIncident 处理事件
func (a *OpsAgent) handleIncident(task *AgentTask) *AgentResponse {
	response := &AgentResponse{
		AgentRole:       a.Role,
		TaskID:          task.ID,
		Status:          "completed",
		Reasoning:       "Analyzing incident details and system state",
		ConfidenceScore: 0.85,
	}

	// 模拟事件处理逻辑
	response.Findings = append(response.Findings,
		"High disk usage detected on /var partition",
		"Service degradation observed in monitoring metrics",
		"Network latency increased by 150%",
	)

	response.Alerts = append(response.Alerts,
		"CRITICAL: Disk usage at 95% on /var",
		"WARNING: Memory pressure detected",
	)

	response.Action = "Scale up infrastructure and clean disk space"

	response.Recommendations = append(response.Recommendations,
		"Implement automated disk cleanup for log files",
		"Enable disk usage monitoring alerts",
		"Plan capacity expansion for next quarter",
	)

	response.NextSteps = append(response.NextSteps,
		"Monitor recovery progress",
		"Review log rotation policies",
		"Schedule infrastructure review",
	)

	return response
}

// handleInvestigation 处理调查
func (a *OpsAgent) handleInvestigation(task *AgentTask) *AgentResponse {
	response := &AgentResponse{
		AgentRole:       a.Role,
		TaskID:          task.ID,
		Status:          "completed",
		Reasoning:       "Correlating logs and metrics to identify root cause",
		ConfidenceScore: 0.78,
	}

	response.Findings = append(response.Findings,
		"Root cause: Unoptimized database query",
		"Query execution time: 5.2 seconds (normal: 100ms)",
		"Affected transactions: ~10,000",
	)

	response.Action = "Optimize database query and add index"

	response.Recommendations = append(response.Recommendations,
		"Implement query performance monitoring",
		"Add slow query logs configuration",
		"Conduct database optimization review",
	)

	return response
}

// handleAudit 处理审计
func (a *OpsAgent) handleAudit(task *AgentTask) *AgentResponse {
	response := &AgentResponse{
		AgentRole:       a.Role,
		TaskID:          task.ID,
		Status:          "completed",
		Reasoning:       "Executing compliance audit against SOC2 controls",
		ConfidenceScore: 0.92,
	}

	response.Findings = append(response.Findings,
		"100% compliance with access control policies",
		"Audit logging enabled for all systems",
		"3 findings in configuration management",
	)

	response.Alerts = append(response.Alerts,
		"WARNING: SSH password authentication still enabled",
	)

	response.Recommendations = append(response.Recommendations,
		"Disable SSH password authentication",
		"Implement bastion host for all SSH access",
		"Review and update firewall rules quarterly",
	)

	return response
}

// handleDiagnostic 处理诊断
func (a *OpsAgent) handleDiagnostic(task *AgentTask) *AgentResponse {
	response := &AgentResponse{
		AgentRole:       a.Role,
		TaskID:          task.ID,
		Status:          "completed",
		Reasoning:       "Running network diagnostics and performance tests",
		ConfidenceScore: 0.88,
	}

	response.Findings = append(response.Findings,
		"Network latency: 15ms (healthy)",
		"Packet loss: 0.1% (within threshold)",
		"DNS resolution: 45ms average",
	)

	response.Action = "Network is healthy, continue monitoring"

	response.Recommendations = append(response.Recommendations,
		"Monitor latency trends for anomalies",
		"Set up automatic alerts for network degradation",
	)

	return response
}

// HasCapability 检查能力
func (a *OpsAgent) HasCapability(cap AgentCapability) bool {
	for _, c := range a.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// GetState 获取状态
func (a *OpsAgent) GetState() AgentState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.State
}

// UpdateKnowledge 更新知识库
func (a *OpsAgent) UpdateKnowledge(key string, value interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Knowledge[key] = value
}

// SecurityExpertAgent 安全专家代理
type SecurityExpertAgent struct {
	mu           sync.RWMutex
	ID           string
	Role         AgentRole
	Capabilities []AgentCapability
	State        AgentState
	Knowledge    map[string]interface{}
}

type securityWorkflowPlan struct {
	PrimaryTool string
	NeedsAttack bool
	Reason      string
}

func (p securityWorkflowPlan) summary(taskType string) *SecurityWorkflowSummary {
	summary := &SecurityWorkflowSummary{
		PrimaryTool:     p.PrimaryTool,
		EvidenceSources: []string{"alert_check", "log_analyze", "incident_timeline", "access_review"},
		Status:          "recommended only; ProcessTask did not execute the tools",
		Reason:          p.Reason,
	}

	if p.NeedsAttack {
		summary.FollowupTools = append(summary.FollowupTools, "attack_reason")
	}

	switch taskType {
	case "incident_response":
		summary.ContainmentFocus = []string{
			"isolate compromised systems",
			"preserve forensic evidence",
			"prioritize immediate containment decisions",
		}
	case "threat_assessment":
		summary.ContainmentFocus = []string{
			"correlate evidence before containment",
			"identify the most likely attacker path",
			"prioritize mitigations by confidence",
		}
	}

	return summary
}

// NewSecurityExpertAgent 创建安全专家代理
func NewSecurityExpertAgent(id string) *SecurityExpertAgent {
	return &SecurityExpertAgent{
		ID:   id,
		Role: RoleSecurityAgent,
		Capabilities: []AgentCapability{
			CapVulnScan,
			CapCertAudit,
			CapConfigAudit,
			CapRiskAssess,
			CapIncidentResp,
		},
		State: AgentState{
			Status:       "ready",
			LastActivity: time.Now(),
		},
		Knowledge: make(map[string]interface{}),
	}
}

// ProcessTask 处理任务
func (a *SecurityExpertAgent) ProcessTask(task *AgentTask) *AgentResponse {
	startTime := time.Now()

	task.Status = "in_progress"
	task.UpdatedAt = time.Now()
	task.AssignedTo = a.ID

	response := &AgentResponse{
		AgentRole:       a.Role,
		TaskID:          task.ID,
		Status:          "processing",
		Findings:        make([]string, 0),
		Alerts:          make([]string, 0),
		Recommendations: make([]string, 0),
		NextSteps:       make([]string, 0),
	}

	// 根据任务类型处理
	switch task.Type {
	case "vulnerability_scan":
		response = a.handleVulnerabilityScan(task)
	case "security_audit":
		response = a.handleSecurityAudit(task)
	case "threat_assessment":
		response = a.handleThreatAssessment(task)
	case "incident_response":
		response = a.handleSecurityIncident(task)
	default:
		response.Status = "failed"
		response.Error = "unknown task type"
	}

	if response.Status != "failed" {
		task.Status = "completed"
		task.Result = response
	} else {
		task.Status = "failed"
		task.Error = response.Error
	}

	task.CompletedAt = time.Now()

	// 更新统计（加锁保护共享状态）
	a.mu.Lock()
	if task.Status == "completed" {
		a.State.CompletedTasks++
	} else {
		a.State.FailedTasks++
	}
	a.State.LastActivity = time.Now()
	a.mu.Unlock()

	response.ResponseTime = int(time.Since(startTime).Milliseconds())

	return response
}

// handleVulnerabilityScan 处理漏洞扫描
func (a *SecurityExpertAgent) handleVulnerabilityScan(task *AgentTask) *AgentResponse {
	response := &AgentResponse{
		AgentRole:       a.Role,
		TaskID:          task.ID,
		Status:          "completed",
		Reasoning:       "Scanning for vulnerabilities in application and dependencies",
		ConfidenceScore: 0.90,
	}

	response.Findings = append(response.Findings,
		"1 CRITICAL vulnerability: CVE-2024-1234 in OpenSSL",
		"3 HIGH severity vulnerabilities found",
		"12 MEDIUM severity vulnerabilities found",
	)

	response.Alerts = append(response.Alerts,
		"CRITICAL: OpenSSL vulnerability allows remote code execution",
		"HIGH: Unpatched kernel vulnerabilities detected",
	)

	response.Action = "Patch OpenSSL and upgrade kernel immediately"

	response.Recommendations = append(response.Recommendations,
		"Upgrade OpenSSL to version 3.0.5 or later",
		"Apply kernel security patches",
		"Implement vulnerability scanning in CI/CD pipeline",
		"Enable automated dependency updates",
	)

	response.NextSteps = append(response.NextSteps,
		"Schedule emergency maintenance window",
		"Test patches in staging environment",
		"Deploy to production after validation",
	)

	return response
}

// handleSecurityAudit 处理安全审计
func (a *SecurityExpertAgent) handleSecurityAudit(task *AgentTask) *AgentResponse {
	response := &AgentResponse{
		AgentRole:       a.Role,
		TaskID:          task.ID,
		Status:          "completed",
		Reasoning:       "Conducting comprehensive security control audit",
		ConfidenceScore: 0.87,
	}

	response.Findings = append(response.Findings,
		"Access control: COMPLIANT",
		"Encryption: 1 issue found (weak cipher suites)",
		"Authentication: COMPLIANT",
		"Audit logging: COMPLIANT",
	)

	response.Alerts = append(response.Alerts,
		"WARNING: Weak TLS cipher suites enabled (RC4, DES)",
	)

	response.Recommendations = append(response.Recommendations,
		"Disable weak TLS cipher suites immediately",
		"Implement TLS 1.3 exclusively",
		"Review certificate validity and renewal process",
	)

	return response
}

// handleThreatAssessment 处理威胁评估
func (a *SecurityExpertAgent) handleThreatAssessment(task *AgentTask) *AgentResponse {
	workflow := a.selectSecurityWorkflow(task)
	response := &AgentResponse{
		AgentRole:       a.Role,
		TaskID:          task.ID,
		Status:          "completed",
		Reasoning:       fmt.Sprintf("Recommending %s as the next investigation workflow: %s", workflow.PrimaryTool, workflow.Reason),
		ConfidenceScore: 0.85,
		WorkflowSummary: workflow.summary("threat_assessment"),
	}

	response.Findings = append(response.Findings,
		"Primary threat: Unpatched software vulnerabilities",
		"Secondary threat: Weak authentication mechanisms",
		"Tertiary threat: Insufficient network segmentation",
	)
	if workflow.PrimaryTool == "incident_assess" {
		response.Findings = append(response.Findings,
			"Recommended investigation workflow: incident_assess for consolidated evidence correlation and containment guidance",
		)
	}
	if workflow.NeedsAttack {
		response.Findings = append(response.Findings,
			"If more evidence is collected, use attack_reason after the initial incident assessment for deeper ATT&CK technique ranking",
		)
	}

	response.Alerts = append(response.Alerts,
		"CRITICAL: High likelihood of successful compromise",
		"HIGH: Active threat actors targeting these vulnerabilities",
	)

	response.Action = fmt.Sprintf("Run %s as the next investigation step, then implement the immediate remediation plan", workflow.PrimaryTool)

	response.Recommendations = append(response.Recommendations,
		fmt.Sprintf("Start with %s to consolidate evidence before making containment decisions", workflow.PrimaryTool),
		"Prioritize patch management",
		"Implement MFA for all users",
		"Implement network microsegmentation",
		"Deploy intrusion detection system",
	)
	if workflow.NeedsAttack {
		response.Recommendations = append(response.Recommendations,
			"Use attack_reason to validate the most likely MITRE ATT&CK techniques after the consolidated assessment",
		)
	}

	response.NextSteps = append(response.NextSteps,
		fmt.Sprintf("Run %s with available alert, log, timeline, and access evidence", workflow.PrimaryTool),
	)
	if workflow.NeedsAttack {
		response.NextSteps = append(response.NextSteps,
			"Run attack_reason for deeper ATT&CK technique ranking if the incident_assess result leaves competing hypotheses",
		)
	}

	return response
}

// handleSecurityIncident 处理安全事件
func (a *SecurityExpertAgent) handleSecurityIncident(task *AgentTask) *AgentResponse {
	workflow := a.selectSecurityWorkflow(task)
	response := &AgentResponse{
		AgentRole:       a.Role,
		TaskID:          task.ID,
		Status:          "completed",
		Reasoning:       fmt.Sprintf("Recommending %s as the next incident workflow: %s", workflow.PrimaryTool, workflow.Reason),
		ConfidenceScore: 0.91,
		WorkflowSummary: workflow.summary("incident_response"),
	}

	response.Findings = append(response.Findings,
		"Incident: Unauthorized access to user database",
		"Impact: 50,000 user records potentially exposed",
		"Timeline: Attack detected 15 minutes after initial compromise",
		fmt.Sprintf("Recommended investigation workflow: %s", workflow.PrimaryTool),
	)
	if workflow.NeedsAttack {
		response.Findings = append(response.Findings,
			"If additional evidence is collected, use attack_reason after the initial incident assessment to refine attacker technique ranking",
		)
	}

	response.Alerts = append(response.Alerts,
		"CRITICAL: Active breach in progress",
		"WARNING: Lateral movement detected",
	)

	response.Action = fmt.Sprintf("Run %s as the next step, isolate affected systems, and initiate incident response", workflow.PrimaryTool)

	response.Recommendations = append(response.Recommendations,
		fmt.Sprintf("Start with %s to produce a consolidated assessment and containment advice", workflow.PrimaryTool),
		"Isolate compromised systems immediately",
		"Preserve forensic evidence",
		"Notify affected users within 72 hours",
		"Conduct post-incident review",
		"Implement additional monitoring",
	)
	if workflow.NeedsAttack {
		response.Recommendations = append(response.Recommendations,
			"Use attack_reason to validate ATT&CK technique hypotheses before broader eradication actions",
		)
	}

	response.NextSteps = append(response.NextSteps,
		fmt.Sprintf("Run %s with all available evidence sources", workflow.PrimaryTool),
		"Establish incident command center",
		"Begin forensic analysis",
		"Coordinate with law enforcement",
		"Prepare customer notification",
	)
	if workflow.NeedsAttack {
		response.NextSteps = append(response.NextSteps,
			"Run attack_reason if you need deeper ATT&CK ranking after the consolidated assessment",
		)
	}

	return response
}

func (a *SecurityExpertAgent) selectSecurityWorkflow(task *AgentTask) securityWorkflowPlan {
	plan := securityWorkflowPlan{
		PrimaryTool: "attack_reason",
		NeedsAttack: true,
		Reason:      "ATT&CK mapping is the primary need",
	}

	if task == nil {
		return plan
	}

	if task.Type == "incident_response" {
		plan.PrimaryTool = "incident_assess"
		plan.Reason = "incident response benefits from a consolidated assessment with containment advice"
		return plan
	}

	if task.Type == "threat_assessment" {
		plan.PrimaryTool = "incident_assess"
		plan.Reason = "threat assessment should first correlate alerts, logs, timelines, and access evidence"
	}

	if metadataSuggestsEvidenceCorrelation(task.Metadata) {
		plan.PrimaryTool = "incident_assess"
		plan.Reason = "task metadata indicates multi-source evidence that should be consolidated first"
	}

	return plan
}

func metadataSuggestsEvidenceCorrelation(metadata map[string]interface{}) bool {
	if len(metadata) == 0 {
		return false
	}

	keys := []string{
		"alert_result",
		"log_analyze_result",
		"timeline_result",
		"access_review_result",
		"events",
		"evidence",
	}
	for _, key := range keys {
		if _, ok := metadata[key]; ok {
			return true
		}
	}

	for key, value := range metadata {
		if containsEvidenceKeyword(key) {
			return true
		}
		if text, ok := value.(string); ok && containsEvidenceKeyword(text) {
			return true
		}
	}

	return false
}

func containsEvidenceKeyword(value string) bool {
	value = strings.ToLower(value)
	keywords := []string{"alert", "log", "timeline", "access", "evidence", "ioc", "incident"}
	for _, keyword := range keywords {
		if strings.Contains(value, keyword) {
			return true
		}
	}
	return false
}

// HasCapability 检查能力
func (a *SecurityExpertAgent) HasCapability(cap AgentCapability) bool {
	for _, c := range a.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// GetState 获取状态
func (a *SecurityExpertAgent) GetState() AgentState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.State
}

// UpdateKnowledge 更新知识库
func (a *SecurityExpertAgent) UpdateKnowledge(key string, value interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Knowledge[key] = value
}
