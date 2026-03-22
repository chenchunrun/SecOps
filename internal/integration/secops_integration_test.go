package integration

import (
	"testing"
	"time"

	"github.com/chenchunrun/SecOps/internal/agent"
	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/security"
)

// TestSecuritySystemIntegration_IncidentResponse 测试完整的安全事件响应流程
func TestSecuritySystemIntegration_IncidentResponse(t *testing.T) {
	// 1. 初始化系统组件
	registry := secops.NewToolRegistry()
	auditStore := audit.NewInMemoryAuditStore()
	securityAgent := agent.NewSecurityExpertAgent("sec-1")
	opsAgent := agent.NewOpsAgent("ops-1")

	// 注册安全扫描工具
	scanTool := secops.NewSecurityScanTool(registry)
	registry.Register(scanTool)

	// 2. 检测安全事件
	event := &audit.AuditEvent{
		EventType:    audit.EventTypeSecurityAlert,
		UserID:       "unknown",
		Username:     "attacker",
		SourceIP:     "192.168.1.100",
		Action:       "unauthorized_access",
		ResourceType: "database",
		ResourceName: "users_db",
		Result:       audit.ResultDenied,
		RiskScore:    90,
		RiskLevel:    "critical",
		Timestamp:    time.Now(),
	}

	auditStore.SaveEvent(event)

	// 3. 触发安全事件响应
	securityTask := &agent.AgentTask{
		ID:        "incident-1",
		Title:     "Unauthorized Database Access Detected",
		Type:      "incident_response",
		Priority:  "critical",
		Severity:  "critical",
		CreatedAt: time.Now(),
	}

	secResponse := securityAgent.ProcessTask(securityTask)

	if secResponse.Status != "completed" {
		t.Errorf("expected security response to be completed, got %s", secResponse.Status)
	}

	if len(secResponse.Findings) == 0 {
		t.Error("expected security findings")
	}

	if len(secResponse.Recommendations) == 0 {
		t.Error("expected security recommendations")
	}

	// 4. 生成审计报告
	reportGenerator := audit.NewComplianceReportGenerator(auditStore)
	now := time.Now()
	report, err := reportGenerator.GenerateReport(
		audit.FrameworkSOC2,
		now.Add(-24*time.Hour),
		now,
	)

	if err != nil {
		t.Fatalf("GenerateReport() error = %v", err)
	}

	if report.TotalEvents == 0 {
		t.Error("expected audit events in report")
	}

	if report.CriticalRiskEvents == 0 {
		t.Error("expected critical risk events to be detected")
	}

	// 5. 验证完整流程
	if securityTask.Status != "completed" {
		t.Error("expected security task to be completed")
	}

	if opsAgent.GetState().CompletedTasks == 0 && securityAgent.GetState().CompletedTasks == 0 {
		t.Error("expected at least one completed task")
	}
}

// TestComplianceFramework_Audit 测试合规审计框架
func TestComplianceFramework_Audit(t *testing.T) {
	// 初始化系统
	auditStore := audit.NewInMemoryAuditStore()
	opsAgent := agent.NewOpsAgent("ops-1")

	// 创建审计任务
	auditTask := &agent.AgentTask{
		ID:        "audit-1",
		Title:     "PCI-DSS Compliance Audit",
		Type:      "audit",
		CreatedAt: time.Now(),
	}

	// 运维代理执行审计
	response := opsAgent.ProcessTask(auditTask)

	if response.Status != "completed" {
		t.Errorf("expected audit to be completed, got %s", response.Status)
	}

	// 添加审计事件
	auditEvent := &audit.AuditEvent{
		EventType:    audit.EventTypeConfigChange,
		Action:       "firewall_rule_update",
		ResourceType: "firewall",
		Result:       audit.ResultSuccess,
		RiskScore:    20,
		RiskLevel:    "low",
		Timestamp:    time.Now(),
		Details: map[string]interface{}{
			"framework": "pci_dss",
			"control":   "firewall_001",
		},
	}

	auditStore.SaveEvent(auditEvent)

	// 生成合规报告
	reportGen := audit.NewComplianceReportGenerator(auditStore)
	now := time.Now()
	report, err := reportGen.GenerateReport(
		audit.FrameworkPCIDSS,
		now.Add(-24*time.Hour),
		now,
	)

	if err != nil {
		t.Fatalf("error generating compliance report: %v", err)
	}

	if report.Framework != audit.FrameworkPCIDSS {
		t.Errorf("expected PCI-DSS framework, got %s", report.Framework)
	}
}

// TestVulnerabilityScanAndResponse 测试漏洞扫描和响应
func TestVulnerabilityScanAndResponse(t *testing.T) {
	// 初始化系统
	registry := secops.NewToolRegistry()
	auditStore := audit.NewInMemoryAuditStore()
	securityAgent := agent.NewSecurityExpertAgent("sec-1")

	// 注册漏洞扫描工具
	scanTool := secops.NewSecurityScanTool(registry)
	registry.Register(scanTool)

	// 创建漏洞扫描任务
	scanTask := &agent.AgentTask{
		ID:        "scan-1",
		Title:     "Full Vulnerability Scan",
		Type:      "vulnerability_scan",
		CreatedAt: time.Now(),
	}

	// 执行扫描
	response := securityAgent.ProcessTask(scanTask)

	if response.Status != "completed" {
		t.Errorf("expected scan to complete, got %s", response.Status)
	}

	if len(response.Findings) == 0 {
		t.Error("expected vulnerability findings")
	}

	// 记录扫描事件
	scanEvent := &audit.AuditEvent{
		EventType:    audit.EventTypeSecurityAlert,
		Action:       "vulnerability_scan",
		ResourceType: "system",
		Result:       audit.ResultSuccess,
		RiskScore:    45,
		RiskLevel:    "medium",
		Timestamp:    time.Now(),
	}

	auditStore.SaveEvent(scanEvent)

	// 验证扫描结果已记录
	count, err := auditStore.CountEvents(&audit.AuditFilter{
		Action: "vulnerability_scan",
	})

	if err != nil {
		t.Fatalf("error counting events: %v", err)
	}

	if count == 0 {
		t.Error("expected scan event to be recorded")
	}
}

// TestCapabilityManagement 测试能力管理
func TestCapabilityManagement(t *testing.T) {
	// 初始化能力管理器
	capMgr := security.NewCapabilityManager()
	capMgr.SetRoleHierarchy("viewer", "operator")
	capMgr.SetRoleHierarchy("operator", "admin")

	// 验证层级关系已建立
	// 观看者应该有某些能力（通过父关系可获得）
	// 操作员应该有更多能力（继承观看者的能力）
	// 管理员应该有最多能力

	// 设置观看者的能力策略
	viewerCaps := []*security.Capability{
		{Name: security.CapabilityLogRead, Pattern: security.CapabilityLogRead},
	}

	viewerPolicy := &security.CapabilityPolicy{
		Role:         "viewer",
		Capabilities: viewerCaps,
	}

	if err := capMgr.SetRolePolicy(viewerPolicy); err != nil {
		t.Errorf("error setting viewer policy: %v", err)
	}

	// 验证操作员有观看者的能力（继承）
	operatorCaps := []*security.Capability{
		{Name: security.CapabilityLogRead, Pattern: security.CapabilityLogRead},
		{Name: security.CapabilityFileWrite, Pattern: security.CapabilityFileWrite},
	}

	operatorPolicy := &security.CapabilityPolicy{
		Role:         "operator",
		Capabilities: operatorCaps,
	}

	if err := capMgr.SetRolePolicy(operatorPolicy); err != nil {
		t.Errorf("error setting operator policy: %v", err)
	}

	// 验证策略已设置成功
	allRoles := capMgr.GetCapabilitiesForRole("operator")
	if len(allRoles) == 0 {
		t.Error("expected operator to have capabilities")
	}
}

// TestRiskAssessmentIntegration 测试风险评估集成
func TestRiskAssessmentIntegration(t *testing.T) {
	// 初始化风险评估器
	assessor := security.NewRiskAssessor()

	// 评估一个命令
	command := "/bin/rm -rf /etc/passwd"
	assessment := assessor.AssessCommand(command)

	if assessment.Level == "" {
		t.Error("expected risk level to be set")
	}

	if assessment.Score == 0 {
		t.Error("expected risk score to be calculated")
	}

	if assessment.Action == "" {
		t.Error("expected action to be recommended")
	}

	// 评估权限请求
	cmd := "log_analyze"
	resource := "/var/log/auth.log"

	assessment2 := assessor.AssessPermissionRequest(cmd, resource)

	if assessment2.Level == "" {
		t.Error("expected risk level for permission request")
	}

	if assessment2.Score < 0 || assessment2.Score > 100 {
		t.Errorf("expected score between 0-100, got %d", assessment2.Score)
	}
}

// TestMultiAgentCoordination 测试多代理协调
func TestMultiAgentCoordination(t *testing.T) {
	// 创建多个代理
	opsAgent := agent.NewOpsAgent("ops-1")
	securityAgent := agent.NewSecurityExpertAgent("sec-1")
	auditStore := audit.NewInMemoryAuditStore()

	// 模拟多代理场景
	// 1. 运维代理检测到性能问题
	opsTask := &agent.AgentTask{
		ID:        "task-1",
		Title:     "High Memory Usage",
		Type:      "incident",
		Priority:  "high",
		CreatedAt: time.Now(),
	}

	opsResponse := opsAgent.ProcessTask(opsTask)

	if opsResponse.Status != "completed" {
		t.Error("expected ops task to complete")
	}

	// 2. 安全代理检查是否有安全含义
	secTask := &agent.AgentTask{
		ID:        "task-2",
		Title:     "Security Check on Memory Issue",
		Type:      "threat_assessment",
		CreatedAt: time.Now(),
	}

	secResponse := securityAgent.ProcessTask(secTask)

	if secResponse.Status != "completed" {
		t.Error("expected security task to complete")
	}

	// 3. 记录两个代理的结果
	for i, response := range []*agent.AgentResponse{opsResponse, secResponse} {
		event := &audit.AuditEvent{
			EventType:    audit.EventTypeCommandExecuted,
			Action:       "agent_response",
			ResourceType: "agent",
			ResourceName: string(response.AgentRole),
			Result:       audit.ResultSuccess,
			RiskScore:    int(response.ConfidenceScore * 100),
			Timestamp:    time.Now(),
		}

		auditStore.SaveEvent(event)

		if event.ID == "" {
			t.Errorf("expected event %d to have ID", i)
		}
	}

	// 验证协调结果
	count, _ := auditStore.CountEvents(&audit.AuditFilter{
		Action: "agent_response",
	})

	if count != 2 {
		t.Errorf("expected 2 agent response events, got %d", count)
	}
}

// TestToolRegistryAndExecution 测试工具注册和执行
func TestToolRegistryAndExecution(t *testing.T) {
	registry := secops.NewToolRegistry()

	// 注册多个工具
	toolInstances := []secops.SecOpsTool{
		secops.NewLogAnalyzeTool(registry),
		secops.NewMonitoringQueryTool(registry),
		secops.NewComplianceCheckTool(registry),
		secops.NewCertificateAuditTool(registry),
		secops.NewSecurityScanTool(registry),
		secops.NewConfigurationAuditTool(registry),
		secops.NewNetworkDiagnosticTool(registry),
	}

	for _, tool := range toolInstances {
		err := registry.Register(tool)
		if err != nil {
			t.Errorf("error registering tool %s: %v", tool.Name(), err)
		}
	}

	// 验证工具注册
	allTools := registry.List()
	if len(allTools) != 7 {
		t.Errorf("expected 7 tools registered, got %d", len(allTools))
	}

	// 检查特定工具
	secScanTool := secops.NewSecurityScanTool(registry)
	if tool, exists := registry.Get(secScanTool.Type()); !exists {
		t.Error("expected SecurityScanTool to be registered")
	} else {
		if tool.Name() != "Security Scan" {
			t.Errorf("expected tool name 'Security Scan', got %s", tool.Name())
		}
	}
}

// TestEndToEndSecurityIncident 端到端安全事件处理
func TestEndToEndSecurityIncident(t *testing.T) {
	// 1. 初始化所有系统组件
	registry := secops.NewToolRegistry()
	auditStore := audit.NewInMemoryAuditStore()
	reportGen := audit.NewComplianceReportGenerator(auditStore)
	opsAgent := agent.NewOpsAgent("ops-1")
	securityAgent := agent.NewSecurityExpertAgent("sec-1")

	// 2. 注册工具
	registry.Register(secops.NewSecurityScanTool(registry))

	// 3. 事件流
	// Step 1: 检测到可疑活动
	suspiciousEvent := &audit.AuditEvent{
		EventType:    audit.EventTypeSecurityAlert,
		UserID:       "user123",
		Username:     "suspected_user",
		Action:       "suspicious_api_call",
		Result:       audit.ResultDenied,
		RiskScore:    85,
		RiskLevel:    "critical",
		Timestamp:    time.Now(),
	}

	auditStore.SaveEvent(suspiciousEvent)

	// Step 2: 安全代理分析事件
	incidentTask := &agent.AgentTask{
		ID:        "incident-final",
		Title:     "Security Incident: Suspicious Activity",
		Type:      "incident_response",
		Priority:  "critical",
		Severity:  "critical",
		CreatedAt: time.Now(),
	}

	incidentResponse := securityAgent.ProcessTask(incidentTask)

	// Step 3: 运维代理采取行动
	remediationTask := &agent.AgentTask{
		ID:        "remediation-1",
		Title:     "Implement Security Controls",
		Type:      "investigation",
		CreatedAt: time.Now(),
	}

	remediationResponse := opsAgent.ProcessTask(remediationTask)

	// Step 4: 记录所有活动
	remediationEvent := &audit.AuditEvent{
		EventType:    audit.EventTypeCommandExecuted,
		Action:       "remediation",
		ResourceType: "security_control",
		Result:       audit.ResultSuccess,
		RiskScore:    10,
		RiskLevel:    "low",
		Timestamp:    time.Now(),
	}

	auditStore.SaveEvent(remediationEvent)

	// Step 5: 生成最终报告
	now := time.Now()
	finalReport, err := reportGen.GenerateReport(
		audit.FrameworkSOC2,
		now.Add(-24*time.Hour),
		now,
	)

	if err != nil {
		t.Fatalf("error generating final report: %v", err)
	}

	// 验证完整流程
	if incidentResponse.Status != "completed" {
		t.Error("incident response should be completed")
	}

	if remediationResponse.Status != "completed" {
		t.Error("remediation response should be completed")
	}

	if finalReport.TotalEvents < 2 {
		t.Error("expected at least 2 events in final report")
	}

	if len(finalReport.SuspiciousEvents) == 0 {
		t.Error("expected suspicious events to be identified")
	}

	if finalReport.ComplianceStatus == "" {
		t.Error("expected compliance status in final report")
	}
}

// BenchmarkIntegration_IncidentResponse 基准测试：事件响应
func BenchmarkIntegration_IncidentResponse(b *testing.B) {
	auditStore := audit.NewInMemoryAuditStore()
	securityAgent := agent.NewSecurityExpertAgent("sec-1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		task := &agent.AgentTask{
			ID:   "task",
			Type: "incident_response",
		}
		securityAgent.ProcessTask(task)

		event := &audit.AuditEvent{
			EventType: audit.EventTypeSecurityAlert,
			RiskScore: 80,
		}
		auditStore.SaveEvent(event)
	}
}

// BenchmarkIntegration_ComplianceReporting 基准测试：合规报告
func BenchmarkIntegration_ComplianceReporting(b *testing.B) {
	auditStore := audit.NewInMemoryAuditStore()

	// 预填充事件
	for i := 0; i < 1000; i++ {
		event := &audit.AuditEvent{
			EventType: audit.EventTypeCommandExecuted,
			RiskScore: 20,
		}
		auditStore.SaveEvent(event)
	}

	reportGen := audit.NewComplianceReportGenerator(auditStore)
	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reportGen.GenerateReport(
			audit.FrameworkSOC2,
			now.Add(-24*time.Hour),
			now,
		)
	}
}
