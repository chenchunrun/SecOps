package agent

import (
	"strings"
	"testing"
	"time"
)

func TestOpsAgent_NewOpsAgent(t *testing.T) {
	agent := NewOpsAgent("ops-1")

	if agent.ID != "ops-1" {
		t.Errorf("expected ID 'ops-1', got %s", agent.ID)
	}

	if agent.Role != RoleOpsAgent {
		t.Errorf("expected role %s, got %s", RoleOpsAgent, agent.Role)
	}

	if len(agent.Capabilities) == 0 {
		t.Error("expected capabilities to be set")
	}

	if agent.State.Status != "ready" {
		t.Errorf("expected status 'ready', got %s", agent.State.Status)
	}
}

func TestOpsAgent_HasCapability(t *testing.T) {
	agent := NewOpsAgent("ops-1")

	if !agent.HasCapability(CapLogAnalysis) {
		t.Error("expected agent to have log analysis capability")
	}

	if !agent.HasCapability(CapMonitoring) {
		t.Error("expected agent to have monitoring capability")
	}

	if agent.HasCapability(CapVulnScan) {
		t.Error("expected agent to not have vulnerability scanning capability")
	}
}

func TestOpsAgent_ProcessTask_Incident(t *testing.T) {
	agent := NewOpsAgent("ops-1")

	task := &AgentTask{
		ID:        "task-1",
		Title:     "Handle Server Outage",
		Type:      "incident",
		Priority:  "critical",
		Severity:  "critical",
		CreatedAt: time.Now(),
	}

	response := agent.ProcessTask(task)

	if response.Status != "completed" {
		t.Errorf("expected status 'completed', got %s", response.Status)
	}

	if task.AssignedTo != agent.ID {
		t.Errorf("expected task assigned to %s", agent.ID)
	}

	if len(response.Findings) == 0 {
		t.Error("expected findings in response")
	}

	if len(response.Recommendations) == 0 {
		t.Error("expected recommendations in response")
	}
}

func TestOpsAgent_ProcessTask_Investigation(t *testing.T) {
	agent := NewOpsAgent("ops-1")

	task := &AgentTask{
		ID:        "task-2",
		Title:     "Investigate Performance Degradation",
		Type:      "investigation",
		Priority:  "high",
		CreatedAt: time.Now(),
	}

	response := agent.ProcessTask(task)

	if response.Status != "completed" {
		t.Errorf("expected status 'completed', got %s", response.Status)
	}

	if response.ConfidenceScore <= 0 || response.ConfidenceScore > 1 {
		t.Errorf("expected confidence score between 0-1, got %f", response.ConfidenceScore)
	}
}

func TestOpsAgent_ProcessTask_Audit(t *testing.T) {
	agent := NewOpsAgent("ops-1")

	task := &AgentTask{
		ID:        "task-3",
		Title:     "SOC2 Compliance Audit",
		Type:      "audit",
		CreatedAt: time.Now(),
	}

	response := agent.ProcessTask(task)

	if response.Status != "completed" {
		t.Errorf("expected status 'completed', got %s", response.Status)
	}

	if len(response.Alerts) == 0 {
		t.Error("expected alerts in audit response")
	}
}

func TestOpsAgent_ProcessTask_Diagnostic(t *testing.T) {
	agent := NewOpsAgent("ops-1")

	task := &AgentTask{
		ID:        "task-4",
		Title:     "Network Diagnostic",
		Type:      "diagnostic",
		CreatedAt: time.Now(),
	}

	response := agent.ProcessTask(task)

	if response.Status != "completed" {
		t.Errorf("expected status 'completed', got %s", response.Status)
	}

	if response.ResponseTime < 0 {
		t.Error("expected non-negative response time")
	}
}

func TestOpsAgent_ProcessTask_UnknownType(t *testing.T) {
	agent := NewOpsAgent("ops-1")

	task := &AgentTask{
		ID:        "task-5",
		Title:     "Unknown Task",
		Type:      "unknown_type",
		CreatedAt: time.Now(),
	}

	response := agent.ProcessTask(task)

	if response.Status != "failed" {
		t.Errorf("expected status 'failed', got %s", response.Status)
	}

	if response.Error == "" {
		t.Error("expected error message")
	}
}

func TestOpsAgent_GetState(t *testing.T) {
	agent := NewOpsAgent("ops-1")

	state := agent.GetState()

	if state.Status != "ready" {
		t.Errorf("expected status 'ready', got %s", state.Status)
	}

	if state.CompletedTasks != 0 {
		t.Errorf("expected 0 completed tasks, got %d", state.CompletedTasks)
	}
}

func TestOpsAgent_UpdateKnowledge(t *testing.T) {
	agent := NewOpsAgent("ops-1")

	agent.UpdateKnowledge("server_config", map[string]string{
		"cpu":    "16 cores",
		"memory": "32GB",
	})

	if _, exists := agent.Knowledge["server_config"]; !exists {
		t.Error("expected knowledge to be updated")
	}
}

func TestSecurityExpertAgent_NewSecurityExpertAgent(t *testing.T) {
	agent := NewSecurityExpertAgent("sec-1")

	if agent.ID != "sec-1" {
		t.Errorf("expected ID 'sec-1', got %s", agent.ID)
	}

	if agent.Role != RoleSecurityAgent {
		t.Errorf("expected role %s, got %s", RoleSecurityAgent, agent.Role)
	}

	if !agent.HasCapability(CapVulnScan) {
		t.Error("expected agent to have vulnerability scanning capability")
	}
}

func TestSecurityExpertAgent_ProcessTask_VulnerabilityScan(t *testing.T) {
	agent := NewSecurityExpertAgent("sec-1")

	task := &AgentTask{
		ID:        "task-1",
		Title:     "Full Vulnerability Scan",
		Type:      "vulnerability_scan",
		Priority:  "high",
		CreatedAt: time.Now(),
	}

	response := agent.ProcessTask(task)

	if response.Status != "completed" {
		t.Errorf("expected status 'completed', got %s", response.Status)
	}

	if len(response.Findings) == 0 {
		t.Error("expected findings in vulnerability scan response")
	}

	if len(response.Alerts) == 0 {
		t.Error("expected alerts for vulnerabilities")
	}

	if task.AssignedTo != agent.ID {
		t.Error("expected task to be assigned to agent")
	}
}

func TestSecurityExpertAgent_ProcessTask_SecurityAudit(t *testing.T) {
	agent := NewSecurityExpertAgent("sec-1")

	task := &AgentTask{
		ID:        "task-2",
		Title:     "Security Control Audit",
		Type:      "security_audit",
		CreatedAt: time.Now(),
	}

	response := agent.ProcessTask(task)

	if response.Status != "completed" {
		t.Errorf("expected status 'completed', got %s", response.Status)
	}

	if len(response.Recommendations) == 0 {
		t.Error("expected recommendations in security audit")
	}
}

func TestSecurityExpertAgent_ProcessTask_ThreatAssessment(t *testing.T) {
	agent := NewSecurityExpertAgent("sec-1")

	task := &AgentTask{
		ID:        "task-3",
		Title:     "Threat Assessment",
		Type:      "threat_assessment",
		Priority:  "high",
		CreatedAt: time.Now(),
	}

	response := agent.ProcessTask(task)

	if response.Status != "completed" {
		t.Errorf("expected status 'completed', got %s", response.Status)
	}

	if response.ConfidenceScore <= 0 {
		t.Error("expected positive confidence score")
	}

	if response.Action != "Run incident_assess as the next investigation step, then implement the immediate remediation plan" {
		t.Fatalf("expected incident_assess workflow action, got %q", response.Action)
	}

	if len(response.NextSteps) == 0 || response.NextSteps[0] != "Run incident_assess with available alert, log, timeline, and access evidence" {
		t.Fatalf("expected incident_assess as the first next step, got %#v", response.NextSteps)
	}

	if response.WorkflowSummary == nil {
		t.Fatal("expected workflow summary in threat assessment response")
	}

	if response.WorkflowSummary.PrimaryTool != "incident_assess" {
		t.Fatalf("expected workflow primary tool incident_assess, got %q", response.WorkflowSummary.PrimaryTool)
	}

	if len(response.WorkflowSummary.FollowupTools) == 0 || response.WorkflowSummary.FollowupTools[0] != "attack_reason" {
		t.Fatalf("expected attack_reason follow-up tool, got %#v", response.WorkflowSummary.FollowupTools)
	}

	if response.WorkflowSummary.Status != "recommended only; ProcessTask did not execute the tools" {
		t.Fatalf("expected recommended-only workflow status, got %q", response.WorkflowSummary.Status)
	}
}

func TestSecurityExpertAgent_ProcessTask_IncidentResponse(t *testing.T) {
	agent := NewSecurityExpertAgent("sec-1")

	task := &AgentTask{
		ID:        "task-4",
		Title:     "Security Incident Response",
		Type:      "incident_response",
		Priority:  "critical",
		Severity:  "critical",
		CreatedAt: time.Now(),
	}

	response := agent.ProcessTask(task)

	if response.Status != "completed" {
		t.Errorf("expected status 'completed', got %s", response.Status)
	}

	if len(response.NextSteps) == 0 {
		t.Error("expected next steps in incident response")
	}

	if response.Action != "Run incident_assess as the next step, isolate affected systems, and initiate incident response" {
		t.Fatalf("expected incident_assess workflow action, got %q", response.Action)
	}

	if response.NextSteps[0] != "Run incident_assess with all available evidence sources" {
		t.Fatalf("expected incident_assess as the first next step, got %#v", response.NextSteps)
	}

	if response.WorkflowSummary == nil {
		t.Fatal("expected workflow summary in incident response")
	}

	if len(response.WorkflowSummary.ContainmentFocus) == 0 {
		t.Fatal("expected containment focus in incident response summary")
	}

	if response.WorkflowSummary.Status != "recommended only; ProcessTask did not execute the tools" {
		t.Fatalf("expected recommended-only workflow status, got %q", response.WorkflowSummary.Status)
	}
}

func TestSecurityExpertAgent_selectSecurityWorkflow_MetadataEvidence(t *testing.T) {
	agent := NewSecurityExpertAgent("sec-1")

	task := &AgentTask{
		ID:        "task-5",
		Title:     "Threat Assessment With Evidence",
		Type:      "threat_assessment",
		CreatedAt: time.Now(),
		Metadata: map[string]interface{}{
			"alert_result": map[string]interface{}{"summary": "suspicious login burst"},
		},
	}

	workflow := agent.selectSecurityWorkflow(task)
	if workflow.PrimaryTool != "incident_assess" {
		t.Fatalf("expected incident_assess primary tool, got %q", workflow.PrimaryTool)
	}
}

func TestAgentResponse_RenderWorkflowSummary(t *testing.T) {
	response := &AgentResponse{
		WorkflowSummary: &SecurityWorkflowSummary{
			PrimaryTool:      "incident_assess",
			FollowupTools:    []string{"attack_reason"},
			EvidenceSources:  []string{"alert_check", "log_analyze"},
			ContainmentFocus: []string{"isolate compromised systems", "preserve forensic evidence"},
			Status:           "recommended only; ProcessTask did not execute the tools",
			Reason:           "incident response benefits from a consolidated assessment with containment advice",
		},
	}

	rendered := response.RenderWorkflowSummary()
	if rendered == "" {
		t.Fatal("expected rendered workflow summary")
	}

	expected := []string{
		"Recommended Tool: incident_assess",
		"Recommended Follow-up Tools: attack_reason",
		"Workflow Status: recommended only; ProcessTask did not execute the tools",
		"Evidence Sources: alert_check, log_analyze",
		"Containment Focus: isolate compromised systems; preserve forensic evidence",
	}
	for _, fragment := range expected {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected rendered summary to contain %q, got %q", fragment, rendered)
		}
	}
}

func TestAgentResponse_RenderSecurityAssessment(t *testing.T) {
	response := &AgentResponse{
		Action:          "Run incident_assess, isolate affected systems, and initiate incident response",
		Reasoning:       "Analyzing security incident and containing threat using incident_assess",
		ConfidenceScore: 0.91,
		Alerts:          []string{"CRITICAL: Active breach in progress"},
		Findings:        []string{"Incident: Unauthorized access to user database"},
		Recommendations: []string{"Isolate compromised systems immediately"},
		NextSteps:       []string{"Run incident_assess with all available evidence sources"},
		WorkflowSummary: &SecurityWorkflowSummary{
			PrimaryTool:      "incident_assess",
			FollowupTools:    []string{"attack_reason"},
			EvidenceSources:  []string{"alert_check", "log_analyze"},
			ContainmentFocus: []string{"isolate compromised systems"},
			Status:           "recommended only; ProcessTask did not execute the tools",
			Reason:           "incident response benefits from a consolidated assessment with containment advice",
		},
	}

	rendered := response.RenderSecurityAssessment()
	expected := []string{
		"Action: Run incident_assess, isolate affected systems, and initiate incident response",
		"Workflow Summary:",
		"Recommended Tool: incident_assess",
		"Alerts: CRITICAL: Active breach in progress",
		"Findings: Incident: Unauthorized access to user database",
		"Recommendations: Isolate compromised systems immediately",
	}
	for _, fragment := range expected {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected rendered assessment to contain %q, got %q", fragment, rendered)
		}
	}
}

func TestSecurityExpertAgent_TaskStatistics(t *testing.T) {
	agent := NewSecurityExpertAgent("sec-1")

	// Process multiple tasks
	for i := 0; i < 3; i++ {
		task := &AgentTask{
			ID:        "task-" + string(rune(i)),
			Type:      "vulnerability_scan",
			CreatedAt: time.Now(),
		}
		agent.ProcessTask(task)
	}

	state := agent.GetState()

	if state.CompletedTasks != 3 {
		t.Errorf("expected 3 completed tasks, got %d", state.CompletedTasks)
	}

	if state.LastActivity.IsZero() {
		t.Error("expected last activity to be set")
	}
}

func TestAgent_CapabilityList(t *testing.T) {
	opsAgent := NewOpsAgent("ops-1")
	secAgent := NewSecurityExpertAgent("sec-1")

	// Verify OpsAgent capabilities
	expectedOpsCaps := []AgentCapability{
		CapLogAnalysis, CapMonitoring, CapCompliance, CapNetworkDiag, CapRiskAssess,
	}

	for _, cap := range expectedOpsCaps {
		if !opsAgent.HasCapability(cap) {
			t.Errorf("OpsAgent missing capability: %s", cap)
		}
	}

	// Verify SecurityExpertAgent capabilities
	expectedSecCaps := []AgentCapability{
		CapVulnScan, CapCertAudit, CapConfigAudit, CapRiskAssess, CapIncidentResp,
	}

	for _, cap := range expectedSecCaps {
		if !secAgent.HasCapability(cap) {
			t.Errorf("SecurityExpertAgent missing capability: %s", cap)
		}
	}
}

func BenchmarkOpsAgent_ProcessTask(b *testing.B) {
	agent := NewOpsAgent("ops-1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		task := &AgentTask{
			ID:        "task",
			Type:      "incident",
			CreatedAt: time.Now(),
		}
		agent.ProcessTask(task)
	}
}

func BenchmarkSecurityExpertAgent_ProcessTask(b *testing.B) {
	agent := NewSecurityExpertAgent("sec-1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		task := &AgentTask{
			ID:        "task",
			Type:      "vulnerability_scan",
			CreatedAt: time.Now(),
		}
		agent.ProcessTask(task)
	}
}
