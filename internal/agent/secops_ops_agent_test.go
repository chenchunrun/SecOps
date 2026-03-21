package agent

import (
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
		ID:          "task-1",
		Title:       "Handle Server Outage",
		Type:        "incident",
		Priority:    "critical",
		Severity:    "critical",
		CreatedAt:   time.Now(),
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
		"cpu": "16 cores",
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
