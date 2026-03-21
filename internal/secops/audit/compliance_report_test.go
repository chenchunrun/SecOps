package audit

import (
	"testing"
	"time"
)

func TestComplianceReportGenerator_GenerateReport_Empty(t *testing.T) {
	store := NewInMemoryAuditStore()
	generator := NewComplianceReportGenerator(store)

	startTime := time.Now().Add(-24 * time.Hour)
	endTime := time.Now()

	report, err := generator.GenerateReport(FrameworkSOC2, startTime, endTime)
	if err != nil {
		t.Errorf("GenerateReport() error = %v", err)
	}

	if report.ComplianceStatus != "pass" {
		t.Errorf("expected compliance status 'pass' for empty audit log, got %s", report.ComplianceStatus)
	}

	if report.ComplianceScore != 100 {
		t.Errorf("expected compliance score 100, got %f", report.ComplianceScore)
	}
}

func TestComplianceReportGenerator_GenerateReport_WithEvents(t *testing.T) {
	store := NewInMemoryAuditStore()
	generator := NewComplianceReportGenerator(store)

	now := time.Now()
	startTime := now.Add(-24 * time.Hour)
	endTime := now

	// 添加成功的事件
	for i := 0; i < 8; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandExecuted,
			Result:    ResultSuccess,
			UserID:    "user1",
			Username:  "alice",
			RiskScore: 10,
			RiskLevel: "low",
			Timestamp: now,
		}
		store.SaveEvent(event)
	}

	// 添加失败的事件
	for i := 0; i < 2; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandFailed,
			Result:    ResultFailure,
			UserID:    "user2",
			Username:  "bob",
			RiskScore: 30,
			RiskLevel: "medium",
			Timestamp: now,
		}
		store.SaveEvent(event)
	}

	report, err := generator.GenerateReport(FrameworkSOC2, startTime, endTime)
	if err != nil {
		t.Errorf("GenerateReport() error = %v", err)
	}

	if report.TotalEvents != 10 {
		t.Errorf("expected 10 total events, got %d", report.TotalEvents)
	}

	if report.SuccessfulEvents != 8 {
		t.Errorf("expected 8 successful events, got %d", report.SuccessfulEvents)
	}

	if report.FailedEvents != 2 {
		t.Errorf("expected 2 failed events, got %d", report.FailedEvents)
	}

	if report.ComplianceScore <= 0 {
		t.Errorf("expected positive compliance score, got %f", report.ComplianceScore)
	}
}

func TestComplianceReportGenerator_GenerateReport_HighRiskEvents(t *testing.T) {
	store := NewInMemoryAuditStore()
	generator := NewComplianceReportGenerator(store)

	now := time.Now()
	startTime := now.Add(-24 * time.Hour)
	endTime := now

	// 添加高风险事件
	event := &AuditEvent{
		EventType: EventTypeSecurityAlert,
		Result:    ResultFailure,
		UserID:    "attacker",
		RiskScore: 95,
		RiskLevel: "critical",
		Timestamp: now,
	}
	store.SaveEvent(event)

	report, err := generator.GenerateReport(FrameworkSOC2, startTime, endTime)
	if err != nil {
		t.Errorf("GenerateReport() error = %v", err)
	}

	if report.CriticalRiskEvents != 1 {
		t.Errorf("expected 1 critical risk event, got %d", report.CriticalRiskEvents)
	}

	if report.ComplianceStatus != "fail" {
		t.Errorf("expected compliance status 'fail', got %s", report.ComplianceStatus)
	}

	if len(report.SuspiciousEvents) == 0 {
		t.Error("expected suspicious events to be detected")
	}
}

func TestComplianceReportGenerator_UserActivity(t *testing.T) {
	store := NewInMemoryAuditStore()
	generator := NewComplianceReportGenerator(store)

	now := time.Now()
	startTime := now.Add(-24 * time.Hour)
	endTime := now

	// 添加多个用户的事件
	for i := 0; i < 5; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandExecuted,
			UserID:    "user1",
			Username:  "alice",
			Result:    ResultSuccess,
			Timestamp: now,
		}
		store.SaveEvent(event)
	}

	for i := 0; i < 3; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandExecuted,
			UserID:    "user2",
			Username:  "bob",
			Result:    ResultSuccess,
			Timestamp: now,
		}
		store.SaveEvent(event)
	}

	report, err := generator.GenerateReport(FrameworkSOC2, startTime, endTime)
	if err != nil {
		t.Errorf("GenerateReport() error = %v", err)
	}

	if report.UniqueUsers != 2 {
		t.Errorf("expected 2 unique users, got %d", report.UniqueUsers)
	}

	if len(report.TopUsers) == 0 {
		t.Error("expected top users to be generated")
	}

	// 验证排序
	if len(report.TopUsers) > 1 {
		if report.TopUsers[0].EventCount < report.TopUsers[1].EventCount {
			t.Error("expected top users to be sorted by event count")
		}
	}
}

func TestComplianceReportGenerator_EventTypeStats(t *testing.T) {
	store := NewInMemoryAuditStore()
	generator := NewComplianceReportGenerator(store)

	now := time.Now()
	startTime := now.Add(-24 * time.Hour)
	endTime := now

	event1 := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Result:    ResultSuccess,
		Timestamp: now,
	}
	store.SaveEvent(event1)

	event2 := &AuditEvent{
		EventType: EventTypePermissionApproved,
		Result:    ResultSuccess,
		Timestamp: now,
	}
	store.SaveEvent(event2)

	event3 := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Result:    ResultSuccess,
		Timestamp: now,
	}
	store.SaveEvent(event3)

	report, err := generator.GenerateReport(FrameworkSOC2, startTime, endTime)
	if err != nil {
		t.Errorf("GenerateReport() error = %v", err)
	}

	if report.EventTypeStats[string(EventTypeCommandExecuted)] != 2 {
		t.Errorf("expected 2 command_executed events, got %d",
			report.EventTypeStats[string(EventTypeCommandExecuted)])
	}

	if report.EventTypeStats[string(EventTypePermissionApproved)] != 1 {
		t.Errorf("expected 1 permission_approved event, got %d",
			report.EventTypeStats[string(EventTypePermissionApproved)])
	}
}

func TestComplianceReportGenerator_ComplianceControls(t *testing.T) {
	store := NewInMemoryAuditStore()
	generator := NewComplianceReportGenerator(store)

	now := time.Now()
	startTime := now.Add(-24 * time.Hour)
	endTime := now

	// 添加一些审计日志
	event := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Result:    ResultSuccess,
		Timestamp: now,
	}
	store.SaveEvent(event)

	report, err := generator.GenerateReport(FrameworkSOC2, startTime, endTime)
	if err != nil {
		t.Errorf("GenerateReport() error = %v", err)
	}

	if len(report.PassedControls) == 0 && len(report.ViolatedControls) == 0 {
		t.Error("expected compliance controls to be evaluated")
	}
}

func TestComplianceReportGenerator_Recommendations(t *testing.T) {
	store := NewInMemoryAuditStore()
	generator := NewComplianceReportGenerator(store)

	now := time.Now()
	startTime := now.Add(-24 * time.Hour)
	endTime := now

	// 添加失败事件
	for i := 0; i < 2; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandFailed,
			Result:    ResultFailure,
			Timestamp: now,
		}
		store.SaveEvent(event)
	}

	// 添加成功事件
	event := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Result:    ResultSuccess,
		Timestamp: now,
	}
	store.SaveEvent(event)

	report, err := generator.GenerateReport(FrameworkSOC2, startTime, endTime)
	if err != nil {
		t.Errorf("GenerateReport() error = %v", err)
	}

	if len(report.Recommendations) == 0 {
		t.Error("expected recommendations to be generated")
	}
}

func TestComplianceReportGenerator_DifferentFrameworks(t *testing.T) {
	store := NewInMemoryAuditStore()
	generator := NewComplianceReportGenerator(store)

	now := time.Now()
	startTime := now.Add(-24 * time.Hour)
	endTime := now

	event := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Result:    ResultSuccess,
		Timestamp: now,
	}
	store.SaveEvent(event)

	frameworks := []ComplianceFramework{
		FrameworkSOC2,
		FrameworkHIPAA,
		FrameworkGDPR,
		FrameworkPCIDSS,
		FrameworkISO27001,
	}

	for _, framework := range frameworks {
		report, err := generator.GenerateReport(framework, startTime, endTime)
		if err != nil {
			t.Errorf("GenerateReport() for %s error = %v", framework, err)
		}

		if report.Framework != framework {
			t.Errorf("expected framework %s, got %s", framework, report.Framework)
		}

		if len(report.PassedControls) == 0 && len(report.ViolatedControls) == 0 {
			t.Errorf("expected controls to be evaluated for framework %s", framework)
		}
	}
}

func TestComplianceReportGenerator_SuspiciousEvents(t *testing.T) {
	store := NewInMemoryAuditStore()
	generator := NewComplianceReportGenerator(store)

	now := time.Now()
	startTime := now.Add(-24 * time.Hour)
	endTime := now

	// 添加高风险事件
	event := &AuditEvent{
		EventType: EventTypeSecurityAlert,
		Result:    ResultDenied,
		UserID:    "hacker",
		Username:  "attacker",
		RiskScore: 85,
		RiskLevel: "critical",
		Timestamp: now,
	}
	store.SaveEvent(event)

	report, err := generator.GenerateReport(FrameworkSOC2, startTime, endTime)
	if err != nil {
		t.Errorf("GenerateReport() error = %v", err)
	}

	if len(report.SuspiciousEvents) == 0 {
		t.Error("expected suspicious events to be detected")
	}

	suspEvent := report.SuspiciousEvents[0]
	if suspEvent.UserID != "hacker" {
		t.Errorf("expected suspicious user hacker, got %s", suspEvent.UserID)
	}
}

func BenchmarkComplianceReportGenerator_GenerateReport(b *testing.B) {
	store := NewInMemoryAuditStore()

	now := time.Now()

	// 填充存储
	for i := 0; i < 1000; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandExecuted,
			UserID:    "user1",
			Result:    ResultSuccess,
			RiskScore: 10,
			Timestamp: now.Add(time.Duration(-i) * time.Hour),
		}
		store.SaveEvent(event)
	}

	generator := NewComplianceReportGenerator(store)
	startTime := now.Add(-24 * 30 * time.Hour) // 30天
	endTime := now

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generator.GenerateReport(FrameworkSOC2, startTime, endTime)
	}
}
