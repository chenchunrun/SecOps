package audit

import (
	"testing"
	"time"
)

func TestInMemoryAuditStore_SaveEvent(t *testing.T) {
	store := NewInMemoryAuditStore()

	event := &AuditEvent{
		EventType: EventTypePermissionRequest,
		UserID:    "user1",
		Username:  "alice",
		Result:    ResultSuccess,
	}

	err := store.SaveEvent(event)
	if err != nil {
		t.Errorf("SaveEvent() error = %v", err)
	}

	if event.ID == "" {
		t.Error("expected event ID to be set")
	}
}

func TestInMemoryAuditStore_SaveEvent_Nil(t *testing.T) {
	store := NewInMemoryAuditStore()

	err := store.SaveEvent(nil)
	if err == nil {
		t.Error("expected error for nil event")
	}
}

func TestInMemoryAuditStore_GetEvent(t *testing.T) {
	store := NewInMemoryAuditStore()

	event := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		UserID:    "user1",
		Result:    ResultSuccess,
		Action:    "read",
	}

	store.SaveEvent(event)
	eventID := event.ID

	retrieved, err := store.GetEvent(eventID)
	if err != nil {
		t.Errorf("GetEvent() error = %v", err)
	}

	if retrieved.ID != eventID {
		t.Errorf("expected event ID %s, got %s", eventID, retrieved.ID)
	}
}

func TestInMemoryAuditStore_GetEvent_NotFound(t *testing.T) {
	store := NewInMemoryAuditStore()

	_, err := store.GetEvent("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent event")
	}
}

func TestInMemoryAuditStore_ListEvents(t *testing.T) {
	store := NewInMemoryAuditStore()

	// 添加多个事件
	for i := 0; i < 5; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandExecuted,
			UserID:    "user1",
			Result:    ResultSuccess,
		}
		store.SaveEvent(event)
	}

	filter := &AuditFilter{}
	events, err := store.ListEvents(filter)
	if err != nil {
		t.Errorf("ListEvents() error = %v", err)
	}

	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}
}

func TestInMemoryAuditStore_ListEvents_WithFilter(t *testing.T) {
	store := NewInMemoryAuditStore()

	// 添加多个不同类型的事件
	for i := 0; i < 3; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandExecuted,
			UserID:    "user1",
			Result:    ResultSuccess,
		}
		store.SaveEvent(event)
	}

	for i := 0; i < 2; i++ {
		event := &AuditEvent{
			EventType: EventTypePermissionDenied,
			UserID:    "user2",
			Result:    ResultDenied,
		}
		store.SaveEvent(event)
	}

	filter := &AuditFilter{
		EventType: EventTypeCommandExecuted,
	}

	events, err := store.ListEvents(filter)
	if err != nil {
		t.Errorf("ListEvents() error = %v", err)
	}

	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}
}

func TestInMemoryAuditStore_ListEvents_WithPagination(t *testing.T) {
	store := NewInMemoryAuditStore()

	for i := 0; i < 10; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandExecuted,
			UserID:    "user1",
		}
		store.SaveEvent(event)
	}

	filter := &AuditFilter{
		Limit:  5,
		Offset: 0,
	}

	events, err := store.ListEvents(filter)
	if err != nil {
		t.Errorf("ListEvents() error = %v", err)
	}

	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}
}

func TestInMemoryAuditStore_CountEvents(t *testing.T) {
	store := NewInMemoryAuditStore()

	for i := 0; i < 7; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandExecuted,
		}
		store.SaveEvent(event)
	}

	filter := &AuditFilter{}
	count, err := store.CountEvents(filter)
	if err != nil {
		t.Errorf("CountEvents() error = %v", err)
	}

	if count != 7 {
		t.Errorf("expected count 7, got %d", count)
	}
}

func TestInMemoryAuditStore_CountEvents_WithFilter(t *testing.T) {
	store := NewInMemoryAuditStore()

	for i := 0; i < 5; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandExecuted,
			UserID:    "user1",
		}
		store.SaveEvent(event)
	}

	for i := 0; i < 3; i++ {
		event := &AuditEvent{
			EventType: EventTypePermissionDenied,
			UserID:    "user2",
		}
		store.SaveEvent(event)
	}

	filter := &AuditFilter{
		UserID: "user1",
	}

	count, err := store.CountEvents(filter)
	if err != nil {
		t.Errorf("CountEvents() error = %v", err)
	}

	if count != 5 {
		t.Errorf("expected count 5, got %d", count)
	}
}

func TestInMemoryAuditStore_DeleteEvent(t *testing.T) {
	store := NewInMemoryAuditStore()

	event := &AuditEvent{
		EventType: EventTypeCommandExecuted,
	}
	store.SaveEvent(event)
	eventID := event.ID

	err := store.DeleteEvent(eventID)
	if err != nil {
		t.Errorf("DeleteEvent() error = %v", err)
	}

	_, err = store.GetEvent(eventID)
	if err == nil {
		t.Error("expected error after deletion")
	}
}

func TestInMemoryAuditStore_DeleteExpiredEvents(t *testing.T) {
	store := NewInMemoryAuditStore()

	now := time.Now()

	// 添加旧事件
	oldEvent := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Timestamp: now.Add(-48 * time.Hour),
	}
	store.SaveEvent(oldEvent)

	// 添加新事件
	newEvent := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Timestamp: now,
	}
	store.SaveEvent(newEvent)

	// 删除24小时前的事件
	err := store.DeleteExpiredEvents(24 * time.Hour)
	if err != nil {
		t.Errorf("DeleteExpiredEvents() error = %v", err)
	}

	filter := &AuditFilter{}
	events, _ := store.ListEvents(filter)

	if len(events) != 1 {
		t.Errorf("expected 1 event after deletion, got %d", len(events))
	}

	if events[0].ID != newEvent.ID {
		t.Error("expected new event to remain")
	}
}

func TestInMemoryAuditStore_ListEvents_ByTimeRange(t *testing.T) {
	store := NewInMemoryAuditStore()

	now := time.Now()

	event1 := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Timestamp: now.Add(-2 * time.Hour),
	}
	store.SaveEvent(event1)

	event2 := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Timestamp: now,
	}
	store.SaveEvent(event2)

	filter := &AuditFilter{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now.Add(1 * time.Hour),
	}

	events, err := store.ListEvents(filter)
	if err != nil {
		t.Errorf("ListEvents() error = %v", err)
	}

	if len(events) != 1 {
		t.Errorf("expected 1 event in time range, got %d", len(events))
	}
}

func TestInMemoryAuditStore_ListEvents_ByResult(t *testing.T) {
	store := NewInMemoryAuditStore()

	event1 := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Result:    ResultSuccess,
	}
	store.SaveEvent(event1)

	event2 := &AuditEvent{
		EventType: EventTypeCommandFailed,
		Result:    ResultFailure,
	}
	store.SaveEvent(event2)

	filter := &AuditFilter{
		Result: ResultSuccess,
	}

	events, err := store.ListEvents(filter)
	if err != nil {
		t.Errorf("ListEvents() error = %v", err)
	}

	if len(events) != 1 {
		t.Errorf("expected 1 success event, got %d", len(events))
	}
}

func TestInMemoryAuditStore_ListEvents_ByMinRiskScore(t *testing.T) {
	store := NewInMemoryAuditStore()

	event1 := &AuditEvent{
		EventType:  EventTypeCommandExecuted,
		RiskScore:  50,
		RiskLevel:  "medium",
	}
	store.SaveEvent(event1)

	event2 := &AuditEvent{
		EventType:  EventTypeSecurityAlert,
		RiskScore:  80,
		RiskLevel:  "critical",
	}
	store.SaveEvent(event2)

	filter := &AuditFilter{
		MinRiskScore: 75,
	}

	events, err := store.ListEvents(filter)
	if err != nil {
		t.Errorf("ListEvents() error = %v", err)
	}

	if len(events) != 1 {
		t.Errorf("expected 1 high-risk event, got %d", len(events))
	}
}

func BenchmarkInMemoryAuditStore_SaveEvent(b *testing.B) {
	store := NewInMemoryAuditStore()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandExecuted,
			UserID:    "user1",
		}
		store.SaveEvent(event)
	}
}

func BenchmarkInMemoryAuditStore_ListEvents(b *testing.B) {
	store := NewInMemoryAuditStore()

	for i := 0; i < 1000; i++ {
		event := &AuditEvent{
			EventType: EventTypeCommandExecuted,
			UserID:    "user1",
		}
		store.SaveEvent(event)
	}

	filter := &AuditFilter{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.ListEvents(filter)
	}
}
