package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFileAuditStore_PersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	store, err := NewFileAuditStore(path)
	if err != nil {
		t.Fatalf("create file store: %v", err)
	}

	event := DefaultAuditEvent(EventTypePermissionRequest)
	event.Action = "test_action"
	if err := store.SaveEvent(event); err != nil {
		t.Fatalf("save event: %v", err)
	}

	reloaded, err := NewFileAuditStore(path)
	if err != nil {
		t.Fatalf("reload file store: %v", err)
	}

	events, err := reloaded.ListEvents(&AuditFilter{})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "test_action" {
		t.Fatalf("unexpected action: %s", events[0].Action)
	}
}

func TestFileAuditStore_DeleteExpiredEventsRewritesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	store, err := NewFileAuditStore(path)
	if err != nil {
		t.Fatalf("create file store: %v", err)
	}

	oldEvent := DefaultAuditEvent(EventTypeCommandExecuted)
	oldEvent.Timestamp = time.Now().Add(-4 * time.Hour)
	if err := store.SaveEvent(oldEvent); err != nil {
		t.Fatalf("save old event: %v", err)
	}
	newEvent := DefaultAuditEvent(EventTypeCommandExecuted)
	if err := store.SaveEvent(newEvent); err != nil {
		t.Fatalf("save new event: %v", err)
	}

	if err := store.DeleteExpiredEvents(2 * time.Hour); err != nil {
		t.Fatalf("delete expired: %v", err)
	}

	reloaded, err := NewFileAuditStore(path)
	if err != nil {
		t.Fatalf("reload file store: %v", err)
	}
	events, err := reloaded.ListEvents(&AuditFilter{})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event after cleanup, got %d", len(events))
	}
}
