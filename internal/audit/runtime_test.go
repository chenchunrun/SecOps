package audit

import (
	"path/filepath"
	"testing"
)

func TestRecordGlobal(t *testing.T) {
	store := NewInMemoryAuditStore()
	SetGlobalStore(store)
	t.Cleanup(func() { SetGlobalStore(NewInMemoryAuditStore()) })

	evt := DefaultAuditEvent(EventTypePermissionDenied)
	evt.Action = "remote_policy_deny"
	if err := RecordGlobal(evt); err != nil {
		t.Fatalf("record global failed: %v", err)
	}

	events, err := store.ListEvents(&AuditFilter{})
	if err != nil {
		t.Fatalf("list events failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "remote_policy_deny" {
		t.Fatalf("unexpected action: %s", events[0].Action)
	}
}

func TestRecordGlobalDurableFallsBackToWAL(t *testing.T) {
	SetGlobalStore(NewInMemoryAuditStore())
	wal, err := NewFileAuditStore(filepath.Join(t.TempDir(), "audit.wal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	SetGlobalWAL(wal)
	t.Cleanup(func() {
		SetGlobalStore(NewInMemoryAuditStore())
		SetGlobalWAL(nil)
	})

	event := DefaultAuditEvent(EventTypeCommandStarted)
	event.Action = "secops_execution_intent"
	if err := RecordGlobalDurable(event); err != nil {
		t.Fatalf("durable record should fall back to WAL: %v", err)
	}
	events, err := wal.ListEvents(&AuditFilter{})
	if err != nil || len(events) != 1 {
		t.Fatalf("expected one WAL event, got %d, err=%v", len(events), err)
	}
}

func TestRecordGlobalDurableFailsWithoutDurableSink(t *testing.T) {
	SetGlobalStore(NewInMemoryAuditStore())
	SetGlobalWAL(nil)
	t.Cleanup(func() { SetGlobalStore(NewInMemoryAuditStore()) })

	if err := RecordGlobalDurable(DefaultAuditEvent(EventTypeCommandStarted)); err == nil {
		t.Fatal("expected durable audit failure without durable store or WAL")
	}
}
