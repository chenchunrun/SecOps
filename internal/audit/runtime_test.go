package audit

import "testing"

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
