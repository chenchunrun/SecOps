package audit

import (
	"errors"
	"path/filepath"
	"testing"
)

type failingDurableStore struct {
	*InMemoryAuditStore
}

func (s *failingDurableStore) IsDurable() bool { return true }
func (s *failingDurableStore) SaveEvent(*AuditEvent) error {
	return errors.New("injected durable store failure")
}

func TestRecordGlobalDurableFallsBackAfterPrimaryFailure(t *testing.T) {
	SetGlobalStore(&failingDurableStore{NewInMemoryAuditStore()})
	wal, err := NewFileAuditStore(filepath.Join(t.TempDir(), "audit.wal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	SetGlobalWAL(wal)
	t.Cleanup(func() {
		SetGlobalStore(NewInMemoryAuditStore())
		SetGlobalWAL(nil)
	})

	if err := RecordGlobalDurable(DefaultAuditEvent(EventTypeCommandStarted)); err != nil {
		t.Fatalf("expected WAL recovery, got %v", err)
	}
}

func TestRecordGlobalDurableFailsWhenPrimaryAndWALFail(t *testing.T) {
	SetGlobalStore(&failingDurableStore{NewInMemoryAuditStore()})
	SetGlobalWAL(&failingDurableStore{NewInMemoryAuditStore()})
	t.Cleanup(func() {
		SetGlobalStore(NewInMemoryAuditStore())
		SetGlobalWAL(nil)
	})

	if err := RecordGlobalDurable(DefaultAuditEvent(EventTypeCommandStarted)); err == nil {
		t.Fatal("expected fail-closed when all durable sinks fail")
	}
}
