package audit

import (
	"context"
	"sync/atomic"
	"sync"
	"testing"
	"time"
)

type captureExporter struct {
	mu     sync.Mutex
	events []*AuditEvent
	ch     chan struct{}
}

func (e *captureExporter) Export(_ context.Context, events []*AuditEvent) error {
	e.mu.Lock()
	e.events = append(e.events, events...)
	e.mu.Unlock()
	select {
	case e.ch <- struct{}{}:
	default:
	}
	return nil
}

func TestExportingAuditStore_SaveEventPersistsAndExports(t *testing.T) {
	base := NewInMemoryAuditStore()
	exporter := &captureExporter{ch: make(chan struct{}, 1)}

	store, err := NewExportingAuditStore(base, time.Second, exporter)
	if err != nil {
		t.Fatalf("new exporting store: %v", err)
	}
	defer store.Close()

	event := DefaultAuditEvent(EventTypeCommandExecuted)
	event.Details["token"] = "Authorization: Bearer secret-token"

	if err := store.SaveEvent(event); err != nil {
		t.Fatalf("save event: %v", err)
	}

	if _, err := base.GetEvent(event.ID); err != nil {
		t.Fatalf("expected event persisted locally: %v", err)
	}

	select {
	case <-exporter.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for async export")
	}

	exporter.mu.Lock()
	defer exporter.mu.Unlock()
	if len(exporter.events) != 1 {
		t.Fatalf("expected 1 exported event, got %d", len(exporter.events))
	}
	if exporter.events[0].Details["token"] == "Authorization: Bearer secret-token" {
		t.Fatal("expected exported event to be redacted")
	}
}

type blockingExporter struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Uint64
}

func (e *blockingExporter) Export(_ context.Context, _ []*AuditEvent) error {
	e.calls.Add(1)
	select {
	case e.started <- struct{}{}:
	default:
	}
	<-e.release
	return nil
}

func TestExportingAuditStore_DropsWhenQueueFull(t *testing.T) {
	base := NewInMemoryAuditStore()
	exporter := &blockingExporter{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}

	store, err := newExportingAuditStore(base, time.Second, 1, 1, exporter)
	if err != nil {
		t.Fatalf("new exporting store: %v", err)
	}
	defer store.Close()

	for i := 0; i < 3; i++ {
		event := DefaultAuditEvent(EventTypeCommandExecuted)
		event.ID = time.Now().Format("150405.000000000")
		if err := store.SaveEvent(event); err != nil {
			t.Fatalf("save event %d: %v", i, err)
		}
	}

	select {
	case <-exporter.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for exporter to start")
	}

	if got := store.dropped.Load(); got == 0 {
		t.Fatal("expected dropped export jobs when queue is full")
	}

	close(exporter.release)
}
