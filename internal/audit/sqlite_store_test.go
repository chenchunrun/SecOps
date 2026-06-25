package audit

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestSQLiteDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	const ddl = `CREATE TABLE IF NOT EXISTS audit_events (
		id            TEXT PRIMARY KEY,
		event_type    TEXT NOT NULL,
		timestamp     INTEGER NOT NULL,
		session_id    TEXT NOT NULL DEFAULT '',
		user_id       TEXT NOT NULL DEFAULT '',
		username      TEXT NOT NULL DEFAULT '',
		source_ip     TEXT NOT NULL DEFAULT '',
		action        TEXT NOT NULL DEFAULT '',
		resource_type TEXT NOT NULL DEFAULT '',
		resource_name TEXT NOT NULL DEFAULT '',
		resource_path TEXT NOT NULL DEFAULT '',
		transport     TEXT NOT NULL DEFAULT '',
		target_host   TEXT NOT NULL DEFAULT '',
		target_env    TEXT NOT NULL DEFAULT '',
		target_id     TEXT NOT NULL DEFAULT '',
		result        TEXT NOT NULL DEFAULT '',
		error_msg     TEXT NOT NULL DEFAULT '',
		risk_score    INTEGER NOT NULL DEFAULT 0,
		risk_level    TEXT NOT NULL DEFAULT '',
		severity      TEXT NOT NULL DEFAULT '',
		details       TEXT NOT NULL DEFAULT '{}',
		change_data   TEXT NOT NULL DEFAULT '',
		approval_id   TEXT NOT NULL DEFAULT '',
		approved_by   TEXT NOT NULL DEFAULT '',
		approved_at   INTEGER NOT NULL DEFAULT 0,
		reason        TEXT NOT NULL DEFAULT '',
		signature     TEXT NOT NULL DEFAULT ''
	)`
	if _, err := db.ExecContext(t.Context(), ddl); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestSQLiteAuditStore_SaveAndGetEvent(t *testing.T) {
	db := newTestSQLiteDB(t)
	store, err := NewSQLiteAuditStore(db)
	if err != nil {
		t.Fatal(err)
	}

	event := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Timestamp: time.Now().UTC(),
		UserID:    "admin",
		Username:  "alice",
		Action:    "read",
		Result:    ResultSuccess,
	}

	if err := store.SaveEvent(event); err != nil {
		t.Fatalf("SaveEvent error: %v", err)
	}
	if event.ID == "" {
		t.Fatal("expected event ID to be set")
	}

	got, err := store.GetEvent(event.ID)
	if err != nil {
		t.Fatalf("GetEvent error: %v", err)
	}
	if got.UserID != "admin" {
		t.Fatalf("expected user_id admin, got %s", got.UserID)
	}
	if got.Action != "read" {
		t.Fatalf("expected action read, got %s", got.Action)
	}
}

func TestSQLiteAuditStore_ListEventsWithFilter(t *testing.T) {
	db := newTestSQLiteDB(t)
	store, _ := NewSQLiteAuditStore(db)

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		store.SaveEvent(&AuditEvent{
			EventType: EventTypeCommandExecuted,
			Timestamp: now.Add(time.Duration(i) * time.Second),
			UserID:    "user1",
			Result:    ResultSuccess,
		})
	}
	for i := 0; i < 3; i++ {
		store.SaveEvent(&AuditEvent{
			EventType: EventTypePermissionDenied,
			Timestamp: now.Add(time.Duration(i+5) * time.Second),
			UserID:    "user2",
			Result:    ResultDenied,
		})
	}

	events, err := store.ListEvents(&AuditFilter{
		EventType: EventTypeCommandExecuted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Fatalf("expected 5 command_executed events, got %d", len(events))
	}
}

func TestSQLiteAuditStore_CountEvents(t *testing.T) {
	db := newTestSQLiteDB(t)
	store, _ := NewSQLiteAuditStore(db)

	for i := 0; i < 7; i++ {
		store.SaveEvent(&AuditEvent{
			EventType: EventTypeCommandExecuted,
			Timestamp: time.Now().UTC(),
		})
	}

	count, err := store.CountEvents(&AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 7 {
		t.Fatalf("expected count 7, got %d", count)
	}
}

func TestSQLiteAuditStore_DeleteEvent(t *testing.T) {
	db := newTestSQLiteDB(t)
	store, _ := NewSQLiteAuditStore(db)

	event := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Timestamp: time.Now().UTC(),
	}
	store.SaveEvent(event)

	// The store is append-only by default: single-event deletion is refused to
	// protect the tamper-evident hash chain.
	if err := store.DeleteEvent(event.ID); err == nil {
		t.Fatal("expected deletion to be refused on append-only store")
	}

	// Break-glass: explicitly enabling deletion allows it.
	store.AllowDelete(true)
	if err := store.DeleteEvent(event.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetEvent(event.ID); err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestSQLiteAuditStore_DeleteExpiredEvents(t *testing.T) {
	db := newTestSQLiteDB(t)
	store, _ := NewSQLiteAuditStore(db)

	now := time.Now().UTC()
	store.SaveEvent(&AuditEvent{
		EventType: EventTypeCommandExecuted,
		Timestamp: now.Add(-48 * time.Hour),
	})
	store.SaveEvent(&AuditEvent{
		EventType: EventTypeCommandExecuted,
		Timestamp: now,
	})

	if err := store.DeleteExpiredEvents(24 * time.Hour); err != nil {
		t.Fatal(err)
	}

	count, _ := store.CountEvents(&AuditFilter{})
	if count != 1 {
		t.Fatalf("expected 1 event after expiry cleanup, got %d", count)
	}
}

func TestSQLiteAuditStore_ActionTruncation(t *testing.T) {
	db := newTestSQLiteDB(t)
	store, _ := NewSQLiteAuditStore(db)

	longAction := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 65 chars
	event := &AuditEvent{
		EventType: EventTypeCommandExecuted,
		Timestamp: time.Now().UTC(),
		Action:    longAction,
	}
	store.SaveEvent(event)

	got, _ := store.GetEvent(event.ID)
	if len(got.Action) != 64 {
		t.Fatalf("expected action length 64, got %d", len(got.Action))
	}
}

func TestSQLiteAuditStore_NilDB(t *testing.T) {
	_, err := NewSQLiteAuditStore(nil)
	if err == nil {
		t.Fatal("expected error for nil db")
	}
}
