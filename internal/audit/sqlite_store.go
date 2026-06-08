package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SQLiteAuditStore persists audit events to a SQLite database, following the
// same persistence pattern used by the Crush base for sessions and messages.
type SQLiteAuditStore struct {
	db *sql.DB
}

// NewSQLiteAuditStore creates a SQLite-backed audit store. The caller must
// ensure the audit_events table exists (via goose migration).
func NewSQLiteAuditStore(db *sql.DB) (*SQLiteAuditStore, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &SQLiteAuditStore{db: db}, nil
}

func (s *SQLiteAuditStore) SaveEvent(event *AuditEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}
	// Generating and writing back the ID is part of the store contract, but
	// other normalized values are kept local so callers do not observe a
	// surprising in-place mutation of their event (e.g. a truncated Action).
	if event.ID == "" {
		event.ID = generateEventID()
	}

	action := event.Action
	if len(action) > inMemoryAuditStoreMaxAction {
		action = truncateRunes(action, inMemoryAuditStoreMaxAction)
	}

	detailsJSON, err := json.Marshal(event.Details)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	var changeJSON []byte
	if event.ChangeData != nil {
		changeJSON, _ = json.Marshal(event.ChangeData)
	}

	ts := event.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	approvedAtMs := int64(0)
	if !event.ApprovedAt.IsZero() {
		approvedAtMs = event.ApprovedAt.UnixMilli()
	}

	const q = `INSERT OR REPLACE INTO audit_events (
		id, event_type, timestamp, session_id, user_id, username, source_ip,
		action, resource_type, resource_name, resource_path,
		transport, target_host, target_env, target_id,
		result, error_msg, risk_score, risk_level, severity,
		details, change_data, approval_id, approved_by, approved_at,
		reason, signature
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

	_, err = s.db.Exec(q,
		event.ID, string(event.EventType), ts.UnixMilli(),
		event.SessionID, event.UserID, event.Username, event.SourceIP,
		action, event.ResourceType, event.ResourceName, event.ResourcePath,
		event.Transport, event.TargetHost, event.TargetEnv, event.TargetID,
		string(event.Result), event.ErrorMsg, event.RiskScore, event.RiskLevel, event.Severity,
		string(detailsJSON), string(changeJSON),
		event.ApprovalID, event.ApprovedBy, approvedAtMs,
		event.Reason, event.Signature,
	)
	return err
}

func (s *SQLiteAuditStore) GetEvent(id string) (*AuditEvent, error) {
	row := s.db.QueryRow(`SELECT
		id, event_type, timestamp, session_id, user_id, username, source_ip,
		action, resource_type, resource_name, resource_path,
		transport, target_host, target_env, target_id,
		result, error_msg, risk_score, risk_level, severity,
		details, change_data, approval_id, approved_by, approved_at,
		reason, signature
	FROM audit_events WHERE id = ?`, id)

	event, err := scanAuditEvent(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("event not found: %s", id)
	}
	return event, err
}

func (s *SQLiteAuditStore) ListEvents(filter *AuditFilter) ([]*AuditEvent, error) {
	where, args := buildWhereClause(filter)
	q := `SELECT
		id, event_type, timestamp, session_id, user_id, username, source_ip,
		action, resource_type, resource_name, resource_path,
		transport, target_host, target_env, target_id,
		result, error_msg, risk_score, risk_level, severity,
		details, change_data, approval_id, approved_by, approved_at,
		reason, signature
	FROM audit_events` + where + ` ORDER BY timestamp ASC`

	if filter != nil && filter.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d OFFSET %d", filter.Limit, filter.Offset)
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*AuditEvent
	for rows.Next() {
		event, err := scanAuditEventRows(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if events == nil {
		events = []*AuditEvent{}
	}
	return events, rows.Err()
}

func (s *SQLiteAuditStore) CountEvents(filter *AuditFilter) (int, error) {
	where, args := buildWhereClause(filter)
	q := `SELECT COUNT(*) FROM audit_events` + where

	var count int
	err := s.db.QueryRow(q, args...).Scan(&count)
	return count, err
}

func (s *SQLiteAuditStore) DeleteEvent(id string) error {
	res, err := s.db.Exec(`DELETE FROM audit_events WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("event not found: %s", id)
	}
	return nil
}

func (s *SQLiteAuditStore) DeleteExpiredEvents(olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan).UnixMilli()
	_, err := s.db.Exec(`DELETE FROM audit_events WHERE timestamp < ?`, cutoff)
	return err
}

// --- helpers ---

func buildWhereClause(filter *AuditFilter) (string, []interface{}) {
	if filter == nil {
		return "", nil
	}
	var clauses []string
	var args []interface{}

	if !filter.StartTime.IsZero() {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, filter.StartTime.UnixMilli())
	}
	if !filter.EndTime.IsZero() {
		clauses = append(clauses, "timestamp <= ?")
		args = append(args, filter.EndTime.UnixMilli())
	}
	if filter.SessionID != "" {
		clauses = append(clauses, "session_id = ?")
		args = append(args, filter.SessionID)
	}
	if filter.UserID != "" {
		clauses = append(clauses, "user_id = ?")
		args = append(args, filter.UserID)
	}
	if filter.Username != "" {
		clauses = append(clauses, "username = ?")
		args = append(args, filter.Username)
	}
	if filter.EventType != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, string(filter.EventType))
	}
	if filter.Action != "" {
		clauses = append(clauses, "action = ?")
		args = append(args, filter.Action)
	}
	if filter.ResourceType != "" {
		clauses = append(clauses, "resource_type = ?")
		args = append(args, filter.ResourceType)
	}
	if filter.ResourceName != "" {
		clauses = append(clauses, "resource_name = ?")
		args = append(args, filter.ResourceName)
	}
	if filter.Result != "" {
		clauses = append(clauses, "result = ?")
		args = append(args, string(filter.Result))
	}
	if filter.MinRiskScore > 0 {
		clauses = append(clauses, "risk_score >= ?")
		args = append(args, filter.MinRiskScore)
	}

	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanAuditEvent(row *sql.Row) (*AuditEvent, error) {
	var e AuditEvent
	var tsMs, approvedAtMs int64
	var eventType, result, detailsJSON, changeJSON string

	err := row.Scan(
		&e.ID, &eventType, &tsMs, &e.SessionID, &e.UserID, &e.Username, &e.SourceIP,
		&e.Action, &e.ResourceType, &e.ResourceName, &e.ResourcePath,
		&e.Transport, &e.TargetHost, &e.TargetEnv, &e.TargetID,
		&result, &e.ErrorMsg, &e.RiskScore, &e.RiskLevel, &e.Severity,
		&detailsJSON, &changeJSON, &e.ApprovalID, &e.ApprovedBy, &approvedAtMs,
		&e.Reason, &e.Signature,
	)
	if err != nil {
		return nil, err
	}
	e.EventType = AuditEventType(eventType)
	e.Result = AuditResult(result)
	e.Timestamp = time.UnixMilli(tsMs).UTC()
	if approvedAtMs > 0 {
		e.ApprovedAt = time.UnixMilli(approvedAtMs).UTC()
	}
	if detailsJSON != "" && detailsJSON != "{}" {
		_ = json.Unmarshal([]byte(detailsJSON), &e.Details)
	}
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	if changeJSON != "" {
		var cd ChangeData
		if json.Unmarshal([]byte(changeJSON), &cd) == nil && cd.FieldName != "" {
			e.ChangeData = &cd
		}
	}
	return &e, nil
}

func scanAuditEventRows(rows *sql.Rows) (*AuditEvent, error) {
	var e AuditEvent
	var tsMs, approvedAtMs int64
	var eventType, result, detailsJSON, changeJSON string

	err := rows.Scan(
		&e.ID, &eventType, &tsMs, &e.SessionID, &e.UserID, &e.Username, &e.SourceIP,
		&e.Action, &e.ResourceType, &e.ResourceName, &e.ResourcePath,
		&e.Transport, &e.TargetHost, &e.TargetEnv, &e.TargetID,
		&result, &e.ErrorMsg, &e.RiskScore, &e.RiskLevel, &e.Severity,
		&detailsJSON, &changeJSON, &e.ApprovalID, &e.ApprovedBy, &approvedAtMs,
		&e.Reason, &e.Signature,
	)
	if err != nil {
		return nil, err
	}
	e.EventType = AuditEventType(eventType)
	e.Result = AuditResult(result)
	e.Timestamp = time.UnixMilli(tsMs).UTC()
	if approvedAtMs > 0 {
		e.ApprovedAt = time.UnixMilli(approvedAtMs).UTC()
	}
	if detailsJSON != "" && detailsJSON != "{}" {
		_ = json.Unmarshal([]byte(detailsJSON), &e.Details)
	}
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	if changeJSON != "" {
		var cd ChangeData
		if json.Unmarshal([]byte(changeJSON), &cd) == nil && cd.FieldName != "" {
			e.ChangeData = &cd
		}
	}
	return &e, nil
}
