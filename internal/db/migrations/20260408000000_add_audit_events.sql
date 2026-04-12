-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS audit_events (
    id            TEXT PRIMARY KEY,
    event_type    TEXT NOT NULL,
    timestamp     INTEGER NOT NULL,  -- Unix milliseconds
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
    details       TEXT NOT NULL DEFAULT '{}',  -- JSON
    change_data   TEXT NOT NULL DEFAULT '',     -- JSON
    approval_id   TEXT NOT NULL DEFAULT '',
    approved_by   TEXT NOT NULL DEFAULT '',
    approved_at   INTEGER NOT NULL DEFAULT 0,
    reason        TEXT NOT NULL DEFAULT '',
    signature     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_session_id ON audit_events (session_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_user_id ON audit_events (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_result ON audit_events (result);
CREATE INDEX IF NOT EXISTS idx_audit_events_risk_score ON audit_events (risk_score);
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS audit_events;
