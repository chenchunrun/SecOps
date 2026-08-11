package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrInvalidAuditPath = errors.New("invalid egress audit path")

// Event associates an egress decision with its durable task request.
type Event struct {
	RequestID string   `json:"request_id"`
	Decision  Decision `json:"decision"`
}

// Observer records egress decisions before protected execution can proceed.
type Observer interface {
	Record(ctx context.Context, event Event) error
}

// AuditRecord is the durable representation of one egress event.
type AuditRecord struct {
	RecordedAt time.Time `json:"recorded_at"`
	Event      Event     `json:"event"`
}

// FileObserver appends complete JSONL records under concurrent use.
type FileObserver struct {
	path string
	mu   sync.Mutex
}

// NewFileObserver creates a durable append-only egress observer.
func NewFileObserver(path string) (*FileObserver, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrInvalidAuditPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create egress audit directory: %w", err)
	}
	return &FileObserver{path: path}, nil
}

// Record persists and syncs a decision before protected task persistence.
func (o *FileObserver) Record(ctx context.Context, event Event) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("record egress audit event: %w", err)
	}
	data, err := json.Marshal(AuditRecord{RecordedAt: time.Now().UTC(), Event: event})
	if err != nil {
		return fmt.Errorf("marshal egress audit event: %w", err)
	}
	data = append(data, '\n')

	o.mu.Lock()
	defer o.mu.Unlock()

	file, err := os.OpenFile(o.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open egress audit file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write egress audit event: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync egress audit event: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close egress audit file: %w", err)
	}
	return nil
}
