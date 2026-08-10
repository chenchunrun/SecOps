package scheduler

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

	"github.com/chenchunrun/SecOps/internal/permission"
)

var ErrInvalidAuditPath = errors.New("invalid scheduler audit path")

// AuditRecord is the durable representation of one scheduler event.
type AuditRecord struct {
	RecordedAt         time.Time                     `json:"recorded_at"`
	Decision           Decision                      `json:"decision"`
	PermissionDecision permission.PermissionDecision `json:"permission_decision"`
}

// FileObserver appends scheduler decisions to storage outside execution
// environments. A mutex preserves complete JSONL records under concurrency.
type FileObserver struct {
	path string
	mu   sync.Mutex
}

// NewFileObserver creates the parent audit directory and returns a durable
// append-only observer.
func NewFileObserver(path string) (*FileObserver, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrInvalidAuditPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create scheduler audit directory: %w", err)
	}
	return &FileObserver{path: path}, nil
}

// Record persists and syncs one scheduler event before scheduling can return
// an executable Computer.
func (o *FileObserver) Record(ctx context.Context, event Event) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("record scheduler audit event: %w", err)
	}
	record := AuditRecord{
		RecordedAt:         time.Now().UTC(),
		Decision:           event.Decision,
		PermissionDecision: event.PermissionDecision,
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal scheduler audit event: %w", err)
	}
	data = append(data, '\n')

	o.mu.Lock()
	defer o.mu.Unlock()

	file, err := os.OpenFile(o.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open scheduler audit file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write scheduler audit event: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync scheduler audit event: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close scheduler audit file: %w", err)
	}
	return nil
}
