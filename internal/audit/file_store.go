package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileAuditStore persists events to a JSONL file while keeping an in-memory
// index for query performance.
type FileAuditStore struct {
	mu   sync.RWMutex
	path string
	mem  *InMemoryAuditStore
}

// NewFileAuditStore creates (or loads) a file-backed audit store.
func NewFileAuditStore(path string) (*FileAuditStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("audit file path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit file: %w", err)
	}
	_ = f.Close()

	store := &FileAuditStore{
		path: path,
		mem:  NewInMemoryAuditStore(),
	}
	if err := store.loadFromDisk(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileAuditStore) SaveEvent(event *AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.mem.SaveEvent(event); err != nil {
		return err
	}
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

func (s *FileAuditStore) GetEvent(id string) (*AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mem.GetEvent(id)
}

func (s *FileAuditStore) ListEvents(filter *AuditFilter) ([]*AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mem.ListEvents(filter)
}

func (s *FileAuditStore) CountEvents(filter *AuditFilter) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mem.CountEvents(filter)
}

func (s *FileAuditStore) DeleteEvent(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.mem.DeleteEvent(id); err != nil {
		return err
	}
	return s.rewriteAllLocked()
}

func (s *FileAuditStore) DeleteExpiredEvents(olderThan time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.mem.DeleteExpiredEvents(olderThan); err != nil {
		return err
	}
	return s.rewriteAllLocked()
}

func (s *FileAuditStore) loadFromDisk() error {
	f, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("open audit file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		_ = s.mem.SaveEvent(&event)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan audit file: %w", err)
	}
	return nil
}

func (s *FileAuditStore) rewriteAllLocked() error {
	events, err := s.mem.ListEvents(&AuditFilter{})
	if err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	for _, event := range events {
		b, err := json.Marshal(event)
		if err != nil {
			_ = f.Close()
			return err
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
