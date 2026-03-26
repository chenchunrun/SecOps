package audit

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// ExportingAuditStore persists events locally and asynchronously exports them
// to one or more external sinks. Export failures are logged but do not block
// the main audit persistence path.
type ExportingAuditStore struct {
	base          AuditStore
	exporters     []SIEMExporter
	exportTimeout time.Duration
}

// NewExportingAuditStore wraps a base store with asynchronous exporter fanout.
func NewExportingAuditStore(base AuditStore, exportTimeout time.Duration, exporters ...SIEMExporter) (*ExportingAuditStore, error) {
	if base == nil {
		return nil, fmt.Errorf("base audit store is required")
	}
	filtered := make([]SIEMExporter, 0, len(exporters))
	for _, exporter := range exporters {
		if exporter != nil {
			filtered = append(filtered, exporter)
		}
	}
	if exportTimeout <= 0 {
		exportTimeout = 3 * time.Second
	}
	return &ExportingAuditStore{
		base:          base,
		exporters:     filtered,
		exportTimeout: exportTimeout,
	}, nil
}

func (s *ExportingAuditStore) SaveEvent(event *AuditEvent) error {
	if err := s.base.SaveEvent(event); err != nil {
		return err
	}
	if len(s.exporters) == 0 || event == nil {
		return nil
	}

	eventCopy := redactEvent(event)
	for _, exporter := range s.exporters {
		exporter := exporter
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), s.exportTimeout)
			defer cancel()
			if err := exporter.Export(ctx, []*AuditEvent{eventCopy}); err != nil {
				slog.Warn("Audit export failed", "error", err, "event_id", event.ID)
			}
		}()
	}
	return nil
}

func (s *ExportingAuditStore) GetEvent(id string) (*AuditEvent, error) {
	return s.base.GetEvent(id)
}

func (s *ExportingAuditStore) ListEvents(filter *AuditFilter) ([]*AuditEvent, error) {
	return s.base.ListEvents(filter)
}

func (s *ExportingAuditStore) CountEvents(filter *AuditFilter) (int, error) {
	return s.base.CountEvents(filter)
}

func (s *ExportingAuditStore) DeleteEvent(id string) error {
	return s.base.DeleteEvent(id)
}

func (s *ExportingAuditStore) DeleteExpiredEvents(olderThan time.Duration) error {
	return s.base.DeleteExpiredEvents(olderThan)
}
