package audit

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultExportQueueSize   = 256
	defaultExportWorkerCount = 2
)

type exportJob struct {
	exporter SIEMExporter
	event    *AuditEvent
}

// ExportingAuditStore persists events locally and asynchronously exports them
// to one or more external sinks. Export failures are logged but do not block
// the main audit persistence path.
type ExportingAuditStore struct {
	base          AuditStore
	exporters     []SIEMExporter
	exportTimeout time.Duration
	jobs          chan exportJob
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	dropped       atomic.Uint64
}

// NewExportingAuditStore wraps a base store with asynchronous exporter fanout.
func NewExportingAuditStore(base AuditStore, exportTimeout time.Duration, exporters ...SIEMExporter) (*ExportingAuditStore, error) {
	return newExportingAuditStore(base, exportTimeout, defaultExportQueueSize, defaultExportWorkerCount, exporters...)
}

func newExportingAuditStore(
	base AuditStore,
	exportTimeout time.Duration,
	queueSize int,
	workerCount int,
	exporters ...SIEMExporter,
) (*ExportingAuditStore, error) {
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
	if queueSize <= 0 {
		queueSize = defaultExportQueueSize
	}
	if workerCount <= 0 {
		workerCount = defaultExportWorkerCount
	}

	ctx, cancel := context.WithCancel(context.Background())
	store := &ExportingAuditStore{
		base:          base,
		exporters:     filtered,
		exportTimeout: exportTimeout,
		jobs:          make(chan exportJob, queueSize),
		cancel:        cancel,
	}
	for range workerCount {
		store.wg.Go(func() {
			store.runWorker(ctx)
		})
	}
	return store, nil
}

func (s *ExportingAuditStore) runWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-s.jobs:
			exportCtx, cancel := context.WithTimeout(context.Background(), s.exportTimeout)
			err := job.exporter.Export(exportCtx, []*AuditEvent{job.event})
			cancel()
			if err != nil {
				slog.Warn("Audit export failed", "error", err, "event_id", job.event.ID)
			}
		}
	}
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
		job := exportJob{exporter: exporter, event: eventCopy}
		select {
		case s.jobs <- job:
		default:
			dropped := s.dropped.Add(1)
			slog.Warn("Audit export queue full; dropping event", "event_id", event.ID, "dropped_total", dropped)
		}
	}
	return nil
}

func (s *ExportingAuditStore) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
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
