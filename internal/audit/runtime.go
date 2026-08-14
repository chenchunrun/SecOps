package audit

import (
	"fmt"
	"sync"
)

var (
	globalAuditStoreMu sync.RWMutex
	globalAuditStore   AuditStore = NewInMemoryAuditStore()
	globalAuditWAL     AuditStore
)

type durabilityReporter interface {
	IsDurable() bool
}

// SetGlobalStore sets the process-wide audit store used by RecordGlobal.
func SetGlobalStore(store AuditStore) {
	globalAuditStoreMu.Lock()
	defer globalAuditStoreMu.Unlock()
	if store == nil {
		globalAuditStore = NewInMemoryAuditStore()
		return
	}
	globalAuditStore = store
}

// GlobalStore returns the process-wide audit store.
func GlobalStore() AuditStore {
	globalAuditStoreMu.RLock()
	defer globalAuditStoreMu.RUnlock()
	return globalAuditStore
}

// RecordGlobal records an audit event using the process-wide store.
func RecordGlobal(event *AuditEvent) error {
	store := GlobalStore()
	if store == nil {
		return nil
	}
	return store.SaveEvent(event)
}

// SetGlobalWAL configures the durable fallback used when the primary audit
// store is unavailable. A nil store disables the fallback.
func SetGlobalWAL(store AuditStore) {
	globalAuditStoreMu.Lock()
	defer globalAuditStoreMu.Unlock()
	globalAuditWAL = store
}

// RecordGlobalDurable succeeds only after a durable sink confirms the write.
func RecordGlobalDurable(event *AuditEvent) error {
	globalAuditStoreMu.RLock()
	store := globalAuditStore
	wal := globalAuditWAL
	globalAuditStoreMu.RUnlock()

	var primaryErr error
	if isDurableStore(store) {
		if err := store.SaveEvent(event); err == nil {
			return nil
		} else {
			primaryErr = err
		}
	} else {
		primaryErr = fmt.Errorf("primary audit store is not durable")
	}

	if isDurableStore(wal) {
		if err := wal.SaveEvent(event); err == nil {
			return nil
		} else {
			return fmt.Errorf("durable audit unavailable: primary: %v; WAL: %w", primaryErr, err)
		}
	}

	return fmt.Errorf("durable audit unavailable: %w; durable WAL is not configured", primaryErr)
}

func isDurableStore(store AuditStore) bool {
	reporter, ok := store.(durabilityReporter)
	return ok && reporter.IsDurable()
}
