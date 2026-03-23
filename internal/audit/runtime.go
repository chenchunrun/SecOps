package audit

import "sync"

var (
	globalAuditStoreMu sync.RWMutex
	globalAuditStore   AuditStore = NewInMemoryAuditStore()
)

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
