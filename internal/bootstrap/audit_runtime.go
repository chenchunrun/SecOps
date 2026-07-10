package bootstrap

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/env"
)

// NewAuditStore builds the process audit store from config. The durable backend
// (memory/file/sqlite) is selected by cfg.Audit.Storage, then optionally wrapped
// with tamper-evident HMAC hash-chain signing, and finally with the SIEM
// exporting decorator when exporters are configured. conn may be nil, in which
// case the sqlite backend falls back to the file backend.
func NewAuditStore(cfg *config.Config, conn *sql.DB) (audit.AuditStore, func(context.Context) error) {
	store := audit.AuditStore(audit.NewInMemoryAuditStore())
	if cfg == nil {
		return store, nil
	}

	store = buildDurableAuditStore(cfg, conn, store)

	exporters := BuildAuditExporters(cfg)
	if len(exporters) == 0 {
		return store, nil
	}

	exportingStore, err := audit.NewExportingAuditStore(store, 3*time.Second, exporters...)
	if err != nil {
		slog.Warn("Failed to initialize audit exporters", "error", err)
		return store, nil
	}

	return exportingStore, func(context.Context) error {
		return exportingStore.Close()
	}
}

// buildDurableAuditStore selects the durable backend. Defaults to the JSONL file
// store; "sqlite" uses the shared DB connection; "memory" keeps the in-memory
// fallback.
func buildDurableAuditStore(cfg *config.Config, conn *sql.DB, fallback audit.AuditStore) audit.AuditStore {
	backend := "file"
	if cfg.Audit != nil && strings.TrimSpace(cfg.Audit.Storage) != "" {
		backend = strings.ToLower(strings.TrimSpace(cfg.Audit.Storage))
	}
	// Strict governance mandates the tamper-evident, append-only SQLite backend
	// (hash-chained signatures, delete disabled) unless the operator explicitly
	// opted into a different backend.
	if cfg.GovernanceStrict() && (cfg.Audit == nil || strings.TrimSpace(cfg.Audit.Storage) == "") {
		backend = "sqlite"
	}
	// Strict governance mandates the tamper-evident, append-only backend.
	if cfg.GovernanceStrict() {
		backend = "sqlite"
	}

	switch backend {
	case "memory":
		return fallback
	case "sqlite":
		if conn == nil {
			slog.Warn("Audit storage 'sqlite' requested but no DB connection; using file backend")
			break
		}
		if sqliteStore, err := audit.NewSQLiteAuditStore(conn); err == nil {
			return sqliteStore
		} else {
			slog.Warn("Failed to init sqlite audit store; using file backend", "error", err)
		}
	}

	if cfg.Options != nil {
		auditPath := filepath.Join(cfg.Options.DataDirectory, "audit", "events.jsonl")
		if fileStore, err := audit.NewFileAuditStore(auditPath); err == nil {
			return fileStore
		} else {
			slog.Warn("Falling back to in-memory audit store", "error", err, "path", auditPath)
		}
	}
	return fallback
}

func BuildAuditExporters(cfg *config.Config) []audit.SIEMExporter {
	if cfg == nil || cfg.Audit == nil || cfg.Audit.Export == nil {
		return nil
	}

	exporters := make([]audit.SIEMExporter, 0, 4)
	if syslogCfg := cfg.Audit.Export.Syslog; syslogCfg != nil && syslogCfg.Enabled && strings.TrimSpace(syslogCfg.Address) != "" {
		exporters = append(exporters, &audit.SyslogExporter{
			Network:  strings.TrimSpace(syslogCfg.Network),
			Address:  strings.TrimSpace(syslogCfg.Address),
			AppName:  strings.TrimSpace(syslogCfg.AppName),
			Hostname: strings.TrimSpace(syslogCfg.Hostname),
			Facility: syslogCfg.Facility,
			Severity: syslogCfg.Severity,
		})
	}

	// Credentials may be supplied via $ENV references so secrets stay out of
	// the on-disk config; resolve them with the shell variable resolver.
	resolver := config.NewShellVariableResolver(env.New())
	resolve := func(v string) string {
		v = strings.TrimSpace(v)
		if v == "" {
			return ""
		}
		resolved, err := resolver.ResolveValue(v)
		if err != nil {
			slog.Warn("Failed to resolve audit export secret", "error", err)
			return ""
		}
		return strings.TrimSpace(resolved)
	}

	if elkCfg := cfg.Audit.Export.ELK; elkCfg != nil && elkCfg.Enabled && strings.TrimSpace(elkCfg.Endpoint) != "" {
		// TLSEnabled is forced on; the exporter rejects plaintext transport to
		// avoid leaking credentials and audit data.
		exporters = append(exporters, &audit.ELKExporter{
			Endpoint:   strings.TrimSpace(elkCfg.Endpoint),
			Index:      strings.TrimSpace(elkCfg.Index),
			Username:   resolve(elkCfg.Username),
			Password:   resolve(elkCfg.Password),
			TLSEnabled: true,
		})
	}

	if splunkCfg := cfg.Audit.Export.Splunk; splunkCfg != nil && splunkCfg.Enabled && strings.TrimSpace(splunkCfg.Endpoint) != "" {
		exporters = append(exporters, &audit.SplunkExporter{
			Endpoint:   strings.TrimSpace(splunkCfg.Endpoint),
			Token:      resolve(splunkCfg.Token),
			Index:      strings.TrimSpace(splunkCfg.Index),
			TLSEnabled: true,
		})
	}
	if sentinelCfg := cfg.Audit.Export.AzureSentinel; sentinelCfg != nil && sentinelCfg.Enabled && strings.TrimSpace(sentinelCfg.Endpoint) != "" {
		exporters = append(exporters, &audit.AzureSentinelExporter{
			Endpoint:   strings.TrimSpace(sentinelCfg.Endpoint),
			Token:      resolve(sentinelCfg.Token),
			RuleID:     strings.TrimSpace(sentinelCfg.RuleID),
			TLSEnabled: true,
		})
	}
	return exporters
}
