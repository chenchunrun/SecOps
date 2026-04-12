package bootstrap

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/config"
)

func NewAuditStore(cfg *config.Config) (audit.AuditStore, func(context.Context) error) {
	store := audit.AuditStore(audit.NewInMemoryAuditStore())
	if cfg == nil {
		return store, nil
	}

	if cfg.Options != nil {
		auditPath := filepath.Join(cfg.Options.DataDirectory, "audit", "events.jsonl")
		if fileStore, err := audit.NewFileAuditStore(auditPath); err == nil {
			store = fileStore
		} else {
			slog.Warn("Falling back to in-memory audit store", "error", err, "path", auditPath)
		}
	}

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

func BuildAuditExporters(cfg *config.Config) []audit.SIEMExporter {
	if cfg == nil || cfg.Audit == nil || cfg.Audit.Export == nil {
		return nil
	}

	exporters := make([]audit.SIEMExporter, 0, 1)
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
	return exporters
}
