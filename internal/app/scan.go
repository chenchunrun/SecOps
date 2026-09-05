package app

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/investigation/scan"
	"github.com/chenchunrun/SecOps/internal/security"
)

func (app *App) initScans(cfg *config.Config) error {
	root := filepath.Dir(config.GlobalConfigData())
	if cfg.Options != nil && cfg.Options.DataDirectory != "" {
		root = cfg.Options.DataDirectory
	}
	service, err := scan.New(filepath.Join(root, "runtime", "scans"), app.ComputerRuntime.EvidenceStore,
		secops.NewSecurityScanTool(nil),
		func(sessionID, subject, target string) error {
			// This workflow is explicitly local; do not bypass a configured backend.
			if cfg.Sandbox != nil && cfg.Sandbox.Mode != "" && !strings.EqualFold(cfg.Sandbox.Mode, "local") {
				return fmt.Errorf("local scan workflow is unavailable with sandbox mode %s", cfg.Sandbox.Mode)
			}
			grant, ok := app.SecOpsPermissions.FindSessionCapability(sessionID, subject, "security:scan", target)
			if !ok {
				return fmt.Errorf("scan requires /scan authorize for this directory and active role")
			}
			return security.ValidateGlobalEngagementAuthorizationForSession(grant.AuthorizationID, "security:scan", target, sessionID, time.Now())
		},
		func(sessionID, taskID, action, target string) error {
			eventType := audit.EventTypeCommandStarted
			if action == "scan_failed" || action == "scan_canceled" {
				eventType = audit.EventTypeCommandFailed
			}
			if action == "scan_awaiting_review" {
				eventType = audit.EventTypeCommandExecuted
			}
			return audit.RecordGlobalDurable(audit.NewAuditEventBuilder(eventType).
				WithSession(sessionID).WithAction(action).WithResource("scan_task", taskID, target).Build())
		})
	if err != nil {
		return fmt.Errorf("initialize scan workflow: %w", err)
	}
	app.Scans = service
	app.cleanupFuncs = append(app.cleanupFuncs, func(context.Context) error { service.Close(); return nil })
	return nil
}

func (app *App) RunScan(sessionID, id string) (scan.Record, error) {
	return app.Scans.Run(app.globalCtx, sessionID, id)
}
