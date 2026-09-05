package app

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/chenchunrun/SecOps/internal/bootstrap"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/evidence"
	"github.com/chenchunrun/SecOps/internal/investigation/scan"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/security"
	"github.com/stretchr/testify/require"
)

func TestScanWiringRequiresLiveSessionGrant(t *testing.T) {
	root := t.TempDir()
	store, err := evidence.NewFileStore(filepath.Join(root, "evidence"))
	require.NoError(t, err)
	perms := permission.NewDefaultService()
	app := &App{SecOpsPermissions: perms, ComputerRuntime: &bootstrap.ComputerRuntime{EvidenceStore: store}}
	cfg := &config.Config{Options: &config.Options{DataDirectory: root}}
	require.NoError(t, app.initScans(cfg))
	t.Cleanup(app.Scans.Close)
	_, err = app.Scans.Prepare(t.Context(), "scan-session", "analyst", root)
	require.ErrorContains(t, err, "authorize")
	_, scope, err := scan.Target(root)
	require.NoError(t, err)
	authorization, err := security.IssueSessionEngagementAuthorization("scan-session", "security:scan", scope, "interactive-user", time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { _ = security.RevokeGlobalEngagementAuthorization(authorization.ID) })
	require.NoError(t, perms.GrantSessionCapability(permission.CapabilityGrant{
		SessionID: "scan-session", Subject: "analyst", Capability: "security:scan", Target: scope,
		AuthorizationID: authorization.ID, GrantedBy: "interactive-user", GrantedAt: authorization.NotBefore, ExpiresAt: authorization.ExpiresAt,
	}))
	_, err = app.Scans.Prepare(t.Context(), "scan-session", "analyst", root)
	require.NoError(t, err)
	_, err = app.Scans.Prepare(t.Context(), "other-session", "analyst", root)
	require.Error(t, err)
	perms.RevokeSessionCapability("scan-session", "analyst", "security:scan", scope)
	_, err = app.Scans.Prepare(t.Context(), "scan-session", "analyst", root)
	require.Error(t, err)
}
