package scan

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
	"github.com/chenchunrun/SecOps/internal/evidence"
	"github.com/stretchr/testify/require"
)

type scannerFunc func(context.Context, interface{}) (interface{}, error)

func (f scannerFunc) ExecuteContext(ctx context.Context, input interface{}) (interface{}, error) {
	return f(ctx, input)
}

func TestAuthorizeScanEvidenceReviewReportRevoke(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := evidence.NewFileStore(filepath.Join(root, "evidence"))
	require.NoError(t, err)
	var authorized atomic.Bool
	scanner := scannerFunc(func(_ context.Context, input interface{}) (interface{}, error) {
		p := input.(*secops.SecurityScanParams)
		require.Equal(t, secops.TargetFilesystem, p.Target)
		return &secops.ScanResult{TotalVulnerabilities: 1, HighCount: 1}, nil
	})
	authorize := func(session, subject, scope string) error {
		if !authorized.Load() || session != "session-1" || subject != "analyst" {
			return errors.New("denied")
		}
		require.Contains(t, scope, "scan-")
		return nil
	}
	service, err := New(filepath.Join(root, "scans"), store, scanner, authorize, func(string, string, string, string) error { return nil })
	require.NoError(t, err)
	_, err = service.Prepare(t.Context(), "session-1", "analyst", root)
	require.ErrorContains(t, err, "denied")
	authorized.Store(true)
	r, err := service.Prepare(t.Context(), "session-1", "analyst", root)
	require.NoError(t, err)
	r, err = service.Run(t.Context(), "session-1", r.ID)
	require.NoError(t, err)
	require.Equal(t, "awaiting_review", r.State)
	_, err = service.Report(t.Context(), "session-1", r.ID)
	require.ErrorContains(t, err, "human review")
	_, err = service.Review(t.Context(), "other-session", r.ID, evidence.VerdictPassed, "reviewed")
	require.ErrorContains(t, err, "session mismatch")
	report, err := service.Review(t.Context(), "session-1", r.ID, evidence.VerdictPassed, "Compared the scanner output with the package inventory")
	require.NoError(t, err)
	require.Equal(t, "interactive-user", report.Verification.CheckerID)
	require.NotEqual(t, report.Finding.MakerID, report.Verification.CheckerID)
	require.Len(t, report.Evidence, 1)
	// Reopening the service preserves the task, evidence and reviewed report.
	reopened, err := New(filepath.Join(root, "scans"), store, scanner, authorize, func(string, string, string, string) error { return nil })
	require.NoError(t, err)
	_, err = reopened.Report(t.Context(), "session-1", r.ID)
	require.NoError(t, err)
	records, err := reopened.List("session-1")
	require.NoError(t, err)
	require.Len(t, records, 1)
	records, err = reopened.List("other-session")
	require.NoError(t, err)
	require.Empty(t, records)
	pending, err := reopened.Prepare(t.Context(), "session-1", "analyst", root)
	require.NoError(t, err)
	require.NoError(t, reopened.Cancel("session-1", pending.ID))
	_, err = reopened.Run(t.Context(), "session-1", pending.ID)
	require.ErrorContains(t, err, "not pending")
	rejected, err := reopened.Prepare(t.Context(), "session-1", "analyst", root)
	require.NoError(t, err)
	_, err = reopened.Run(t.Context(), "session-1", rejected.ID)
	require.NoError(t, err)
	_, err = reopened.Review(t.Context(), "session-1", rejected.ID, evidence.VerdictPassed, "")
	require.Error(t, err)
	_, err = reopened.Review(t.Context(), "session-1", rejected.ID, evidence.VerdictRejected, "Package not applicable")
	require.NoError(t, err)
	_, err = reopened.Report(t.Context(), "session-1", rejected.ID)
	require.Error(t, err)
	reopened.Close()
	authorized.Store(false)
	_, err = reopened.Prepare(t.Context(), "session-1", "analyst", root)
	require.ErrorContains(t, err, "denied")
}

func TestRevocationCancelsInFlightScan(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := evidence.NewFileStore(filepath.Join(root, "evidence"))
	require.NoError(t, err)
	var revoked atomic.Bool
	started := make(chan struct{})
	service, err := New(filepath.Join(root, "scans"), store, scannerFunc(func(ctx context.Context, _ interface{}) (interface{}, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}), func(string, string, string) error {
		if revoked.Load() {
			return errors.New("revoked")
		}
		return nil
	}, func(string, string, string, string) error { return nil })
	require.NoError(t, err)
	r, err := service.Prepare(t.Context(), "s", "analyst", root)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, err := service.Run(t.Context(), "s", r.ID); done <- err }()
	<-started
	revoked.Store(true)
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("revocation did not stop scan")
	}
	r, err = service.Get("s", r.ID)
	require.NoError(t, err)
	require.Equal(t, "canceled", r.State)
	_, err = service.Report(t.Context(), "s", r.ID)
	require.Error(t, err)
}

func TestAuditFailurePreventsScanner(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := evidence.NewFileStore(filepath.Join(root, "evidence"))
	require.NoError(t, err)
	service, err := New(filepath.Join(root, "scans"), store, scannerFunc(func(context.Context, interface{}) (interface{}, error) {
		t.Fatal("scanner executed without durable audit")
		return nil, nil
	}), func(string, string, string) error { return nil }, func(string, string, string, string) error { return errors.New("audit offline") })
	require.NoError(t, err)
	r, err := service.Prepare(t.Context(), "s", "analyst", root)
	require.NoError(t, err)
	_, err = service.Run(t.Context(), "s", r.ID)
	require.ErrorContains(t, err, "audit offline")
}
