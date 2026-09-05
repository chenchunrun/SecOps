package scan

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
	"github.com/chenchunrun/SecOps/internal/evidence"
	"github.com/stretchr/testify/require"
)

func TestInvalidScanOutputNeverBecomesEvidence(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"target", "scanner", "total", "counts", "nil-item", "cvss", "severity"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			store, err := evidence.NewFileStore(filepath.Join(root, "evidence"))
			require.NoError(t, err)
			scanner := scannerFunc(func(_ context.Context, raw interface{}) (interface{}, error) {
				p := raw.(*secops.SecurityScanParams)
				result := &secops.ScanResult{Scanner: secops.ScannerTrivy, Target: p.TargetPath, ScanTime: time.Now(), TotalVulnerabilities: 1, HighCount: 1, Vulnerabilities: []*secops.Vulnerability{{ID: "test", Severity: secops.VulnHigh}}}
				switch name {
				case "target":
					result.Target = "other-target"
				case "scanner":
					result.Scanner = secops.ScannerNuclei
				case "total":
					result.TotalVulnerabilities = -1
				case "counts":
					result.HighCount = 0
				case "nil-item":
					result.Vulnerabilities[0] = nil
				case "cvss":
					result.Vulnerabilities[0].CVSS = 11
				case "severity":
					result.Vulnerabilities[0].Severity = "invented"
				}
				return result, nil
			})
			service, err := New(filepath.Join(root, "tasks"), store, scanner, func(string, string, string) error { return nil }, func(string, string, string, string) error { return nil })
			require.NoError(t, err)
			defer service.Close()
			record, err := service.Prepare(t.Context(), "session", "analyst", root)
			require.NoError(t, err)
			record, err = service.Run(t.Context(), "session", record.ID)
			require.ErrorContains(t, err, "invalid scan output")
			require.Equal(t, "failed", record.State)
			require.Empty(t, record.EvidenceID)
			_, _, err = store.GetEvidence(t.Context(), record.ID+"-output")
			require.Error(t, err)
		})
	}
}
