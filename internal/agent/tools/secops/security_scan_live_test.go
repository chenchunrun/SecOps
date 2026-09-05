package secops

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRealTrivyCompatibility is opt-in because it downloads Trivy's public DB.
func TestRealTrivyCompatibility(t *testing.T) {
	if os.Getenv("SECOPS_TEST_TRIVY") != "1" {
		t.Skip("set SECOPS_TEST_TRIVY=1 with trivy on PATH to validate the real scanner")
	}
	version, err := exec.CommandContext(t.Context(), "trivy", "--version").Output()
	require.NoError(t, err)
	t.Log(string(version))
	tool := NewSecurityScanTool(nil)
	result, err := tool.ExecuteContext(t.Context(), &SecurityScanParams{Scanner: ScannerTrivy, Target: TargetFilesystem, TargetPath: t.TempDir(), ScanType: "vuln"})
	require.NoError(t, err)
	scan, ok := result.(*ScanResult)
	require.True(t, ok)
	require.Equal(t, ScannerTrivy, scan.Scanner)
	require.Zero(t, scan.TotalVulnerabilities)
	// Only a dependency inventory is written; no vulnerable code is installed.
	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, "requirements.txt"), []byte("Django==2.2.0\n"), 0o600))
	result, err = tool.ExecuteContext(t.Context(), &SecurityScanParams{Scanner: ScannerTrivy, Target: TargetFilesystem, TargetPath: directory, ScanType: "vuln"})
	require.NoError(t, err)
	scan = result.(*ScanResult)
	require.Positive(t, scan.TotalVulnerabilities)
	require.NotEmpty(t, scan.Vulnerabilities)
	t.Logf("Parsed %d reported vulnerabilities from the dependency fixture", scan.TotalVulnerabilities)
}
