package secops

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestScanCancellationReachesExecutor(t *testing.T) {
	t.Parallel()
	tool := NewSecurityScanTool(nil)
	started := make(chan struct{})
	tool.runCmd = func(ctx context.Context, _ string, _ ...string) ([]byte, []byte, error) {
		close(started)
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := tool.ExecuteContext(ctx, &SecurityScanParams{Scanner: ScannerTrivy, Target: TargetFilesystem, TargetPath: "."})
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("scan ignored cancellation")
	}
}

func TestScanUnsupportedFlagsFailBeforeExecution(t *testing.T) {
	t.Parallel()
	tool := NewSecurityScanTool(nil)
	tool.runCmd = func(context.Context, string, ...string) ([]byte, []byte, error) {
		t.Fatal("invalid request reached scanner")
		return nil, nil, nil
	}
	for _, params := range []*SecurityScanParams{
		{Scanner: ScannerTrivy, Target: TargetFilesystem, TargetPath: ".", Full: true},
		{Scanner: ScannerTrivy, Target: TargetFilesystem, TargetPath: ".", FixVulns: true},
	} {
		_, err := tool.ExecuteContext(t.Context(), params)
		require.ErrorContains(t, err, "not supported")
	}
}

func TestTrivyCVSSAcceptsVectorStringsAlongsideScores(t *testing.T) {
	t.Parallel()
	output := []byte(`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-fixture","Severity":"HIGH","CVSS":{"nvd":{"V3Score":8.1,"V3Vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N","V2Score":6.8,"V2Vector":"AV:N/AC:M/Au:N/C:P/I:P/A:P"}}}]}]}`)
	vulns, _, err := parseTrivyOutput(output)
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	require.Equal(t, 8.1, vulns[0].CVSS)
}
