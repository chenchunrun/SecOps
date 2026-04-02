package execution

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoteExecutorRequiresHost(t *testing.T) {
	t.Parallel()

	executor := NewRemoteExecutor()
	_, err := executor.Execute(context.Background(), RemoteRequest{
		Command: "hostname",
	})
	require.Error(t, err)
	require.EqualError(t, err, "remote_host is required for remote execution")
}

func TestFormatRemoteTarget(t *testing.T) {
	t.Parallel()

	require.Equal(t, "10.0.0.10", formatRemoteTarget("", "10.0.0.10"))
	require.Equal(t, "ops@10.0.0.10", formatRemoteTarget("ops", "10.0.0.10"))
	require.Equal(t, "", formatRemoteTarget("ops", ""))
}

func TestShellQuoteSingle(t *testing.T) {
	t.Parallel()

	require.Equal(t, "'/var/log/app'", shellQuoteSingle("/var/log/app"))
	require.Equal(t, `'a'"'"'b'`, shellQuoteSingle("a'b"))
}
