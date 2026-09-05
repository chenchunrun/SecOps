package secops

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDataToolsCancelRunningCommand(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"database-local", "database-remote", "logs-remote", "backup-remote"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			started := make(chan struct{})
			runner := func(ctx context.Context, _ string, _ ...string) ([]byte, []byte, error) {
				close(started)
				<-ctx.Done()
				return nil, nil, ctx.Err()
			}
			var tool ContextTool
			var params interface{}
			switch name {
			case "database-local", "database-remote":
				db := NewDatabaseQueryTool(nil)
				db.runCmd = runner
				p := &DatabaseQueryParams{System: "mysql", Query: "SELECT 1"}
				if name == "database-remote" {
					p.RemoteHost = "localhost"
				}
				tool, params = db, p
			case "logs-remote":
				logs := NewLogAnalyzeTool(nil)
				logs.runCmd = runner
				tool, params = logs, &LogAnalyzeParams{Source: "system", RemoteHost: "localhost"}
			case "backup-remote":
				backup := NewBackupCheckTool(nil)
				backup.runCmd = runner
				tool, params = backup, &BackupCheckParams{SystemType: "files", Target: "/tmp", RemoteHost: "localhost"}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type response struct {
				result interface{}
				err    error
			}
			done := make(chan response, 1)
			go func() { result, err := tool.ExecuteContext(ctx, params); done <- response{result, err} }()
			select {
			case <-started:
			case r := <-done:
				t.Fatalf("execution stopped before command: %v", r.err)
			case <-time.After(time.Second):
				t.Fatal("command did not start")
			}
			cancel()
			select {
			case r := <-done:
				require.ErrorIs(t, r.err, context.Canceled)
				require.Nil(t, r.result, "cancellation must not produce evidence or fallback samples")
			case <-time.After(time.Second):
				t.Fatal("command ignored session cancellation")
			}
		})
	}
}

func TestDataToolsCanceledBeforeExecution(t *testing.T) {
	t.Parallel()
	for _, tool := range []ContextTool{NewDatabaseQueryTool(nil), NewLogAnalyzeTool(nil), NewBackupCheckTool(nil)} {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		result, err := tool.ExecuteContext(ctx, nil)
		require.Nil(t, result)
		require.ErrorIs(t, err, context.Canceled)
	}
}

func TestLogReadStopsBetweenFiles(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tool := NewLogAnalyzeTool(nil)
	tool.glob = func(string) ([]string, error) { return []string{"a.log", "b.log"}, nil }
	reads := 0
	tool.readFile = func(string) ([]byte, error) {
		reads++
		cancel()
		return []byte("test"), nil
	}
	result, err := tool.ExecuteContext(ctx, &LogAnalyzeParams{Source: "system"})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, result)
	require.Equal(t, 1, reads)
}
