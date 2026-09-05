package secops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	_ ContextTool = (*NetworkDiagnosticTool)(nil)
	_ ContextTool = (*MonitoringQueryTool)(nil)
)

func TestNetworkDiagnosticSessionCancellation(t *testing.T) {
	for _, kind := range []NetworkDiagnosticType{DiagnosticPing, DiagnosticTraceroute, DiagnosticMTR} {
		t.Run(string(kind), func(t *testing.T) {
			t.Setenv("SECOPS_NETWORK_DIAG_ALLOW_FALLBACK", "1")
			tool := NewNetworkDiagnosticTool(nil)
			started := make(chan struct{})
			tool.runCmd = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				result, err := tool.ExecuteContext(ctx, &NetworkDiagnosticParams{Type: kind, Target: "127.0.0.1", Timeout: 30})
				if result != nil {
					done <- nil
					return
				}
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("diagnostic did not start")
			}
			cancel()
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(time.Second):
				t.Fatal("diagnostic ignored cancellation")
			}
		})
	}
}

func TestDiagnosticCanceledBeforeExecution(t *testing.T) {
	t.Parallel()
	for _, kind := range []NetworkDiagnosticType{DiagnosticPing, DiagnosticTraceroute, DiagnosticMTR, DiagnosticDNS, DiagnosticPortScan} {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		result, err := NewNetworkDiagnosticTool(nil).ExecuteContext(ctx, &NetworkDiagnosticParams{Type: kind, Target: "127.0.0.1", Ports: []int{443}})
		require.Nil(t, result)
		require.ErrorIs(t, err, context.Canceled)
	}
}

func TestMonitoringSessionCancellation(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-t.Context().Done():
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := NewMonitoringQueryTool(nil).ExecuteContext(ctx, &MonitoringQueryParams{System: SystemPrometheus, Endpoint: server.URL, Query: "up", StartTime: time.Now().Add(-time.Hour), EndTime: time.Now()})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("monitoring request did not start")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("monitoring ignored cancellation")
	}
}
