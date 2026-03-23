package secops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMonitoringQueryTool_Type(t *testing.T) {
	tool := NewMonitoringQueryTool(nil)
	if tool.Type() != ToolTypeMonitoringQuery {
		t.Errorf("expected %v, got %v", ToolTypeMonitoringQuery, tool.Type())
	}
}

func TestMonitoringQueryTool_ValidateParams(t *testing.T) {
	tool := NewMonitoringQueryTool(nil)

	now := time.Now()

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name: "valid params with query",
			params: &MonitoringQueryParams{
				System:    SystemPrometheus,
				Endpoint:  "http://localhost:9090",
				Query:     "up",
				StartTime: now.Add(-1 * time.Hour),
				EndTime:   now,
			},
			wantErr: false,
		},
		{
			name: "valid params with metric",
			params: &MonitoringQueryParams{
				System:    SystemPrometheus,
				Endpoint:  "http://localhost:9090",
				Metric:    "cpu_usage",
				StartTime: now.Add(-1 * time.Hour),
				EndTime:   now,
			},
			wantErr: false,
		},
		{
			name: "valid influxdb params with metric",
			params: &MonitoringQueryParams{
				System:    SystemInfluxDB,
				Endpoint:  "http://localhost:8086",
				Database:  "metrics",
				Metric:    "cpu_usage",
				Field:     "usage",
				StartTime: now.Add(-1 * time.Hour),
				EndTime:   now,
			},
			wantErr: false,
		},
		{
			name: "missing system",
			params: &MonitoringQueryParams{
				Endpoint:  "http://localhost:9090",
				Query:     "up",
				StartTime: now.Add(-1 * time.Hour),
				EndTime:   now,
			},
			wantErr: true,
		},
		{
			name: "missing query and metric",
			params: &MonitoringQueryParams{
				System:    SystemPrometheus,
				Endpoint:  "http://localhost:9090",
				StartTime: now.Add(-1 * time.Hour),
				EndTime:   now,
			},
			wantErr: true,
		},
		{
			name: "invalid time range",
			params: &MonitoringQueryParams{
				System:    SystemPrometheus,
				Endpoint:  "http://localhost:9090",
				Query:     "up",
				StartTime: now,
				EndTime:   now.Add(-1 * time.Hour),
			},
			wantErr: true,
		},
		{
			name: "query too long",
			params: &MonitoringQueryParams{
				System:    SystemPrometheus,
				Endpoint:  "http://localhost:9090",
				Query:     strings.Repeat("a", 2001),
				StartTime: now.Add(-1 * time.Hour),
				EndTime:   now,
			},
			wantErr: true,
		},
		{
			name: "influxdb missing database",
			params: &MonitoringQueryParams{
				System:    SystemInfluxDB,
				Endpoint:  "http://localhost:8086",
				Metric:    "cpu_usage",
				StartTime: now.Add(-1 * time.Hour),
				EndTime:   now,
			},
			wantErr: true,
		},
		{
			name: "invalid remote port",
			params: &MonitoringQueryParams{
				System:     SystemPrometheus,
				Endpoint:   "http://localhost:9090",
				Query:      "up",
				StartTime:  now.Add(-1 * time.Hour),
				EndTime:    now,
				RemoteHost: "10.0.0.70",
				RemotePort: 70000,
			},
			wantErr: true,
		},
		{
			name: "remote option without host",
			params: &MonitoringQueryParams{
				System:     SystemPrometheus,
				Endpoint:   "http://localhost:9090",
				Query:      "up",
				StartTime:  now.Add(-1 * time.Hour),
				EndTime:    now,
				RemoteUser: "ops",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tool.ValidateParams(tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMonitoringQueryTool_Execute(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/v1/query_range") {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"result":[{"metric":{"__name__":"cpu_usage","instance":"local"},"values":[[1700000000,"0.95"],[1700000600,"0.98"]]}]}}`))
	}))
	defer ts.Close()

	tool := NewMonitoringQueryTool(nil)

	now := time.Now()
	params := &MonitoringQueryParams{
		System:    SystemPrometheus,
		Endpoint:  ts.URL,
		Metric:    "cpu_usage",
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	queryResult, ok := result.(*MonitoringQueryResult)
	if !ok {
		t.Fatal("expected MonitoringQueryResult")
	}

	if queryResult.System != SystemPrometheus {
		t.Errorf("expected system %v, got %v", SystemPrometheus, queryResult.System)
	}

	if len(queryResult.Series) == 0 {
		t.Error("expected non-empty series")
	}
	if len(queryResult.Series[0].Points) == 0 {
		t.Error("expected non-empty points")
	}
}

func TestMonitoringQueryTool_ExecuteRemotePrometheus(t *testing.T) {
	tool := NewMonitoringQueryTool(nil)
	var gotName string
	var gotArgs []string
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return []byte(`{"status":"success","data":{"result":[{"metric":{"__name__":"cpu_usage","instance":"remote"},"values":[[1700000000,"0.92"],[1700000600,"0.96"]]}]}}`), nil, nil
	}

	now := time.Now()
	result, err := tool.Execute(&MonitoringQueryParams{
		System:          SystemPrometheus,
		Endpoint:        "http://127.0.0.1:9090",
		Metric:          "cpu_usage",
		StartTime:       now.Add(-1 * time.Hour),
		EndTime:         now,
		RemoteHost:      "10.0.0.70",
		RemoteUser:      "ops",
		RemotePort:      2222,
		RemoteKeyPath:   "/tmp/id_ed25519",
		RemoteProxyJump: "bastion",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	qr := result.(*MonitoringQueryResult)
	if len(qr.Series) == 0 || len(qr.Series[0].Points) == 0 {
		t.Fatalf("expected remote series points, got %+v", qr.Series)
	}
	if gotName != "ssh" {
		t.Fatalf("expected ssh command, got %s", gotName)
	}
	if !strings.Contains(strings.Join(gotArgs, " "), "ops@10.0.0.70") {
		t.Fatalf("unexpected ssh args: %q", strings.Join(gotArgs, " "))
	}
}

func TestMonitoringQueryTool_ExecuteInfluxDB(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/query" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if got := q.Get("db"); got != "metrics" {
			t.Fatalf("expected db=metrics, got %s", got)
		}
		if got := q.Get("epoch"); got != "ms" {
			t.Fatalf("expected epoch=ms, got %s", got)
		}
		if !strings.Contains(q.Get("q"), `SELECT mean("usage") FROM "cpu_usage"`) {
			t.Fatalf("unexpected query: %s", q.Get("q"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"series":[{"name":"cpu_usage","tags":{"host":"local"},"columns":["time","mean"],"values":[[1700000000000,0.95],[1700000600000,0.98]]}]}]}`))
	}))
	defer ts.Close()

	tool := NewMonitoringQueryTool(nil)

	now := time.Now()
	params := &MonitoringQueryParams{
		System:      SystemInfluxDB,
		Endpoint:    ts.URL,
		Database:    "metrics",
		Metric:      "cpu_usage",
		Field:       "usage",
		Aggregation: "mean",
		StartTime:   now.Add(-1 * time.Hour),
		EndTime:     now,
		Step:        30 * time.Second,
	}

	result, err := tool.Execute(params)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	queryResult, ok := result.(*MonitoringQueryResult)
	if !ok {
		t.Fatal("expected MonitoringQueryResult")
	}
	if queryResult.System != SystemInfluxDB {
		t.Fatalf("expected system %v, got %v", SystemInfluxDB, queryResult.System)
	}
	if len(queryResult.Series) != 1 {
		t.Fatalf("expected 1 series, got %d", len(queryResult.Series))
	}
	if got := len(queryResult.Series[0].Points); got != 2 {
		t.Fatalf("expected 2 points, got %d", got)
	}
	if queryResult.Series[0].Labels["host"] != "local" {
		t.Fatalf("expected host label local, got %v", queryResult.Series[0].Labels)
	}
	if queryResult.Stats == nil || queryResult.Stats.Count != 2 {
		t.Fatalf("expected stats with 2 points, got %+v", queryResult.Stats)
	}
}

func TestMonitoringQueryTool_CalculateStats(t *testing.T) {
	tool := NewMonitoringQueryTool(nil)

	series := []*MetricSeries{
		{
			Name: "cpu_usage",
			Points: []*MetricPoint{
				{Timestamp: time.Now(), Value: 10.0},
				{Timestamp: time.Now(), Value: 20.0},
				{Timestamp: time.Now(), Value: 30.0},
				{Timestamp: time.Now(), Value: 40.0},
				{Timestamp: time.Now(), Value: 50.0},
			},
		},
	}

	stats := tool.calculateStats(series)

	if stats.Count != 5 {
		t.Errorf("expected count 5, got %d", stats.Count)
	}

	if stats.Min != 10.0 {
		t.Errorf("expected min 10.0, got %f", stats.Min)
	}

	if stats.Max != 50.0 {
		t.Errorf("expected max 50.0, got %f", stats.Max)
	}

	if stats.Avg != 30.0 {
		t.Errorf("expected avg 30.0, got %f", stats.Avg)
	}
}

func TestMonitoringQueryTool_CheckThresholds(t *testing.T) {
	tool := NewMonitoringQueryTool(nil)

	result := &MonitoringQueryResult{
		Stats: &MetricStats{
			Count: 10,
			Min:   20.0,
			Max:   90.0,
			Avg:   50.0,
		},
	}

	thresholds := map[string]float64{
		"cpu":    40.0,
		"memory": 85.0,
	}

	alerts := tool.CheckThresholds(result, thresholds)

	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(alerts))
	}

	// 检查 CPU 告警
	cpuAlert := alerts[0]
	if cpuAlert.Name != "HighCPU" {
		t.Errorf("expected HighCPU alert, got %s", cpuAlert.Name)
	}

	if cpuAlert.Severity != "warning" {
		t.Errorf("expected warning severity, got %s", cpuAlert.Severity)
	}
}

func TestMonitoringQueryTool_ExecuteUnsupportedSystem(t *testing.T) {
	tool := NewMonitoringQueryTool(nil)

	now := time.Now()
	params := &MonitoringQueryParams{
		System:    MetricsSystem("unsupported"),
		Endpoint:  "http://localhost:9090",
		Metric:    "cpu_usage",
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	}

	_, err := tool.Execute(params)
	if err == nil {
		t.Error("expected error for unsupported system")
	}
}

func BenchmarkMonitoringQueryTool_Execute(b *testing.B) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"result":[{"metric":{"__name__":"cpu_usage"},"values":[[1700000000,"0.95"],[1700000600,"0.98"]]}]}}`))
	}))
	defer ts.Close()

	tool := NewMonitoringQueryTool(nil)

	now := time.Now()
	params := &MonitoringQueryParams{
		System:    SystemPrometheus,
		Endpoint:  ts.URL,
		Metric:    "cpu_usage",
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}
