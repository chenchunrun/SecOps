package secops

import (
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
				Metric:    "cpu_usage",
				StartTime: now.Add(-1 * time.Hour),
				EndTime:   now,
			},
			wantErr: false,
		},
		{
			name: "missing system",
			params: &MonitoringQueryParams{
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
				StartTime: now.Add(-1 * time.Hour),
				EndTime:   now,
			},
			wantErr: true,
		},
		{
			name: "invalid time range",
			params: &MonitoringQueryParams{
				System:    SystemPrometheus,
				Query:     "up",
				StartTime: now,
				EndTime:   now.Add(-1 * time.Hour),
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
	tool := NewMonitoringQueryTool(nil)

	now := time.Now()
	params := &MonitoringQueryParams{
		System:    SystemPrometheus,
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
	tool := NewMonitoringQueryTool(nil)

	now := time.Now()
	params := &MonitoringQueryParams{
		System:    SystemPrometheus,
		Metric:    "cpu_usage",
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tool.Execute(params)
	}
}
