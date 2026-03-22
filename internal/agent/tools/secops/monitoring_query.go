package secops

import (
	"fmt"
	"time"
)

// MetricsSystem 指标系统
type MetricsSystem string

const (
	SystemPrometheus MetricsSystem = "prometheus"
	SystemGrafana    MetricsSystem = "grafana"
	SystemDatadog    MetricsSystem = "datadog"
	SystemNewRelic   MetricsSystem = "newrelic"
)

// MonitoringQueryParams 监控查询参数
type MonitoringQueryParams struct {
	// 系统配置
	System     MetricsSystem `json:"system"`
	Endpoint   string        `json:"endpoint"`
	Credential string        `json:"credential,omitempty"`

	// 查询条件
	Query      string        `json:"query"`       // PromQL, DataDog query 等
	Metric     string        `json:"metric,omitempty"` // 指标名称
	Labels     map[string]string `json:"labels,omitempty"` // 标签过滤

	// 时间范围
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`

	// 聚合选项
	Step       time.Duration `json:"step,omitempty"`
	Aggregation string        `json:"aggregation,omitempty"` // avg, sum, max, min, p99 等
}

// MetricPoint 指标数据点
type MetricPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// MetricSeries 指标序列
type MetricSeries struct {
	Name   string         `json:"name"`
	Labels map[string]string `json:"labels"`
	Points []*MetricPoint `json:"points"`
}

// MonitoringQueryResult 查询结果
type MonitoringQueryResult struct {
	System       MetricsSystem `json:"system"`
	Query        string        `json:"query"`
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	Series       []*MetricSeries `json:"series"`
	Stats        *MetricStats  `json:"stats,omitempty"`
	Alerts       []*Alert      `json:"alerts,omitempty"`
}

// MetricStats 指标统计
type MetricStats struct {
	Count   int     `json:"count"`
	Min     float64 `json:"min"`
	Max     float64 `json:"max"`
	Avg     float64 `json:"avg"`
	P50     float64 `json:"p50"`
	P95     float64 `json:"p95"`
	P99     float64 `json:"p99"`
}

// Alert 告警
type Alert struct {
	Name        string    `json:"name"`
	Condition   string    `json:"condition"`
	Value       float64   `json:"value"`
	Threshold   float64   `json:"threshold"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// MonitoringQueryTool 监控查询工具
type MonitoringQueryTool struct {
	registry *SecOpsToolRegistry
}

// NewMonitoringQueryTool 创建监控查询工具
func NewMonitoringQueryTool(registry *SecOpsToolRegistry) *MonitoringQueryTool {
	return &MonitoringQueryTool{
		registry: registry,
	}
}

// Type 实现 Tool.Type
func (mqt *MonitoringQueryTool) Type() ToolType {
	return ToolTypeMonitoringQuery
}

// Name 实现 Tool.Name
func (mqt *MonitoringQueryTool) Name() string {
	return "Monitoring Query"
}

// Description 实现 Tool.Description
func (mqt *MonitoringQueryTool) Description() string {
	return "Query metrics from monitoring systems (Prometheus, Grafana, Datadog, NewRelic)"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (mqt *MonitoringQueryTool) RequiredCapabilities() []string {
	return []string{
		"monitoring:query",
	}
}

// ValidateParams 实现 Tool.ValidateParams
func (mqt *MonitoringQueryTool) ValidateParams(params interface{}) error {
	p, ok := params.(*MonitoringQueryParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.System == "" {
		return fmt.Errorf("system is required")
	}

	if p.Query == "" && p.Metric == "" {
		return fmt.Errorf("query or metric is required")
	}

	if p.StartTime.IsZero() || p.EndTime.IsZero() {
		return fmt.Errorf("start_time and end_time are required")
	}

	if p.StartTime.After(p.EndTime) {
		return ErrInvalidDateRange
	}

	// Enforce query complexity limits to prevent ReDoS and large PromQL
	// subqueries that could overwhelm the monitoring backend.
	if len(p.Query) > 2000 {
		return fmt.Errorf("query exceeds maximum length of 2000 characters")
	}

	return nil
}

// Execute 实现 Tool.Execute
func (mqt *MonitoringQueryTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*MonitoringQueryParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := mqt.ValidateParams(p); err != nil {
		return nil, err
	}

	result := &MonitoringQueryResult{
		System:    p.System,
		Query:     p.Query,
		StartTime: p.StartTime,
		EndTime:   p.EndTime,
		Series:    make([]*MetricSeries, 0),
		Alerts:    make([]*Alert, 0),
	}

	// 根据系统类型执行查询
	switch p.System {
	case SystemPrometheus:
		mqt.queryPrometheus(p, result)
	case SystemGrafana:
		mqt.queryGrafana(p, result)
	case SystemDatadog:
		mqt.queryDatadog(p, result)
	case SystemNewRelic:
		mqt.queryNewRelic(p, result)
	default:
		return nil, fmt.Errorf("unsupported system: %s", p.System)
	}

	// 计算统计
	if len(result.Series) > 0 {
		result.Stats = mqt.calculateStats(result.Series)
	}

	return result, nil
}

// 私有方法

// queryPrometheus Prometheus 查询
func (mqt *MonitoringQueryTool) queryPrometheus(params *MonitoringQueryParams, result *MonitoringQueryResult) {
	// TODO: 实现 Prometheus 查询
	// 这是一个占位符实现

	series := &MetricSeries{
		Name: params.Metric,
		Labels: map[string]string{
			"job": "prometheus",
		},
		Points: []*MetricPoint{
			{
				Timestamp: params.StartTime,
				Value:     0.95,
			},
			{
				Timestamp: params.EndTime,
				Value:     0.98,
			},
		},
	}

	result.Series = append(result.Series, series)
}

// queryGrafana Grafana 查询
func (mqt *MonitoringQueryTool) queryGrafana(params *MonitoringQueryParams, result *MonitoringQueryResult) {
	// TODO: 实现 Grafana 查询
	series := &MetricSeries{
		Name: params.Metric,
		Labels: map[string]string{
			"source": "grafana",
		},
		Points: make([]*MetricPoint, 0),
	}
	result.Series = append(result.Series, series)
}

// queryDatadog Datadog 查询
func (mqt *MonitoringQueryTool) queryDatadog(params *MonitoringQueryParams, result *MonitoringQueryResult) {
	// TODO: 实现 Datadog 查询
	series := &MetricSeries{
		Name: params.Metric,
		Labels: map[string]string{
			"source": "datadog",
		},
		Points: make([]*MetricPoint, 0),
	}
	result.Series = append(result.Series, series)
}

// queryNewRelic NewRelic 查询
func (mqt *MonitoringQueryTool) queryNewRelic(params *MonitoringQueryParams, result *MonitoringQueryResult) {
	// TODO: 实现 NewRelic 查询
	series := &MetricSeries{
		Name: params.Metric,
		Labels: map[string]string{
			"source": "newrelic",
		},
		Points: make([]*MetricPoint, 0),
	}
	result.Series = append(result.Series, series)
}

// calculateStats 计算统计信息
func (mqt *MonitoringQueryTool) calculateStats(series []*MetricSeries) *MetricStats {
	stats := &MetricStats{}

	if len(series) == 0 {
		return stats
	}

	totalPoints := 0
	var sum float64
	var min, max float64
	var values []float64

	for _, s := range series {
		for _, point := range s.Points {
			totalPoints++
			sum += point.Value
			values = append(values, point.Value)

			if min == 0 || point.Value < min {
				min = point.Value
			}
			if max == 0 || point.Value > max {
				max = point.Value
			}
		}
	}

	if totalPoints == 0 {
		return stats
	}

	stats.Count = totalPoints
	stats.Min = min
	stats.Max = max
	stats.Avg = sum / float64(totalPoints)

	// 计算百分位数（简化实现）
	if len(values) > 0 {
		stats.P50 = values[len(values)/2]
		stats.P95 = values[(len(values)*95)/100]
		stats.P99 = values[(len(values)*99)/100]
	}

	return stats
}

// CheckThresholds 检查阈值
func (mqt *MonitoringQueryTool) CheckThresholds(result *MonitoringQueryResult, thresholds map[string]float64) []*Alert {
	alerts := make([]*Alert, 0)

	if result.Stats == nil {
		return alerts
	}

	// 检查 CPU
	if cpuThreshold, ok := thresholds["cpu"]; ok {
		if result.Stats.Avg > cpuThreshold {
			alerts = append(alerts, &Alert{
				Name:        "HighCPU",
				Condition:   "avg_cpu > threshold",
				Value:       result.Stats.Avg,
				Threshold:   cpuThreshold,
				Severity:    "warning",
				Description: "Average CPU usage exceeds threshold",
				Timestamp:   time.Now(),
			})
		}
	}

	// 检查内存
	if memThreshold, ok := thresholds["memory"]; ok {
		if result.Stats.Max > memThreshold {
			alerts = append(alerts, &Alert{
				Name:        "HighMemory",
				Condition:   "max_memory > threshold",
				Value:       result.Stats.Max,
				Threshold:   memThreshold,
				Severity:    "critical",
				Description: "Memory usage exceeds critical threshold",
				Timestamp:   time.Now(),
			})
		}
	}

	return alerts
}
