package secops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// MetricsSystem 指标系统
type MetricsSystem string

const (
	SystemPrometheus MetricsSystem = "prometheus"
	SystemGrafana    MetricsSystem = "grafana"
	SystemDatadog    MetricsSystem = "datadog"
	SystemNewRelic   MetricsSystem = "newrelic"
	SystemInfluxDB   MetricsSystem = "influxdb"
)

// MonitoringQueryParams 监控查询参数
type MonitoringQueryParams struct {
	// 系统配置
	System     MetricsSystem `json:"system"`
	Endpoint   string        `json:"endpoint"`
	Credential string        `json:"credential,omitempty"`
	Database   string        `json:"database,omitempty"`

	// 查询条件
	Query  string            `json:"query"`            // PromQL, DataDog query 等
	Metric string            `json:"metric,omitempty"` // 指标名称
	Field  string            `json:"field,omitempty"`  // InfluxDB field
	Labels map[string]string `json:"labels,omitempty"` // 标签过滤

	// 时间范围
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	// 聚合选项
	Step        time.Duration `json:"step,omitempty"`
	Aggregation string        `json:"aggregation,omitempty"` // avg, sum, max, min, p99 等
}

// MetricPoint 指标数据点
type MetricPoint struct {
	Timestamp time.Time         `json:"timestamp"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// MetricSeries 指标序列
type MetricSeries struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	Points []*MetricPoint    `json:"points"`
}

// MonitoringQueryResult 查询结果
type MonitoringQueryResult struct {
	System    MetricsSystem   `json:"system"`
	Query     string          `json:"query"`
	StartTime time.Time       `json:"start_time"`
	EndTime   time.Time       `json:"end_time"`
	Series    []*MetricSeries `json:"series"`
	Stats     *MetricStats    `json:"stats,omitempty"`
	Alerts    []*Alert        `json:"alerts,omitempty"`
}

// MetricStats 指标统计
type MetricStats struct {
	Count int     `json:"count"`
	Min   float64 `json:"min"`
	Max   float64 `json:"max"`
	Avg   float64 `json:"avg"`
	P50   float64 `json:"p50"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
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
	client   *http.Client
}

// NewMonitoringQueryTool 创建监控查询工具
func NewMonitoringQueryTool(registry *SecOpsToolRegistry) *MonitoringQueryTool {
	return &MonitoringQueryTool{
		registry: registry,
		client:   &http.Client{Timeout: 30 * time.Second},
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
	return "Query metrics from monitoring systems (Prometheus, Grafana, Datadog, NewRelic, InfluxDB)"
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
	if strings.TrimSpace(p.Endpoint) == "" {
		return fmt.Errorf("endpoint is required")
	}

	if p.StartTime.IsZero() || p.EndTime.IsZero() {
		return fmt.Errorf("start_time and end_time are required")
	}

	if p.StartTime.After(p.EndTime) {
		return ErrInvalidDateRange
	}

	if p.Step < 0 {
		return fmt.Errorf("step cannot be negative")
	}

	switch p.System {
	case SystemInfluxDB:
		if strings.TrimSpace(p.Database) == "" {
			return fmt.Errorf("database is required for influxdb")
		}
		if strings.TrimSpace(p.Query) == "" && strings.TrimSpace(p.Metric) == "" {
			return fmt.Errorf("query or metric is required for influxdb")
		}
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 根据系统类型执行查询
	var queryErr error
	switch p.System {
	case SystemPrometheus:
		queryErr = mqt.queryPrometheus(ctx, p, result)
	case SystemGrafana:
		queryErr = mqt.queryGrafana(ctx, p, result)
	case SystemDatadog:
		queryErr = mqt.queryDatadog(ctx, p, result)
	case SystemNewRelic:
		queryErr = mqt.queryNewRelic(ctx, p, result)
	case SystemInfluxDB:
		queryErr = mqt.queryInfluxDB(ctx, p, result)
	default:
		return nil, fmt.Errorf("unsupported system: %s", p.System)
	}
	if queryErr != nil {
		return nil, queryErr
	}

	// 计算统计
	if len(result.Series) > 0 {
		result.Stats = mqt.calculateStats(result.Series)
	}

	return result, nil
}

// 私有方法

// queryPrometheus Prometheus 查询
func (mqt *MonitoringQueryTool) queryPrometheus(ctx context.Context, params *MonitoringQueryParams, result *MonitoringQueryResult) error {
	u, err := url.Parse(strings.TrimRight(params.Endpoint, "/") + "/api/v1/query_range")
	if err != nil {
		return fmt.Errorf("invalid prometheus endpoint: %w", err)
	}
	q := u.Query()
	query := strings.TrimSpace(params.Query)
	if query == "" {
		query = strings.TrimSpace(params.Metric)
	}
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(params.StartTime.Unix(), 10))
	q.Set("end", strconv.FormatInt(params.EndTime.Unix(), 10))
	step := params.Step
	if step <= 0 {
		step = 60 * time.Second
	}
	q.Set("step", strconv.FormatFloat(step.Seconds(), 'f', -1, 64))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if params.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+params.Credential)
	}
	body, err := mqt.doRequest(req)
	if err != nil {
		return err
	}

	var payload struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Values [][]interface{}   `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("parse prometheus response: %w", err)
	}

	for _, item := range payload.Data.Result {
		series := &MetricSeries{
			Name:   params.Metric,
			Labels: item.Metric,
			Points: make([]*MetricPoint, 0, len(item.Values)),
		}
		if series.Name == "" {
			series.Name = item.Metric["__name__"]
		}
		for _, pair := range item.Values {
			if len(pair) < 2 {
				continue
			}
			tsFloat, ok := pair[0].(float64)
			if !ok {
				continue
			}
			valStr, ok := pair[1].(string)
			if !ok {
				continue
			}
			val, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				continue
			}
			series.Points = append(series.Points, &MetricPoint{
				Timestamp: time.Unix(int64(tsFloat), 0),
				Value:     val,
				Labels:    item.Metric,
			})
		}
		result.Series = append(result.Series, series)
	}

	return nil
}

// queryGrafana Grafana 查询
func (mqt *MonitoringQueryTool) queryGrafana(ctx context.Context, params *MonitoringQueryParams, result *MonitoringQueryResult) error {
	// Use Grafana's common Prometheus proxy endpoint.
	inner := *params
	inner.Endpoint = strings.TrimRight(params.Endpoint, "/") + "/api/datasources/proxy/1"
	return mqt.queryPrometheus(ctx, &inner, result)
}

// queryDatadog Datadog 查询
func (mqt *MonitoringQueryTool) queryDatadog(ctx context.Context, params *MonitoringQueryParams, result *MonitoringQueryResult) error {
	u, err := url.Parse(strings.TrimRight(params.Endpoint, "/") + "/api/v1/query")
	if err != nil {
		return fmt.Errorf("invalid datadog endpoint: %w", err)
	}
	q := u.Query()
	query := strings.TrimSpace(params.Query)
	if query == "" {
		query = strings.TrimSpace(params.Metric)
	}
	q.Set("query", query)
	q.Set("from", strconv.FormatInt(params.StartTime.Unix(), 10))
	q.Set("to", strconv.FormatInt(params.EndTime.Unix(), 10))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if params.Credential != "" {
		req.Header.Set("DD-API-KEY", params.Credential)
		req.Header.Set("DD-APPLICATION-KEY", params.Credential)
	}
	body, err := mqt.doRequest(req)
	if err != nil {
		return err
	}

	var payload struct {
		Series []struct {
			Metric    string      `json:"metric"`
			Scope     string      `json:"scope"`
			Pointlist [][]float64 `json:"pointlist"`
		} `json:"series"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("parse datadog response: %w", err)
	}

	for _, item := range payload.Series {
		labels := map[string]string{}
		if item.Scope != "" {
			labels["scope"] = item.Scope
		}
		series := &MetricSeries{
			Name:   item.Metric,
			Labels: labels,
			Points: make([]*MetricPoint, 0, len(item.Pointlist)),
		}
		for _, pair := range item.Pointlist {
			if len(pair) < 2 {
				continue
			}
			// Datadog timestamp in milliseconds.
			ts := int64(pair[0]) / 1000
			series.Points = append(series.Points, &MetricPoint{
				Timestamp: time.Unix(ts, 0),
				Value:     pair[1],
				Labels:    labels,
			})
		}
		result.Series = append(result.Series, series)
	}

	return nil
}

// queryNewRelic NewRelic 查询
func (mqt *MonitoringQueryTool) queryNewRelic(ctx context.Context, params *MonitoringQueryParams, result *MonitoringQueryResult) error {
	u := strings.TrimRight(params.Endpoint, "/") + "/v1/accounts/events/query"
	query := strings.TrimSpace(params.Query)
	if query == "" {
		query = strings.TrimSpace(params.Metric)
	}
	payload := map[string]interface{}{
		"query": query,
		"from":  params.StartTime.Format(time.RFC3339),
		"to":    params.EndTime.Format(time.RFC3339),
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if params.Credential != "" {
		req.Header.Set("Api-Key", params.Credential)
	}
	body, err := mqt.doRequest(req)
	if err != nil {
		return err
	}

	var nr struct {
		Results []struct {
			Timestamp string  `json:"timestamp"`
			Value     float64 `json:"value"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &nr); err != nil {
		return fmt.Errorf("parse newrelic response: %w", err)
	}

	series := &MetricSeries{
		Name:   query,
		Labels: map[string]string{"source": "newrelic"},
		Points: make([]*MetricPoint, 0, len(nr.Results)),
	}
	for _, item := range nr.Results {
		ts, err := time.Parse(time.RFC3339, item.Timestamp)
		if err != nil {
			continue
		}
		series.Points = append(series.Points, &MetricPoint{
			Timestamp: ts,
			Value:     item.Value,
			Labels:    series.Labels,
		})
	}
	result.Series = append(result.Series, series)
	return nil
}

// queryInfluxDB InfluxDB 查询
func (mqt *MonitoringQueryTool) queryInfluxDB(ctx context.Context, params *MonitoringQueryParams, result *MonitoringQueryResult) error {
	u, err := url.Parse(strings.TrimRight(params.Endpoint, "/") + "/query")
	if err != nil {
		return fmt.Errorf("invalid influxdb endpoint: %w", err)
	}

	query, err := mqt.buildInfluxQuery(params)
	if err != nil {
		return err
	}

	q := u.Query()
	q.Set("db", strings.TrimSpace(params.Database))
	q.Set("q", query)
	q.Set("epoch", "ms")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if params.Credential != "" {
		req.Header.Set("Authorization", "Token "+params.Credential)
	}

	body, err := mqt.doRequest(req)
	if err != nil {
		return err
	}

	var payload struct {
		Results []struct {
			Error string `json:"error"`
			Series []struct {
				Name    string            `json:"name"`
				Tags    map[string]string `json:"tags"`
				Columns []string          `json:"columns"`
				Values  [][]interface{}   `json:"values"`
			} `json:"series"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("parse influxdb response: %w", err)
	}

	for _, item := range payload.Results {
		if strings.TrimSpace(item.Error) != "" {
			return fmt.Errorf("influxdb query error: %s", item.Error)
		}
		for _, seriesItem := range item.Series {
			series := &MetricSeries{
				Name:   seriesItem.Name,
				Labels: make(map[string]string),
				Points: make([]*MetricPoint, 0, len(seriesItem.Values)),
			}
			for k, v := range seriesItem.Tags {
				series.Labels[k] = v
			}
			if series.Name == "" {
				series.Name = strings.TrimSpace(params.Metric)
			}

			for _, row := range seriesItem.Values {
				point, ok := influxPointFromRow(seriesItem.Columns, row)
				if !ok {
					continue
				}
				series.Points = append(series.Points, point)
			}
			result.Series = append(result.Series, series)
		}
	}

	return nil
}

func (mqt *MonitoringQueryTool) buildInfluxQuery(params *MonitoringQueryParams) (string, error) {
	query := strings.TrimSpace(params.Query)
	if query != "" {
		return query, nil
	}

	measurement := strings.TrimSpace(params.Metric)
	if measurement == "" {
		return "", fmt.Errorf("metric is required for influxdb when query is empty")
	}

	field := strings.TrimSpace(params.Field)
	if field == "" {
		field = "value"
	}

	expression := quoteInfluxIdentifier(field)
	aggregation := strings.ToLower(strings.TrimSpace(params.Aggregation))
	if aggregation != "" {
		expression = fmt.Sprintf("%s(%s)", aggregation, expression)
	}

	builder := strings.Builder{}
	builder.WriteString("SELECT ")
	builder.WriteString(expression)
	builder.WriteString(" FROM ")
	builder.WriteString(quoteInfluxIdentifier(measurement))

	conditions := make([]string, 0, 2+len(params.Labels))
	conditions = append(conditions,
		fmt.Sprintf("time >= %s", quoteInfluxTime(params.StartTime)),
		fmt.Sprintf("time <= %s", quoteInfluxTime(params.EndTime)),
	)
	for k, v := range params.Labels {
		conditions = append(conditions, fmt.Sprintf("%s = %s", quoteInfluxIdentifier(k), quoteInfluxString(v)))
	}
	if len(conditions) > 0 {
		builder.WriteString(" WHERE ")
		builder.WriteString(strings.Join(conditions, " AND "))
	}

	step := params.Step
	if step <= 0 {
		step = 60 * time.Second
	}
	builder.WriteString(" GROUP BY time(")
	builder.WriteString(formatInfluxDuration(step))
	builder.WriteString(") fill(null)")

	return builder.String(), nil
}

func influxPointFromRow(columns []string, row []interface{}) (*MetricPoint, bool) {
	if len(columns) == 0 || len(row) == 0 {
		return nil, false
	}

	timeIdx := 0
	for i, col := range columns {
		if strings.EqualFold(col, "time") {
			timeIdx = i
			break
		}
	}
	if timeIdx >= len(row) {
		return nil, false
	}

	ts, ok := parseInfluxTimestamp(row[timeIdx])
	if !ok {
		return nil, false
	}

	valueFound := false
	var value float64
	for i := range row {
		if i == timeIdx {
			continue
		}
		if parsed, ok := parseInfluxFloat(row[i]); ok {
			value = parsed
			valueFound = true
			break
		}
	}
	if !valueFound {
		return nil, false
	}

	return &MetricPoint{
		Timestamp: ts,
		Value:     value,
	}, true
}

func parseInfluxTimestamp(value interface{}) (time.Time, bool) {
	switch v := value.(type) {
	case float64:
		return unixValueToTime(v), true
	case int64:
		return unixValueToTime(float64(v)), true
	case json.Number:
		parsed, err := v.Float64()
		if err != nil {
			return time.Time{}, false
		}
		return unixValueToTime(parsed), true
	case string:
		layouts := []string{time.RFC3339Nano, time.RFC3339}
		for _, layout := range layouts {
			if ts, err := time.Parse(layout, v); err == nil {
				return ts, true
			}
		}
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			return unixIntToTime(parsed), true
		}
		return time.Time{}, false
	default:
		return time.Time{}, false
	}
}

func parseInfluxFloat(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case int64:
		return float64(v), true
	case json.Number:
		parsed, err := v.Float64()
		if err != nil {
			return 0, false
		}
		return parsed, true
	case string:
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func unixValueToTime(value float64) time.Time {
	return unixIntToTime(int64(value))
}

func unixIntToTime(value int64) time.Time {
	switch {
	case value > 1_000_000_000_000_000:
		return time.Unix(0, value)
	case value > 1_000_000_000_000:
		return time.UnixMilli(value)
	default:
		return time.Unix(value, 0)
	}
}

func quoteInfluxIdentifier(value string) string {
	return `"` + strings.ReplaceAll(strings.TrimSpace(value), `"`, `\"`) + `"`
}

func quoteInfluxString(value string) string {
	return `'` + strings.ReplaceAll(strings.TrimSpace(value), `'`, `\'`) + `'`
}

func quoteInfluxTime(value time.Time) string {
	return quoteInfluxString(value.UTC().Format(time.RFC3339Nano))
}

func formatInfluxDuration(value time.Duration) string {
	if value <= 0 {
		return "60s"
	}
	if value%time.Second == 0 {
		return fmt.Sprintf("%ds", int64(value/time.Second))
	}
	if value%time.Millisecond == 0 {
		return fmt.Sprintf("%dms", int64(value/time.Millisecond))
	}
	return value.String()
}

func (mqt *MonitoringQueryTool) doRequest(req *http.Request) ([]byte, error) {
	client := mqt.client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("query failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
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
