package secops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// AlertCheckParams for checking alerts
type AlertCheckParams struct {
	System          string `json:"system"` // prometheus, grafana, datadog, pagerduty
	Filter          string `json:"filter"`
	Status          string `json:"status"` // firing, resolved, acknowledged
	TimeRange       string `json:"time_range"`
	Endpoint        string `json:"endpoint,omitempty"`
	APIToken        string `json:"api_token,omitempty"`
	RemoteHost      string `json:"remote_host,omitempty"`
	RemoteUser      string `json:"remote_user,omitempty"`
	RemotePort      int    `json:"remote_port,omitempty"`
	RemoteKeyPath   string `json:"remote_key_path,omitempty"`
	RemoteProxyJump string `json:"remote_proxy_jump,omitempty"`
}

// AlertCheckTool 告警检查工具
type AlertCheckTool struct {
	registry *SecOpsToolRegistry
	runCmd   func(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

// NewAlertCheckTool 创建告警检查工具
func NewAlertCheckTool(registry *SecOpsToolRegistry) *AlertCheckTool {
	return &AlertCheckTool{
		registry: registry,
		runCmd:   runAlertCommand,
	}
}

// Type 实现 Tool.Type
func (act *AlertCheckTool) Type() ToolType {
	return ToolTypeAlertCheck
}

// Name 实现 Tool.Name
func (act *AlertCheckTool) Name() string {
	return "Alert Check"
}

// Description 实现 Tool.Description
func (act *AlertCheckTool) Description() string {
	return "Check alerts from Prometheus, Grafana, Datadog, and PagerDuty"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (act *AlertCheckTool) RequiredCapabilities() []string {
	return []string{"monitoring:read", "alerting:read"}
}

// AlertInfo 告警信息
type AlertInfo struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Status      string            `json:"status"`   // firing, resolved, acknowledged
	Severity    string            `json:"severity"` // critical, warning, info
	FiredAt     time.Time         `json:"fired_at"`
	Message     string            `json:"message"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// AlertCheckResult 告警检查结果
type AlertCheckResult struct {
	System       string      `json:"system"`
	Total        int         `json:"total"`
	Firing       int         `json:"firing"`
	Resolved     int         `json:"resolved"`
	Acknowledged int         `json:"acknowledged"`
	Alerts       []AlertInfo `json:"alerts"`
	DataSource   string      `json:"data_source,omitempty"`   // live, fallback_sample
	FallbackReason string    `json:"fallback_reason,omitempty"`
}

// ValidateParams 实现 Tool.ValidateParams
func (act *AlertCheckTool) ValidateParams(params interface{}) error {
	p, ok := params.(*AlertCheckParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.System == "" {
		return fmt.Errorf("system is required")
	}

	validSystems := map[string]bool{
		"prometheus": true,
		"grafana":    true,
		"datadog":    true,
		"pagerduty":  true,
	}
	if !validSystems[p.System] {
		return fmt.Errorf("unsupported system: %s", p.System)
	}

	validStatuses := map[string]bool{
		"firing":       true,
		"resolved":     true,
		"acknowledged": true,
	}
	if p.Status != "" && !validStatuses[p.Status] {
		return fmt.Errorf("unsupported status: %s", p.Status)
	}
	if err := validateRemoteSSHParams(p.RemoteHost, p.RemoteUser, p.RemoteKeyPath, p.RemoteProxyJump, p.RemotePort); err != nil {
		return err
	}

	return nil
}

// Execute 实现 Tool.Execute
func (act *AlertCheckTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*AlertCheckParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := act.ValidateParams(p); err != nil {
		return nil, err
	}

	return act.performCheck(p), nil
}

// performCheck 执行告警检查
func (act *AlertCheckTool) performCheck(params *AlertCheckParams) *AlertCheckResult {
	result := &AlertCheckResult{
		System: params.System,
		Alerts: make([]AlertInfo, 0),
	}

	switch params.System {
	case "prometheus":
		if alerts := act.queryPrometheusAlerts(params); len(alerts) > 0 {
			result.Alerts = alerts
			result.DataSource = "live"
		} else {
			result.Alerts = act.getPrometheusAlerts(params)
			result.DataSource = "fallback_sample"
			result.FallbackReason = "prometheus alerts unavailable; returned built-in sample alerts"
		}
	case "grafana":
		if alerts := act.queryGrafanaAlerts(params); len(alerts) > 0 {
			result.Alerts = alerts
			result.DataSource = "live"
		} else {
			result.Alerts = act.getGrafanaAlerts(params)
			result.DataSource = "fallback_sample"
			result.FallbackReason = "grafana alerts unavailable; returned built-in sample alerts"
		}
	case "datadog":
		if alerts := act.queryDatadogAlerts(params); len(alerts) > 0 {
			result.Alerts = alerts
			result.DataSource = "live"
		} else {
			result.Alerts = act.getDatadogAlerts(params)
			result.DataSource = "fallback_sample"
			result.FallbackReason = "datadog alerts unavailable; returned built-in sample alerts"
		}
	case "pagerduty":
		if alerts := act.queryPagerDutyAlerts(params); len(alerts) > 0 {
			result.Alerts = alerts
			result.DataSource = "live"
		} else {
			result.Alerts = act.getPagerDutyAlerts(params)
			result.DataSource = "fallback_sample"
			result.FallbackReason = "pagerduty alerts unavailable; returned built-in sample alerts"
		}
	}

	result.Alerts = act.applyAlertFilters(result.Alerts, params)

	// 统计
	result.Total = len(result.Alerts)
	for _, a := range result.Alerts {
		switch a.Status {
		case "firing":
			result.Firing++
		case "resolved":
			result.Resolved++
		case "acknowledged":
			result.Acknowledged++
		}
	}

	// 按状态过滤
	if params.Status != "" {
		filtered := make([]AlertInfo, 0)
		for _, a := range result.Alerts {
			if a.Status == params.Status {
				filtered = append(filtered, a)
			}
		}
		result.Alerts = filtered
		result.Total = len(result.Alerts)
		// 重新统计
		result.Firing = 0
		result.Resolved = 0
		result.Acknowledged = 0
		for _, a := range result.Alerts {
			switch a.Status {
			case "firing":
				result.Firing++
			case "resolved":
				result.Resolved++
			case "acknowledged":
				result.Acknowledged++
			}
		}
	}

	return result
}

func (act *AlertCheckTool) applyAlertFilters(alerts []AlertInfo, params *AlertCheckParams) []AlertInfo {
	filtered := alerts

	if params.TimeRange != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(params.TimeRange)); err == nil && d > 0 {
			cutoff := time.Now().Add(-d)
			tmp := make([]AlertInfo, 0, len(filtered))
			for _, a := range filtered {
				if a.FiredAt.IsZero() || !a.FiredAt.Before(cutoff) {
					tmp = append(tmp, a)
				}
			}
			filtered = tmp
		}
	}

	if strings.TrimSpace(params.Filter) != "" {
		needle := strings.ToLower(strings.TrimSpace(params.Filter))
		tmp := make([]AlertInfo, 0, len(filtered))
		for _, a := range filtered {
			if alertMatchesFilter(a, needle) {
				tmp = append(tmp, a)
			}
		}
		filtered = tmp
	}

	return filtered
}

func alertMatchesFilter(a AlertInfo, needle string) bool {
	if strings.Contains(strings.ToLower(a.Name), needle) ||
		strings.Contains(strings.ToLower(a.Message), needle) ||
		strings.Contains(strings.ToLower(a.ID), needle) {
		return true
	}

	for k, v := range a.Labels {
		if strings.Contains(strings.ToLower(k), needle) || strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}
	for k, v := range a.Annotations {
		if strings.Contains(strings.ToLower(k), needle) || strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}

	return false
}

// getPrometheusAlerts 获取 Prometheus 告警
func (act *AlertCheckTool) getPrometheusAlerts(params *AlertCheckParams) []AlertInfo {
	if alerts := act.queryPrometheusAlerts(params); len(alerts) > 0 {
		return alerts
	}
	return []AlertInfo{
		{
			ID:       "prometheus-001",
			Name:     "HighCPUUsage",
			Status:   "firing",
			Severity: "warning",
			FiredAt:  time.Now().Add(-30 * time.Minute),
			Message:  "CPU usage above 80% for 5 minutes",
			Labels:   map[string]string{"pod": "api-server-0", "namespace": "production"},
		},
		{
			ID:       "prometheus-002",
			Name:     "HighMemoryUsage",
			Status:   "firing",
			Severity: "critical",
			FiredAt:  time.Now().Add(-15 * time.Minute),
			Message:  "Memory usage above 90% for 3 minutes",
			Labels:   map[string]string{"pod": "worker-1", "namespace": "production"},
		},
		{
			ID:       "prometheus-003",
			Name:     "DiskSpaceLow",
			Status:   "resolved",
			Severity: "warning",
			FiredAt:  time.Now().Add(-2 * time.Hour),
			Message:  "Disk space below 20% on /data",
			Labels:   map[string]string{"host": "node-01", "mount": "/data"},
		},
		{
			ID:       "prometheus-004",
			Name:     "ServiceDown",
			Status:   "acknowledged",
			Severity: "critical",
			FiredAt:  time.Now().Add(-1 * time.Hour),
			Message:  "Service endpoint not responding",
			Labels:   map[string]string{"service": "payment-gateway", "namespace": "production"},
		},
		{
			ID:       "prometheus-005",
			Name:     "HighErrorRate",
			Status:   "firing",
			Severity: "critical",
			FiredAt:  time.Now().Add(-5 * time.Minute),
			Message:  "HTTP 5xx error rate above 5%",
			Labels:   map[string]string{"service": "checkout-api", "namespace": "production"},
		},
	}
}

// getGrafanaAlerts 获取 Grafana 告警
func (act *AlertCheckTool) getGrafanaAlerts(params *AlertCheckParams) []AlertInfo {
	if alerts := act.queryGrafanaAlerts(params); len(alerts) > 0 {
		return alerts
	}
	return []AlertInfo{
		{
			ID:          "grafana-001",
			Name:        "DBConnectionPoolExhausted",
			Status:      "firing",
			Severity:    "critical",
			FiredAt:     time.Now().Add(-10 * time.Minute),
			Message:     "Database connection pool at 95% capacity",
			Annotations: map[string]string{"dashboard": "Database Overview"},
		},
		{
			ID:          "grafana-002",
			Name:        "APILatencySpike",
			Status:      "firing",
			Severity:    "warning",
			FiredAt:     time.Now().Add(-20 * time.Minute),
			Message:     "P99 latency above 500ms",
			Annotations: map[string]string{"dashboard": "API Performance"},
		},
		{
			ID:          "grafana-003",
			Name:        "DiskIOHigh",
			Status:      "resolved",
			Severity:    "info",
			FiredAt:     time.Now().Add(-3 * time.Hour),
			Message:     "Disk I/O utilization spike detected",
			Annotations: map[string]string{"dashboard": "System Metrics"},
		},
	}
}

// getDatadogAlerts 获取 Datadog 告警
func (act *AlertCheckTool) getDatadogAlerts(params *AlertCheckParams) []AlertInfo {
	if alerts := act.queryDatadogAlerts(params); len(alerts) > 0 {
		return alerts
	}
	return []AlertInfo{
		{
			ID:       "dd-001",
			Name:     "SyntheticsTestFailed",
			Status:   "firing",
			Severity: "critical",
			FiredAt:  time.Now().Add(-8 * time.Minute),
			Message:  "Checkout flow synthetic test failed - timeout",
			Labels:   map[string]string{"env": "production", "region": "us-east-1"},
		},
		{
			ID:       "dd-002",
			Name:     "APMErrorRate",
			Status:   "acknowledged",
			Severity: "warning",
			FiredAt:  time.Now().Add(-45 * time.Minute),
			Message:  "Application error rate above 2%",
			Labels:   map[string]string{"service": "user-service"},
		},
		{
			ID:       "dd-003",
			Name:     "ContainerRestart",
			Status:   "resolved",
			Severity: "info",
			FiredAt:  time.Now().Add(-1 * time.Hour),
			Message:  "Container restarted unexpectedly",
			Labels:   map[string]string{"pod": "auth-service-5c8d9f", "namespace": "staging"},
		},
	}
}

// getPagerDutyAlerts 获取 PagerDuty 告警
func (act *AlertCheckTool) getPagerDutyAlerts(params *AlertCheckParams) []AlertInfo {
	if alerts := act.queryPagerDutyAlerts(params); len(alerts) > 0 {
		return alerts
	}
	return []AlertInfo{
		{
			ID:       "pd-001",
			Name:     "DatabaseReplicationLag",
			Status:   "firing",
			Severity: "critical",
			FiredAt:  time.Now().Add(-25 * time.Minute),
			Message:  "PostgreSQL replication lag exceeds 30 seconds",
			Labels:   map[string]string{"service": "postgresql-primary"},
		},
		{
			ID:       "pd-002",
			Name:     "KubernetesNodeNotReady",
			Status:   "acknowledged",
			Severity: "warning",
			FiredAt:  time.Now().Add(-2 * time.Hour),
			Message:  "Node node-03 is in NotReady state",
			Labels:   map[string]string{"node": "node-03", "cluster": "prod-us-east"},
		},
		{
			ID:       "pd-003",
			Name:     "CertificateExpiring",
			Status:   "firing",
			Severity: "warning",
			FiredAt:  time.Now().Add(-6 * time.Hour),
			Message:  "SSL certificate for api.example.com expires in 7 days",
			Labels:   map[string]string{"domain": "api.example.com"},
		},
	}
}

func (act *AlertCheckTool) resolveEndpoint(params *AlertCheckParams, key string) string {
	if strings.TrimSpace(params.Endpoint) != "" {
		return strings.TrimRight(strings.TrimSpace(params.Endpoint), "/")
	}
	return strings.TrimRight(strings.TrimSpace(os.Getenv(key)), "/")
}

func (act *AlertCheckTool) resolveToken(params *AlertCheckParams, key string) string {
	if strings.TrimSpace(params.APIToken) != "" {
		return strings.TrimSpace(params.APIToken)
	}
	return strings.TrimSpace(os.Getenv(key))
}

func (act *AlertCheckTool) queryPrometheusAlerts(params *AlertCheckParams) []AlertInfo {
	if strings.TrimSpace(params.RemoteHost) != "" {
		if alerts := act.queryPrometheusAlertsRemote(params); len(alerts) > 0 {
			return alerts
		}
	}
	base := act.resolveEndpoint(params, "SECOPS_PROMETHEUS_ENDPOINT")
	if base == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, base+"/api/v1/alerts", nil)
	if err != nil {
		return nil
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()

	var payload struct {
		Status string `json:"status"`
		Data   struct {
			Alerts []struct {
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
				State       string            `json:"state"`
				ActiveAt    string            `json:"activeAt"`
			} `json:"alerts"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}

	alerts := make([]AlertInfo, 0, len(payload.Data.Alerts))
	for i, a := range payload.Data.Alerts {
		status := strings.ToLower(strings.TrimSpace(a.State))
		if status == "" {
			status = "firing"
		}
		firedAt := time.Now()
		if t, err := time.Parse(time.RFC3339, a.ActiveAt); err == nil {
			firedAt = t
		}
		name := a.Labels["alertname"]
		if name == "" {
			name = fmt.Sprintf("prometheus-alert-%d", i+1)
		}
		sev := strings.ToLower(a.Labels["severity"])
		if sev == "" {
			sev = "warning"
		}
		msg := a.Annotations["summary"]
		if msg == "" {
			msg = a.Annotations["description"]
		}
		if msg == "" {
			msg = name
		}
		alerts = append(alerts, AlertInfo{
			ID:          fmt.Sprintf("prom-%d", i+1),
			Name:        name,
			Status:      normalizeAlertStatus(status),
			Severity:    sev,
			FiredAt:     firedAt,
			Message:     msg,
			Labels:      a.Labels,
			Annotations: a.Annotations,
		})
	}
	return alerts
}

func (act *AlertCheckTool) queryGrafanaAlerts(params *AlertCheckParams) []AlertInfo {
	if strings.TrimSpace(params.RemoteHost) != "" {
		if alerts := act.queryGrafanaAlertsRemote(params); len(alerts) > 0 {
			return alerts
		}
	}
	base := act.resolveEndpoint(params, "SECOPS_GRAFANA_ENDPOINT")
	if base == "" {
		return nil
	}

	token := act.resolveToken(params, "SECOPS_GRAFANA_TOKEN")
	paths := []string{
		"/api/alertmanager/grafana/api/v2/alerts",
		"/api/alerts",
	}
	for _, path := range paths {
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			continue
		}

		var v2 []struct {
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
			Status      struct {
				State string `json:"state"`
			} `json:"status"`
			StartsAt string `json:"startsAt"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&v2); err == nil {
			_ = resp.Body.Close()
			alerts := make([]AlertInfo, 0, len(v2))
			for i, a := range v2 {
				t := time.Now()
				if tt, err := time.Parse(time.RFC3339, a.StartsAt); err == nil {
					t = tt
				}
				name := a.Labels["alertname"]
				if name == "" {
					name = fmt.Sprintf("grafana-alert-%d", i+1)
				}
				msg := a.Annotations["summary"]
				if msg == "" {
					msg = a.Annotations["description"]
				}
				if msg == "" {
					msg = name
				}
				alerts = append(alerts, AlertInfo{
					ID:          fmt.Sprintf("grafana-%d", i+1),
					Name:        name,
					Status:      normalizeAlertStatus(a.Status.State),
					Severity:    defaultIfEmpty(strings.ToLower(a.Labels["severity"]), "warning"),
					FiredAt:     t,
					Message:     msg,
					Labels:      a.Labels,
					Annotations: a.Annotations,
				})
			}
			return alerts
		}
		_ = resp.Body.Close()
	}
	return nil
}

func (act *AlertCheckTool) queryDatadogAlerts(params *AlertCheckParams) []AlertInfo {
	base := act.resolveEndpoint(params, "SECOPS_DATADOG_ENDPOINT")
	if base == "" {
		base = "https://api.datadoghq.com"
	}
	apiKey := act.resolveToken(params, "SECOPS_DATADOG_API_KEY")
	appKey := strings.TrimSpace(os.Getenv("SECOPS_DATADOG_APP_KEY"))
	if apiKey == "" || appKey == "" {
		return nil
	}
	q := url.QueryEscape(params.Filter)
	if q == "" {
		q = "*"
	}
	req, err := http.NewRequest(http.MethodGet, base+"/api/v1/monitor/search?query="+q, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("DD-API-KEY", apiKey)
	req.Header.Set("DD-APPLICATION-KEY", appKey)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()

	var payload struct {
		Monitors []struct {
			ID             int64    `json:"id"`
			Name           string   `json:"name"`
			Message        string   `json:"message"`
			OverallState   string   `json:"overall_state"`
			Tags           []string `json:"tags"`
			Classification string   `json:"classification"`
		} `json:"monitors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	alerts := make([]AlertInfo, 0, len(payload.Monitors))
	for _, m := range payload.Monitors {
		alerts = append(alerts, AlertInfo{
			ID:       fmt.Sprintf("dd-%d", m.ID),
			Name:     m.Name,
			Status:   normalizeDatadogState(m.OverallState),
			Severity: defaultIfEmpty(strings.ToLower(m.Classification), "warning"),
			FiredAt:  time.Now(),
			Message:  defaultIfEmpty(m.Message, m.Name),
		})
	}
	return alerts
}

func (act *AlertCheckTool) queryPagerDutyAlerts(params *AlertCheckParams) []AlertInfo {
	base := act.resolveEndpoint(params, "SECOPS_PAGERDUTY_ENDPOINT")
	if base == "" {
		base = "https://api.pagerduty.com"
	}
	token := act.resolveToken(params, "SECOPS_PAGERDUTY_TOKEN")
	if token == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, base+"/incidents?limit=50", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Token token="+token)
	req.Header.Set("Accept", "application/vnd.pagerduty+json;version=2")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()

	var payload struct {
		Incidents []struct {
			ID        string `json:"id"`
			Title     string `json:"title"`
			Status    string `json:"status"`
			Urgency   string `json:"urgency"`
			CreatedAt string `json:"created_at"`
		} `json:"incidents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	alerts := make([]AlertInfo, 0, len(payload.Incidents))
	for _, inc := range payload.Incidents {
		t := time.Now()
		if tt, err := time.Parse(time.RFC3339, inc.CreatedAt); err == nil {
			t = tt
		}
		alerts = append(alerts, AlertInfo{
			ID:       inc.ID,
			Name:     defaultIfEmpty(inc.Title, "pagerduty incident"),
			Status:   normalizePagerDutyStatus(inc.Status),
			Severity: defaultIfEmpty(strings.ToLower(inc.Urgency), "warning"),
			FiredAt:  t,
			Message:  defaultIfEmpty(inc.Title, inc.ID),
		})
	}
	return alerts
}

func normalizeAlertStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "firing", "active", "triggered":
		return "firing"
	case "resolved", "inactive":
		return "resolved"
	case "acknowledged", "suppressed":
		return "acknowledged"
	default:
		return "firing"
	}
}

func normalizeDatadogState(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "alert", "triggered", "warn":
		return "firing"
	case "ok":
		return "resolved"
	case "no data":
		return "acknowledged"
	default:
		return "firing"
	}
}

func normalizePagerDutyStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "triggered":
		return "firing"
	case "resolved":
		return "resolved"
	case "acknowledged":
		return "acknowledged"
	default:
		return "firing"
	}
}

func defaultIfEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func (act *AlertCheckTool) queryPrometheusAlertsRemote(params *AlertCheckParams) []AlertInfo {
	base := act.resolveEndpoint(params, "SECOPS_PROMETHEUS_ENDPOINT")
	if base == "" {
		base = "http://127.0.0.1:9090"
	}
	payload, err := act.runRemoteHTTPGet(params, base+"/api/v1/alerts", nil)
	if err != nil || len(payload) == 0 {
		return nil
	}
	var resp struct {
		Data struct {
			Alerts []struct {
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
				State       string            `json:"state"`
				ActiveAt    string            `json:"activeAt"`
			} `json:"alerts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil
	}
	alerts := make([]AlertInfo, 0, len(resp.Data.Alerts))
	for i, a := range resp.Data.Alerts {
		firedAt := time.Now()
		if t, err := time.Parse(time.RFC3339, a.ActiveAt); err == nil {
			firedAt = t
		}
		name := defaultIfEmpty(a.Labels["alertname"], fmt.Sprintf("prometheus-alert-%d", i+1))
		msg := defaultIfEmpty(a.Annotations["summary"], a.Annotations["description"])
		msg = defaultIfEmpty(msg, name)
		alerts = append(alerts, AlertInfo{
			ID:          fmt.Sprintf("prom-%d", i+1),
			Name:        name,
			Status:      normalizeAlertStatus(a.State),
			Severity:    defaultIfEmpty(strings.ToLower(a.Labels["severity"]), "warning"),
			FiredAt:     firedAt,
			Message:     msg,
			Labels:      a.Labels,
			Annotations: a.Annotations,
		})
	}
	return alerts
}

func (act *AlertCheckTool) queryGrafanaAlertsRemote(params *AlertCheckParams) []AlertInfo {
	base := act.resolveEndpoint(params, "SECOPS_GRAFANA_ENDPOINT")
	if base == "" {
		base = "http://127.0.0.1:3000"
	}
	token := act.resolveToken(params, "SECOPS_GRAFANA_TOKEN")
	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	paths := []string{
		"/api/alertmanager/grafana/api/v2/alerts",
		"/api/alerts",
	}
	for _, p := range paths {
		payload, err := act.runRemoteHTTPGet(params, base+p, headers)
		if err != nil || len(payload) == 0 {
			continue
		}
		var v2 []struct {
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
			Status      struct {
				State string `json:"state"`
			} `json:"status"`
			StartsAt string `json:"startsAt"`
		}
		if err := json.Unmarshal(payload, &v2); err != nil {
			continue
		}
		alerts := make([]AlertInfo, 0, len(v2))
		for i, a := range v2 {
			t := time.Now()
			if tt, err := time.Parse(time.RFC3339, a.StartsAt); err == nil {
				t = tt
			}
			name := defaultIfEmpty(a.Labels["alertname"], fmt.Sprintf("grafana-alert-%d", i+1))
			msg := defaultIfEmpty(a.Annotations["summary"], a.Annotations["description"])
			msg = defaultIfEmpty(msg, name)
			alerts = append(alerts, AlertInfo{
				ID:          fmt.Sprintf("grafana-%d", i+1),
				Name:        name,
				Status:      normalizeAlertStatus(a.Status.State),
				Severity:    defaultIfEmpty(strings.ToLower(a.Labels["severity"]), "warning"),
				FiredAt:     t,
				Message:     msg,
				Labels:      a.Labels,
				Annotations: a.Annotations,
			})
		}
		return alerts
	}
	return nil
}

func (act *AlertCheckTool) runRemoteHTTPGet(params *AlertCheckParams, urlStr string, headers map[string]string) ([]byte, error) {
	if act.runCmd == nil {
		act.runCmd = runAlertCommand
	}
	remoteCmd := buildRemoteCurlCommand(urlStr, headers)
	sshArgs, err := buildAlertSSHArgs(params, remoteCmd)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stdout, stderr, cmdErr := act.runCmd(ctx, "ssh", sshArgs...)
	if cmdErr != nil && len(strings.TrimSpace(string(stdout))) == 0 {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = cmdErr.Error()
		}
		return nil, fmt.Errorf("remote curl failed: %s", msg)
	}
	return stdout, nil
}

func buildRemoteCurlCommand(urlStr string, headers map[string]string) string {
	parts := []string{"curl", "-fsSL", shellQuoteAlert(urlStr)}
	for k, v := range headers {
		parts = append(parts, "-H", shellQuoteAlert(k+": "+v))
	}
	return strings.Join(parts, " ")
}

func runAlertCommand(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err == nil {
		return out, nil, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return out, ee.Stderr, err
	}
	return out, nil, err
}

func buildAlertSSHArgs(params *AlertCheckParams, remoteCmd string) ([]string, error) {
	if params == nil {
		return nil, fmt.Errorf("remote params are required")
	}
	host := strings.TrimSpace(params.RemoteHost)
	if host == "" {
		return nil, fmt.Errorf("remote_host is required")
	}
	target := host
	user := strings.TrimSpace(params.RemoteUser)
	if user != "" {
		target = user + "@" + host
	}
	sshArgs := defaultSSHOptionArgs()
	if params.RemotePort > 0 {
		sshArgs = append(sshArgs, "-p", strconv.Itoa(params.RemotePort))
	}
	if key := strings.TrimSpace(params.RemoteKeyPath); key != "" {
		sshArgs = append(sshArgs, "-i", key)
	}
	if jump := strings.TrimSpace(params.RemoteProxyJump); jump != "" {
		sshArgs = append(sshArgs, "-J", jump)
	}
	sshArgs = append(sshArgs, target, "sh", "-lc", remoteCmd)
	return sshArgs, nil
}

func shellQuoteAlert(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}
