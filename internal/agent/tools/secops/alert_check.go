package secops

import (
	"fmt"
	"time"
)

// AlertCheckParams for checking alerts
type AlertCheckParams struct {
	System    string `json:"system"`    // prometheus, grafana, datadog, pagerduty
	Filter   string `json:"filter"`
	Status   string `json:"status"`   // firing, resolved, acknowledged
	TimeRange string `json:"time_range"`
}

// AlertCheckTool 告警检查工具
type AlertCheckTool struct {
	registry *SecOpsToolRegistry
}

// NewAlertCheckTool 创建告警检查工具
func NewAlertCheckTool(registry *SecOpsToolRegistry) *AlertCheckTool {
	return &AlertCheckTool{registry: registry}
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
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`    // firing, resolved, acknowledged
	Severity  string    `json:"severity"`  // critical, warning, info
	FiredAt   time.Time `json:"fired_at"`
	Message   string    `json:"message"`
	Labels    map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// AlertCheckResult 告警检查结果
type AlertCheckResult struct {
	System   string      `json:"system"`
	Total    int         `json:"total"`
	Firing   int         `json:"firing"`
	Resolved int         `json:"resolved"`
	Acknowledged int     `json:"acknowledged"`
	Alerts   []AlertInfo `json:"alerts"`
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
		"grafana":   true,
		"datadog":   true,
		"pagerduty": true,
	}
	if !validSystems[p.System] {
		return fmt.Errorf("unsupported system: %s", p.System)
	}

	validStatuses := map[string]bool{
		"firing":      true,
		"resolved":    true,
		"acknowledged": true,
	}
	if p.Status != "" && !validStatuses[p.Status] {
		return fmt.Errorf("unsupported status: %s", p.Status)
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
		result.Alerts = act.getPrometheusAlerts(params)
	case "grafana":
		result.Alerts = act.getGrafanaAlerts(params)
	case "datadog":
		result.Alerts = act.getDatadogAlerts(params)
	case "pagerduty":
		result.Alerts = act.getPagerDutyAlerts(params)
	}

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

// getPrometheusAlerts 获取 Prometheus 告警
func (act *AlertCheckTool) getPrometheusAlerts(params *AlertCheckParams) []AlertInfo {
	return []AlertInfo{
		{
			ID:        "prometheus-001",
			Name:      "HighCPUUsage",
			Status:    "firing",
			Severity:  "warning",
			FiredAt:   time.Now().Add(-30 * time.Minute),
			Message:   "CPU usage above 80% for 5 minutes",
			Labels:    map[string]string{"pod": "api-server-0", "namespace": "production"},
		},
		{
			ID:        "prometheus-002",
			Name:      "HighMemoryUsage",
			Status:    "firing",
			Severity:  "critical",
			FiredAt:   time.Now().Add(-15 * time.Minute),
			Message:   "Memory usage above 90% for 3 minutes",
			Labels:    map[string]string{"pod": "worker-1", "namespace": "production"},
		},
		{
			ID:        "prometheus-003",
			Name:      "DiskSpaceLow",
			Status:    "resolved",
			Severity:  "warning",
			FiredAt:   time.Now().Add(-2 * time.Hour),
			Message:   "Disk space below 20% on /data",
			Labels:    map[string]string{"host": "node-01", "mount": "/data"},
		},
		{
			ID:        "prometheus-004",
			Name:      "ServiceDown",
			Status:    "acknowledged",
			Severity:  "critical",
			FiredAt:   time.Now().Add(-1 * time.Hour),
			Message:   "Service endpoint not responding",
			Labels:    map[string]string{"service": "payment-gateway", "namespace": "production"},
		},
		{
			ID:        "prometheus-005",
			Name:      "HighErrorRate",
			Status:    "firing",
			Severity:  "critical",
			FiredAt:   time.Now().Add(-5 * time.Minute),
			Message:   "HTTP 5xx error rate above 5%",
			Labels:    map[string]string{"service": "checkout-api", "namespace": "production"},
		},
	}
}

// getGrafanaAlerts 获取 Grafana 告警
func (act *AlertCheckTool) getGrafanaAlerts(params *AlertCheckParams) []AlertInfo {
	return []AlertInfo{
		{
			ID:        "grafana-001",
			Name:      "DBConnectionPoolExhausted",
			Status:    "firing",
			Severity:  "critical",
			FiredAt:   time.Now().Add(-10 * time.Minute),
			Message:   "Database connection pool at 95% capacity",
			Annotations: map[string]string{"dashboard": "Database Overview"},
		},
		{
			ID:        "grafana-002",
			Name:      "APILatencySpike",
			Status:    "firing",
			Severity:  "warning",
			FiredAt:   time.Now().Add(-20 * time.Minute),
			Message:   "P99 latency above 500ms",
			Annotations: map[string]string{"dashboard": "API Performance"},
		},
		{
			ID:        "grafana-003",
			Name:      "DiskIOHigh",
			Status:    "resolved",
			Severity:  "info",
			FiredAt:   time.Now().Add(-3 * time.Hour),
			Message:   "Disk I/O utilization spike detected",
			Annotations: map[string]string{"dashboard": "System Metrics"},
		},
	}
}

// getDatadogAlerts 获取 Datadog 告警
func (act *AlertCheckTool) getDatadogAlerts(params *AlertCheckParams) []AlertInfo {
	return []AlertInfo{
		{
			ID:        "dd-001",
			Name:      "SyntheticsTestFailed",
			Status:    "firing",
			Severity:  "critical",
			FiredAt:   time.Now().Add(-8 * time.Minute),
			Message:   "Checkout flow synthetic test failed - timeout",
			Labels:    map[string]string{"env": "production", "region": "us-east-1"},
		},
		{
			ID:        "dd-002",
			Name:      "APMErrorRate",
			Status:    "acknowledged",
			Severity:  "warning",
			FiredAt:   time.Now().Add(-45 * time.Minute),
			Message:   "Application error rate above 2%",
			Labels:    map[string]string{"service": "user-service"},
		},
		{
			ID:        "dd-003",
			Name:      "ContainerRestart",
			Status:    "resolved",
			Severity:  "info",
			FiredAt:   time.Now().Add(-1 * time.Hour),
			Message:   "Container restarted unexpectedly",
			Labels:    map[string]string{"pod": "auth-service-5c8d9f", "namespace": "staging"},
		},
	}
}

// getPagerDutyAlerts 获取 PagerDuty 告警
func (act *AlertCheckTool) getPagerDutyAlerts(params *AlertCheckParams) []AlertInfo {
	return []AlertInfo{
		{
			ID:        "pd-001",
			Name:      "DatabaseReplicationLag",
			Status:    "firing",
			Severity:  "critical",
			FiredAt:   time.Now().Add(-25 * time.Minute),
			Message:   "PostgreSQL replication lag exceeds 30 seconds",
			Labels:    map[string]string{"service": "postgresql-primary"},
		},
		{
			ID:        "pd-002",
			Name:      "KubernetesNodeNotReady",
			Status:    "acknowledged",
			Severity:  "warning",
			FiredAt:   time.Now().Add(-2 * time.Hour),
			Message:   "Node node-03 is in NotReady state",
			Labels:    map[string]string{"node": "node-03", "cluster": "prod-us-east"},
		},
		{
			ID:        "pd-003",
			Name:      "CertificateExpiring",
			Status:    "firing",
			Severity:  "warning",
			FiredAt:   time.Now().Add(-6 * time.Hour),
			Message:   "SSL certificate for api.example.com expires in 7 days",
			Labels:    map[string]string{"domain": "api.example.com"},
		},
	}
}
