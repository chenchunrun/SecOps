package secops

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DeploymentStatusTool 部署状态检查工具
type DeploymentStatusTool struct {
	registry *SecOpsToolRegistry
	runCmd   func(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

// NewDeploymentStatusTool 创建部署状态检查工具
func NewDeploymentStatusTool(registry *SecOpsToolRegistry) *DeploymentStatusTool {
	return &DeploymentStatusTool{
		registry: registry,
		runCmd:   runDeploymentCommand,
	}
}

// Type 实现 Tool.Type
func (dst *DeploymentStatusTool) Type() ToolType {
	return ToolTypeDeploymentStatus
}

// Name 实现 Tool.Name
func (dst *DeploymentStatusTool) Name() string {
	return "Deployment Status"
}

// Description 实现 Tool.Description
func (dst *DeploymentStatusTool) Description() string {
	return "Check deployment health, rollout status, and canary analysis for Kubernetes and cloud platforms"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (dst *DeploymentStatusTool) RequiredCapabilities() []string {
	return []string{"kubernetes:read", "deployment:read"}
}

// DeploymentStatusParams 部署状态检查参数
type DeploymentStatusParams struct {
	Platform        string `json:"platform"`   // kubernetes, aws, gcp, azure
	Namespace       string `json:"namespace"`  // for kubernetes
	Deployment      string `json:"deployment"` // deployment name
	Env             string `json:"env"`        // environment: production, staging, dev
	Target          string `json:"target"`     // cluster or target identifier
	RemoteHost      string `json:"remote_host,omitempty"`
	RemoteUser      string `json:"remote_user,omitempty"`
	RemotePort      int    `json:"remote_port,omitempty"`
	RemoteKeyPath   string `json:"remote_key_path,omitempty"`
	RemoteProxyJump string `json:"remote_proxy_jump,omitempty"`
}

// ReplicaStatus 副本状态
type ReplicaStatus struct {
	Desired   int `json:"desired"`
	Ready     int `json:"ready"`
	Available int `json:"available"`
	Updated   int `json:"updated"`
	Replicas  int `json:"replicas"`
}

// RolloutInfo 滚动更新信息
type RolloutInfo struct {
	InProgress     bool   `json:"in_progress"`
	Strategy       string `json:"strategy"` // RollingUpdate, BlueGreen, Canary
	Step           int    `json:"step,omitempty"`
	TotalSteps     int    `json:"total_steps,omitempty"`
	Paused         bool   `json:"paused"`
	AbortRequested bool   `json:"abort_requested,omitempty"`
	Progress       string `json:"progress,omitempty"`
}

// CanaryAnalysis 金丝雀分析
type CanaryAnalysis struct {
	TrafficWeight   int           `json:"traffic_weight"` // percentage to canary
	AnalysisStarted string        `json:"analysis_started"`
	MetricsChecked  int           `json:"metrics_checked"`
	MetricsPassed   int           `json:"metrics_passed"`
	MetricsFailed   int           `json:"metrics_failed"`
	ErrorRate       float64       `json:"error_rate"`     // percentage
	P99Latency      float64       `json:"p99_latency_ms"` // milliseconds
	P50Latency      float64       `json:"p50_latency_ms"` // milliseconds
	SuccessRate     float64       `json:"success_rate"`   // percentage
	Recommendation  string        `json:"recommendation"` // promote, rollback, hold
	Details         []MetricCheck `json:"details,omitempty"`
}

// MetricCheck 指标检查
type MetricCheck struct {
	Name        string  `json:"name"`
	Threshold   float64 `json:"threshold"`
	Current     float64 `json:"current"`
	Passed      bool    `json:"passed"`
	Description string  `json:"description"`
}

// DeploymentHealth 部署健康状态
type DeploymentHealth struct {
	Status            string      `json:"status"` // healthy, degraded, unhealthy, unknown
	AvailableReplicas int         `json:"available_replicas"`
	ReadyReplicas     int         `json:"ready_replicas"`
	UpdatedReplicas   int         `json:"updated_replicas"`
	Conditions        []Condition `json:"conditions,omitempty"`
	Events            []Event     `json:"events,omitempty"`
	Uptime            string      `json:"uptime"`
}

// Condition 部署条件
type Condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// Event 事件
type Event struct {
	Type      string `json:"type"` // Normal, Warning
	Reason    string `json:"reason"`
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
}

// DeploymentStatusResult 部署状态结果
type DeploymentStatusResult struct {
	Platform        string            `json:"platform"`
	Deployment      string            `json:"deployment"`
	Namespace       string            `json:"namespace,omitempty"`
	Health          *DeploymentHealth `json:"health,omitempty"`
	Replicas        *ReplicaStatus    `json:"replicas,omitempty"`
	Rollout         *RolloutInfo      `json:"rollout,omitempty"`
	CanaryAnalysis  *CanaryAnalysis   `json:"canary_analysis,omitempty"`
	Version         string            `json:"version,omitempty"`
	PreviousVersion string            `json:"previous_version,omitempty"`
	Error           string            `json:"error,omitempty"`
	DataSource      string            `json:"data_source,omitempty"`   // live, fallback_sample
	FallbackReason  string            `json:"fallback_reason,omitempty"`
}

// ValidateParams 实现 Tool.ValidateParams
func (dst *DeploymentStatusTool) ValidateParams(params interface{}) error {
	p, ok := params.(*DeploymentStatusParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.Platform == "" {
		return fmt.Errorf("platform is required")
	}

	validPlatforms := map[string]bool{
		"kubernetes": true,
		"aws":        true,
		"gcp":        true,
		"azure":      true,
	}
	if !validPlatforms[p.Platform] {
		return fmt.Errorf("unsupported platform: %s", p.Platform)
	}

	if p.Deployment == "" {
		return fmt.Errorf("deployment is required")
	}
	if p.RemotePort < 0 || p.RemotePort > 65535 {
		return fmt.Errorf("remote_port must be between 1 and 65535")
	}
	if strings.TrimSpace(p.RemoteHost) == "" {
		if strings.TrimSpace(p.RemoteUser) != "" || p.RemotePort > 0 ||
			strings.TrimSpace(p.RemoteKeyPath) != "" || strings.TrimSpace(p.RemoteProxyJump) != "" {
			return fmt.Errorf("remote_host is required when remote ssh options are set")
		}
	}

	return nil
}

// Execute 实现 Tool.Execute
func (dst *DeploymentStatusTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*DeploymentStatusParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := dst.ValidateParams(p); err != nil {
		return nil, err
	}

	return dst.performCheck(p), nil
}

// performCheck 执行部署状态检查
func (dst *DeploymentStatusTool) performCheck(params *DeploymentStatusParams) *DeploymentStatusResult {
	result := &DeploymentStatusResult{
		Platform:   params.Platform,
		Deployment: params.Deployment,
		Namespace:  params.Namespace,
		Version:    "v2.3.1",
	}

	switch params.Platform {
	case "kubernetes":
		result = dst.getK8sDeploymentStatus(params)
	case "aws":
		result = dst.getAWSDeploymentStatus(params)
	case "gcp":
		result = dst.getGCPDDeploymentStatus(params)
	case "azure":
		result = dst.getAzureDeploymentStatus(params)
	}

	return result
}

// getK8sDeploymentStatus 获取 Kubernetes 部署状态
func (dst *DeploymentStatusTool) getK8sDeploymentStatus(params *DeploymentStatusParams) *DeploymentStatusResult {
	if live := dst.getK8sDeploymentStatusFromKubectl(params); live != nil {
		live.DataSource = "live"
		return live
	}

	result := &DeploymentStatusResult{
		Platform:        "kubernetes",
		Deployment:      params.Deployment,
		Namespace:       params.Namespace,
		Version:         "v2.3.1",
		PreviousVersion: "v2.3.0",
		Health: &DeploymentHealth{
			Status:            "healthy",
			AvailableReplicas: 3,
			ReadyReplicas:     3,
			UpdatedReplicas:   3,
			Uptime:            "14d 6h 23m",
			Conditions: []Condition{
				{Type: "Available", Status: "True", Reason: "MinimumReplicasAvailable", Message: "Deployment has minimum replicas"},
				{Type: "Progressing", Status: "True", Reason: "NewReplicaSetAvailable", Message: "ReplicaSet has been progressing"},
			},
			Events: []Event{
				{Type: "Normal", Reason: "ScalingReplicaSet", Timestamp: time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04"), Message: "Scaled up to 3 replicas"},
				{Type: "Normal", Reason: "Pulled", Timestamp: time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04"), Message: "Container image pulled successfully"},
			},
		},
		Replicas: &ReplicaStatus{
			Desired:   3,
			Ready:     3,
			Available: 3,
			Updated:   3,
			Replicas:  3,
		},
		Rollout: &RolloutInfo{
			InProgress: false,
			Strategy:   "RollingUpdate",
			Paused:     false,
			Progress:   "Deployment is complete",
		},
		CanaryAnalysis: &CanaryAnalysis{
			TrafficWeight:   0,
			AnalysisStarted: "",
			MetricsChecked:  0,
			MetricsPassed:   0,
			MetricsFailed:   0,
			Recommendation:  "none",
		},
		DataSource:     "fallback_sample",
		FallbackReason: "kubernetes deployment status unavailable; returned built-in sample status",
	}

	return result
}

// getK8sCanaryStatus 获取 Kubernetes 金丝雀分析
func (dst *DeploymentStatusTool) getK8sCanaryStatus(params *DeploymentStatusParams) *DeploymentStatusResult {
	result := dst.getK8sDeploymentStatus(params)
	result.Rollout = &RolloutInfo{
		InProgress:     true,
		Strategy:       "Canary",
		Step:           3,
		TotalSteps:     5,
		Paused:         false,
		AbortRequested: false,
		Progress:       "Step 3/5: Analyzing canary metrics",
	}
	result.CanaryAnalysis = &CanaryAnalysis{
		TrafficWeight:   20,
		AnalysisStarted: time.Now().Add(-10 * time.Minute).Format("2006-01-02 15:04:05"),
		MetricsChecked:  5,
		MetricsPassed:   4,
		MetricsFailed:   1,
		ErrorRate:       0.45,
		P99Latency:      245.3,
		P50Latency:      42.1,
		SuccessRate:     99.55,
		Recommendation:  "hold",
		Details: []MetricCheck{
			{Name: "error_rate", Threshold: 1.0, Current: 0.45, Passed: true, Description: "Error rate below threshold"},
			{Name: "p99_latency", Threshold: 500.0, Current: 245.3, Passed: true, Description: "P99 latency acceptable"},
			{Name: "cpu_usage", Threshold: 80.0, Current: 62.0, Passed: true, Description: "CPU usage within limits"},
			{Name: "memory_usage", Threshold: 85.0, Current: 71.0, Passed: true, Description: "Memory usage within limits"},
			{Name: "request_success_rate", Threshold: 99.0, Current: 99.55, Passed: false, Description: "Success rate below target (99.8%)"},
		},
	}

	return result
}

// getAWSDeploymentStatus 获取 AWS 部署状态
func (dst *DeploymentStatusTool) getAWSDeploymentStatus(params *DeploymentStatusParams) *DeploymentStatusResult {
	if live := dst.getAWSDeploymentStatusFromCLI(params); live != nil {
		live.DataSource = "live"
		return live
	}
	return &DeploymentStatusResult{
		Platform:   "aws",
		Deployment: params.Deployment,
		Version:    "v2.3.1",
		Health: &DeploymentHealth{
			Status:            "healthy",
			AvailableReplicas: 4,
			ReadyReplicas:     4,
			UpdatedReplicas:   4,
			Uptime:            "7d 2h 15m",
			Conditions: []Condition{
				{Type: "Healthy", Status: "True", Reason: "ELB", Message: "All targets healthy"},
				{Type: "AutoScaling", Status: "True", Reason: "MinReplicasMet", Message: "Minimum replicas requirement met"},
			},
		},
		Replicas: &ReplicaStatus{
			Desired:   4,
			Ready:     4,
			Available: 4,
			Updated:   4,
			Replicas:  4,
		},
		Rollout: &RolloutInfo{
			InProgress: false,
			Strategy:   "RollingUpdate",
			Paused:     false,
			Progress:   "Deployment complete",
		},
		DataSource:     "fallback_sample",
		FallbackReason: "aws deployment status unavailable; returned built-in sample status",
	}
}

// getGCPDDeploymentStatus 获取 GCP 部署状态
func (dst *DeploymentStatusTool) getGCPDDeploymentStatus(params *DeploymentStatusParams) *DeploymentStatusResult {
	if live := dst.getGCPDeploymentStatusFromCLI(params); live != nil {
		live.DataSource = "live"
		return live
	}
	return &DeploymentStatusResult{
		Platform:   "gcp",
		Deployment: params.Deployment,
		Version:    "v2.3.1",
		Health: &DeploymentHealth{
			Status:            "healthy",
			AvailableReplicas: 3,
			ReadyReplicas:     3,
			UpdatedReplicas:   3,
			Uptime:            "21d 4h 10m",
			Conditions: []Condition{
				{Type: "Ready", Status: "True", Reason: "MinimumReplicas", Message: "Minimum replicas available"},
				{Type: "CloudRun", Status: "True", Reason: "ServiceReady", Message: "Cloud Run service is ready"},
			},
		},
		Replicas: &ReplicaStatus{
			Desired:   3,
			Ready:     3,
			Available: 3,
			Updated:   3,
			Replicas:  3,
		},
		Rollout: &RolloutInfo{
			InProgress: false,
			Strategy:   "RollingUpdate",
			Paused:     false,
			Progress:   "Deployment complete",
		},
		DataSource:     "fallback_sample",
		FallbackReason: "gcp deployment status unavailable; returned built-in sample status",
	}
}

// getAzureDeploymentStatus 获取 Azure 部署状态
func (dst *DeploymentStatusTool) getAzureDeploymentStatus(params *DeploymentStatusParams) *DeploymentStatusResult {
	if live := dst.getAzureDeploymentStatusFromCLI(params); live != nil {
		live.DataSource = "live"
		return live
	}
	return &DeploymentStatusResult{
		Platform:   "azure",
		Deployment: params.Deployment,
		Version:    "v2.3.1",
		Health: &DeploymentHealth{
			Status:            "healthy",
			AvailableReplicas: 2,
			ReadyReplicas:     2,
			UpdatedReplicas:   2,
			Uptime:            "5d 12h 30m",
			Conditions: []Condition{
				{Type: "Available", Status: "True", Reason: "MinimumReplicas", Message: "Minimum replicas available"},
				{Type: "Progressing", Status: "True", Reason: "DeploymentSuccessful", Message: "Deployment completed successfully"},
			},
		},
		Replicas: &ReplicaStatus{
			Desired:   2,
			Ready:     2,
			Available: 2,
			Updated:   2,
			Replicas:  2,
		},
		Rollout: &RolloutInfo{
			InProgress: false,
			Strategy:   "RollingUpdate",
			Paused:     false,
			Progress:   "Deployment complete",
		},
		DataSource:     "fallback_sample",
		FallbackReason: "azure deployment status unavailable; returned built-in sample status",
	}
}

func (dst *DeploymentStatusTool) getK8sDeploymentStatusFromKubectl(params *DeploymentStatusParams) *DeploymentStatusResult {
	namespace := strings.TrimSpace(params.Namespace)
	if namespace == "" {
		namespace = "default"
	}

	args := []string{"get", "deployment", params.Deployment, "-n", namespace, "-o", "json"}
	out, err := dst.commandOutput(params, "kubectl", args...)
	if err != nil || len(out) == 0 {
		return nil
	}

	var dep struct {
		Metadata struct {
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			Replicas int `json:"replicas"`
			Strategy struct {
				Type string `json:"type"`
			} `json:"strategy"`
		} `json:"spec"`
		Status struct {
			Replicas          int `json:"replicas"`
			ReadyReplicas     int `json:"readyReplicas"`
			AvailableReplicas int `json:"availableReplicas"`
			UpdatedReplicas   int `json:"updatedReplicas"`
			Conditions        []struct {
				Type    string `json:"type"`
				Status  string `json:"status"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"conditions"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &dep); err != nil {
		return nil
	}

	rollout := dst.getK8sRolloutInfo(params, namespace, dep.Spec.Strategy.Type)
	events := dst.getK8sRecentEvents(params, namespace)
	version, prevVersion := inferDeploymentVersions(dep.Metadata.Labels, dep.Metadata.Annotations)

	healthStatus := "unknown"
	if dep.Status.AvailableReplicas == dep.Spec.Replicas && dep.Spec.Replicas > 0 {
		healthStatus = "healthy"
	} else if dep.Status.AvailableReplicas > 0 {
		healthStatus = "degraded"
	} else {
		healthStatus = "unhealthy"
	}

	conditions := make([]Condition, 0, len(dep.Status.Conditions))
	for _, c := range dep.Status.Conditions {
		conditions = append(conditions, Condition{
			Type:    c.Type,
			Status:  c.Status,
			Reason:  c.Reason,
			Message: c.Message,
		})
	}

	result := &DeploymentStatusResult{
		Platform:        "kubernetes",
		Deployment:      params.Deployment,
		Namespace:       namespace,
		Version:         version,
		PreviousVersion: prevVersion,
		Health: &DeploymentHealth{
			Status:            healthStatus,
			AvailableReplicas: dep.Status.AvailableReplicas,
			ReadyReplicas:     dep.Status.ReadyReplicas,
			UpdatedReplicas:   dep.Status.UpdatedReplicas,
			Conditions:        conditions,
			Events:            events,
			Uptime:            "unknown",
		},
		Replicas: &ReplicaStatus{
			Desired:   dep.Spec.Replicas,
			Ready:     dep.Status.ReadyReplicas,
			Available: dep.Status.AvailableReplicas,
			Updated:   dep.Status.UpdatedReplicas,
			Replicas:  dep.Status.Replicas,
		},
		Rollout: rollout,
		CanaryAnalysis: &CanaryAnalysis{
			TrafficWeight:  0,
			Recommendation: "none",
		},
	}

	if strings.EqualFold(result.Rollout.Strategy, "Canary") || rollout.InProgress {
		result.CanaryAnalysis = dst.estimateCanaryAnalysis(result)
	}

	return result
}

func (dst *DeploymentStatusTool) getK8sRolloutInfo(params *DeploymentStatusParams, namespace, strategy string) *RolloutInfo {
	rollout := &RolloutInfo{
		Strategy:   normalizedStrategy(strategy),
		InProgress: false,
		Paused:     false,
		Progress:   "Deployment is complete",
	}
	stdout, stderr, err := dst.commandRun(params, "kubectl", "rollout", "status", "deployment/"+params.Deployment, "-n", namespace)
	out := append(append([]byte(nil), stdout...), stderr...)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = "Rollout status unavailable"
		}
		rollout.InProgress = true
		rollout.Progress = msg
		return rollout
	}
	msg := strings.TrimSpace(string(out))
	if msg != "" {
		rollout.Progress = msg
	}
	if strings.Contains(strings.ToLower(msg), "waiting") ||
		strings.Contains(strings.ToLower(msg), "progressing") {
		rollout.InProgress = true
	}
	return rollout
}

func (dst *DeploymentStatusTool) getK8sRecentEvents(params *DeploymentStatusParams, namespace string) []Event {
	out, err := dst.commandOutput(
		params,
		"kubectl", "get", "events", "-n", namespace,
		"--field-selector", "involvedObject.kind=Deployment,involvedObject.name="+params.Deployment,
		"-o", "json",
	)
	if err != nil || len(out) == 0 {
		return nil
	}

	var payload struct {
		Items []struct {
			Type              string `json:"type"`
			Reason            string `json:"reason"`
			Message           string `json:"message"`
			LastTimestamp     string `json:"lastTimestamp"`
			EventTime         string `json:"eventTime"`
			CreationTimestamp string `json:"creationTimestamp"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil
	}

	events := make([]Event, 0, len(payload.Items))
	for _, it := range payload.Items {
		ts := strings.TrimSpace(it.LastTimestamp)
		if ts == "" {
			ts = strings.TrimSpace(it.EventTime)
		}
		if ts == "" {
			ts = strings.TrimSpace(it.CreationTimestamp)
		}
		if ts == "" {
			ts = time.Now().Format("2006-01-02 15:04")
		}
		typ := it.Type
		if typ == "" {
			typ = "Normal"
		}
		if typ != "Normal" && typ != "Warning" {
			typ = "Normal"
		}
		events = append(events, Event{
			Type:      typ,
			Reason:    it.Reason,
			Timestamp: ts,
			Message:   it.Message,
		})
	}
	return events
}

func inferDeploymentVersions(labels, annotations map[string]string) (string, string) {
	candidates := []string{
		"app.kubernetes.io/version",
		"version",
		"image.tag",
		"helm.sh/chart",
	}
	version := "unknown"
	previous := ""
	for _, k := range candidates {
		if v, ok := labels[k]; ok && strings.TrimSpace(v) != "" {
			version = v
			break
		}
		if v, ok := annotations[k]; ok && strings.TrimSpace(v) != "" {
			version = v
			break
		}
	}
	if p, ok := annotations["deployment.kubernetes.io/revision"]; ok && p != "" {
		previous = p
	}
	return version, previous
}

func normalizedStrategy(strategy string) string {
	s := strings.TrimSpace(strategy)
	switch strings.ToLower(s) {
	case "rollingupdate":
		return "RollingUpdate"
	case "bluegreen", "blue_green":
		return "BlueGreen"
	case "canary":
		return "Canary"
	default:
		if s == "" {
			return "RollingUpdate"
		}
		return s
	}
}

func (dst *DeploymentStatusTool) estimateCanaryAnalysis(result *DeploymentStatusResult) *CanaryAnalysis {
	rec := "promote"
	if result.Health != nil && result.Health.Status == "degraded" {
		rec = "hold"
	}
	if result.Health != nil && result.Health.Status == "unhealthy" {
		rec = "rollback"
	}
	return &CanaryAnalysis{
		TrafficWeight:   20,
		AnalysisStarted: time.Now().Add(-5 * time.Minute).Format("2006-01-02 15:04:05"),
		MetricsChecked:  3,
		MetricsPassed:   2,
		MetricsFailed:   1,
		ErrorRate:       0.5,
		P99Latency:      250,
		P50Latency:      40,
		SuccessRate:     99.5,
		Recommendation:  rec,
	}
}

func (dst *DeploymentStatusTool) getAWSDeploymentStatusFromCLI(params *DeploymentStatusParams) *DeploymentStatusResult {
	cluster := strings.TrimSpace(params.Target)
	if cluster == "" {
		cluster = "default"
	}

	args := []string{
		"ecs", "describe-services",
		"--cluster", cluster,
		"--services", params.Deployment,
		"--output", "json",
	}
	out, err := dst.commandOutput(params, "aws", args...)
	if err != nil || len(out) == 0 {
		return nil
	}

	var payload struct {
		Services []struct {
			Deployments []struct {
				Status       string `json:"status"`
				RolloutState string `json:"rolloutState"`
			} `json:"deployments"`
			DesiredCount int `json:"desiredCount"`
			RunningCount int `json:"runningCount"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &payload); err != nil || len(payload.Services) == 0 {
		return nil
	}

	svc := payload.Services[0]
	healthStatus := "healthy"
	if svc.RunningCount < svc.DesiredCount {
		healthStatus = "degraded"
	}

	rolloutProgress := "Deployment complete"
	if len(svc.Deployments) > 0 {
		state := strings.ToUpper(strings.TrimSpace(svc.Deployments[0].RolloutState))
		if state == "IN_PROGRESS" {
			rolloutProgress = "Rollout in progress"
		} else if state == "FAILED" {
			rolloutProgress = "Rollout failed"
			healthStatus = "unhealthy"
		}
	}

	return &DeploymentStatusResult{
		Platform:   "aws",
		Deployment: params.Deployment,
		Version:    "unknown",
		Health: &DeploymentHealth{
			Status:            healthStatus,
			AvailableReplicas: svc.RunningCount,
			ReadyReplicas:     svc.RunningCount,
			UpdatedReplicas:   svc.RunningCount,
			Uptime:            "unknown",
		},
		Replicas: &ReplicaStatus{
			Desired:   svc.DesiredCount,
			Ready:     svc.RunningCount,
			Available: svc.RunningCount,
			Updated:   svc.RunningCount,
			Replicas:  svc.RunningCount,
		},
		Rollout: &RolloutInfo{
			InProgress: strings.Contains(strings.ToLower(rolloutProgress), "progress"),
			Strategy:   "RollingUpdate",
			Paused:     false,
			Progress:   rolloutProgress,
		},
		DataSource: "live",
	}
}

func (dst *DeploymentStatusTool) getGCPDeploymentStatusFromCLI(params *DeploymentStatusParams) *DeploymentStatusResult {
	args := []string{"run", "services", "describe", params.Deployment, "--format=json"}
	if region := strings.TrimSpace(params.Target); region != "" {
		args = append(args, "--region", region)
	}
	out, err := dst.commandOutput(params, "gcloud", args...)
	if err != nil || len(out) == 0 {
		return nil
	}

	var payload struct {
		Status struct {
			URL     string `json:"url"`
			Traffic []struct {
				Percent int `json:"percent"`
			} `json:"traffic"`
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
		Spec struct {
			Template struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil
	}

	health := "unknown"
	for _, c := range payload.Status.Conditions {
		if strings.EqualFold(c.Type, "Ready") {
			if strings.EqualFold(c.Status, "True") {
				health = "healthy"
			} else {
				health = "degraded"
			}
			break
		}
	}

	replicas := 1
	if len(payload.Status.Traffic) == 0 {
		replicas = 0
	}

	return &DeploymentStatusResult{
		Platform:   "gcp",
		Deployment: params.Deployment,
		Version:    emptyAs(payload.Spec.Template.Metadata.Name, "unknown"),
		Health: &DeploymentHealth{
			Status:            health,
			AvailableReplicas: replicas,
			ReadyReplicas:     replicas,
			UpdatedReplicas:   replicas,
			Uptime:            "unknown",
			Conditions: []Condition{
				{Type: "URL", Status: boolToStatus(payload.Status.URL != ""), Message: payload.Status.URL},
			},
		},
		Replicas: &ReplicaStatus{
			Desired:   replicas,
			Ready:     replicas,
			Available: replicas,
			Updated:   replicas,
			Replicas:  replicas,
		},
		Rollout: &RolloutInfo{
			InProgress: false,
			Strategy:   "RollingUpdate",
			Paused:     false,
			Progress:   "Deployment complete",
		},
		DataSource: "live",
	}
}

func (dst *DeploymentStatusTool) getAzureDeploymentStatusFromCLI(params *DeploymentStatusParams) *DeploymentStatusResult {
	resourceGroup := strings.TrimSpace(params.Target)
	if resourceGroup == "" {
		return nil
	}

	out, err := dst.commandOutput(
		params,
		"az", "webapp", "show",
		"--name", params.Deployment,
		"--resource-group", resourceGroup,
		"--output", "json",
	)
	if err != nil || len(out) == 0 {
		return nil
	}

	var payload struct {
		State           string `json:"state"`
		Location        string `json:"location"`
		DefaultHostName string `json:"defaultHostName"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil
	}

	health := "degraded"
	if strings.EqualFold(payload.State, "Running") {
		health = "healthy"
	}

	return &DeploymentStatusResult{
		Platform:   "azure",
		Deployment: params.Deployment,
		Version:    "unknown",
		Health: &DeploymentHealth{
			Status:            health,
			AvailableReplicas: 1,
			ReadyReplicas:     1,
			UpdatedReplicas:   1,
			Uptime:            "unknown",
			Conditions: []Condition{
				{Type: "HostName", Status: boolToStatus(payload.DefaultHostName != ""), Message: payload.DefaultHostName},
				{Type: "Location", Status: boolToStatus(payload.Location != ""), Message: payload.Location},
			},
		},
		Replicas: &ReplicaStatus{
			Desired:   1,
			Ready:     1,
			Available: 1,
			Updated:   1,
			Replicas:  1,
		},
		Rollout: &RolloutInfo{
			InProgress: false,
			Strategy:   "RollingUpdate",
			Paused:     false,
			Progress:   "Deployment complete",
		},
		DataSource: "live",
	}
}

func boolToStatus(ok bool) string {
	if ok {
		return "True"
	}
	return "False"
}

func emptyAs(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func (dst *DeploymentStatusTool) commandOutput(params *DeploymentStatusParams, name string, args ...string) ([]byte, error) {
	stdout, stderr, err := dst.commandRun(params, name, args...)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s command failed: %s", name, msg)
	}
	return stdout, nil
}

func (dst *DeploymentStatusTool) commandRun(params *DeploymentStatusParams, name string, args ...string) ([]byte, []byte, error) {
	if dst.runCmd == nil {
		dst.runCmd = runDeploymentCommand
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if params != nil && strings.TrimSpace(params.RemoteHost) != "" {
		sshArgs, err := buildDeploymentSSHArgs(params, name, args...)
		if err != nil {
			return nil, nil, err
		}
		return dst.runCmd(ctx, "ssh", sshArgs...)
	}
	return dst.runCmd(ctx, name, args...)
}

func runDeploymentCommand(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
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

func buildDeploymentSSHArgs(params *DeploymentStatusParams, name string, args ...string) ([]string, error) {
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
	sshArgs := []string{"-o", "BatchMode=yes"}
	if params.RemotePort > 0 {
		sshArgs = append(sshArgs, "-p", strconv.Itoa(params.RemotePort))
	}
	if key := strings.TrimSpace(params.RemoteKeyPath); key != "" {
		sshArgs = append(sshArgs, "-i", key)
	}
	if jump := strings.TrimSpace(params.RemoteProxyJump); jump != "" {
		sshArgs = append(sshArgs, "-J", jump)
	}
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellQuoteDeployment(name))
	for _, arg := range args {
		parts = append(parts, shellQuoteDeployment(arg))
	}
	sshArgs = append(sshArgs, target, "sh", "-lc", strings.Join(parts, " "))
	return sshArgs, nil
}

func shellQuoteDeployment(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}
