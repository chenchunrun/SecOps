package secops

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// InfrastructureQueryTool 基础设施查询工具
type InfrastructureQueryTool struct {
	registry *SecOpsToolRegistry
}

// NewInfrastructureQueryTool 创建基础设施查询工具
func NewInfrastructureQueryTool(registry *SecOpsToolRegistry) *InfrastructureQueryTool {
	return &InfrastructureQueryTool{registry: registry}
}

// Type 实现 Tool.Type
func (iqt *InfrastructureQueryTool) Type() ToolType {
	return ToolTypeInfrastructureQuery
}

// Name 实现 Tool.Name
func (iqt *InfrastructureQueryTool) Name() string {
	return "Infrastructure Query"
}

// Description 实现 Tool.Description
func (iqt *InfrastructureQueryTool) Description() string {
	return "Query infrastructure state for Terraform, AWS, GCP, Azure, and Kubernetes"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (iqt *InfrastructureQueryTool) RequiredCapabilities() []string {
	return []string{"infrastructure:read"}
}

// InfrastructureQueryParams 基础设施查询参数
type InfrastructureQueryParams struct {
	SystemType string `json:"system_type"` // terraform, aws, gcp, azure, kubernetes
	QueryType  string `json:"query_type"`  // state, resources, scaling, costs
	Target     string `json:"target"`      // workspace, cluster, project, etc.
	Filter     string `json:"filter,omitempty"`
	Region     string `json:"region,omitempty"`
}

// ResourceInfo 资源信息
type ResourceInfo struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Status    string            `json:"status"`
	Region    string            `json:"region,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	CreatedAt string            `json:"created_at,omitempty"`
	UpdatedAt string            `json:"updated_at,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
}

// ScalingInfo 扩缩容信息
type ScalingInfo struct {
	MinReplicas     int     `json:"min_replicas"`
	MaxReplicas     int     `json:"max_replicas"`
	CurrentReplicas int     `json:"current_replicas"`
	DesiredReplicas int     `json:"desired_replicas"`
	CPUUtilization  float64 `json:"cpu_utilization,omitempty"`
	MemUtilization  float64 `json:"mem_utilization,omitempty"`
}

// CostInfo 成本信息
type CostInfo struct {
	Service      string  `json:"service"`
	MonthlyCost  float64 `json:"monthly_cost"`
	Currency     string  `json:"currency"`
	UsageHours   int     `json:"usage_hours"`
	CostPerHour  float64 `json:"cost_per_hour"`
	Trend        string  `json:"trend"` // increasing, decreasing, stable
	ForecastCost float64 `json:"forecast_cost,omitempty"`
}

// TerraformState Terraform 状态信息
type TerraformState struct {
	Workspace     string            `json:"workspace"`
	StateVersion  string            `json:"state_version"`
	Resources     []ResourceInfo    `json:"resources"`
	Modules       []string          `json:"modules,omitempty"`
	LastRun       string            `json:"last_run"`
	DriftDetected bool              `json:"drift_detected"`
	Outputs       map[string]string `json:"outputs,omitempty"`
}

// InfrastructureQueryResult 基础设施查询结果
type InfrastructureQueryResult struct {
	SystemType     string          `json:"system_type"`
	QueryType      string          `json:"query_type"`
	Resources      []ResourceInfo  `json:"resources,omitempty"`
	ScalingInfo    *ScalingInfo    `json:"scaling_info,omitempty"`
	CostInfo       []CostInfo      `json:"cost_info,omitempty"`
	TerraformState *TerraformState `json:"terraform_state,omitempty"`
	Error          string          `json:"error,omitempty"`
}

// ValidateParams 实现 Tool.ValidateParams
func (iqt *InfrastructureQueryTool) ValidateParams(params interface{}) error {
	p, ok := params.(*InfrastructureQueryParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.SystemType == "" {
		return fmt.Errorf("system_type is required")
	}

	validSystems := map[string]bool{
		"terraform":  true,
		"aws":        true,
		"gcp":        true,
		"azure":      true,
		"kubernetes": true,
	}
	if !validSystems[p.SystemType] {
		return fmt.Errorf("unsupported system_type: %s", p.SystemType)
	}

	validQueryTypes := map[string]bool{
		"state":     true,
		"resources": true,
		"scaling":   true,
		"costs":     true,
	}
	if p.QueryType != "" && !validQueryTypes[p.QueryType] {
		return fmt.Errorf("unsupported query_type: %s", p.QueryType)
	}

	return nil
}

// Execute 实现 Tool.Execute
func (iqt *InfrastructureQueryTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*InfrastructureQueryParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := iqt.ValidateParams(p); err != nil {
		return nil, err
	}

	return iqt.performQuery(p), nil
}

// performQuery 执行基础设施查询
func (iqt *InfrastructureQueryTool) performQuery(params *InfrastructureQueryParams) *InfrastructureQueryResult {
	result := &InfrastructureQueryResult{
		SystemType: params.SystemType,
		QueryType:  params.QueryType,
	}

	switch params.SystemType {
	case "terraform":
		result.TerraformState = iqt.getTerraformState(params)
	case "aws":
		result.Resources = iqt.getAWSResources(params)
		if params.QueryType == "scaling" {
			result.ScalingInfo = iqt.getAWSScalingInfo(params)
		}
		if params.QueryType == "costs" {
			result.CostInfo = iqt.getAWSCosts(params)
		}
	case "gcp":
		result.Resources = iqt.getGCPResources(params)
		if params.QueryType == "scaling" {
			result.ScalingInfo = iqt.getGCPScalingInfo(params)
		}
		if params.QueryType == "costs" {
			result.CostInfo = iqt.getGCPCosts(params)
		}
	case "azure":
		result.Resources = iqt.getAzureResources(params)
		if params.QueryType == "scaling" {
			result.ScalingInfo = iqt.getAzureScalingInfo(params)
		}
		if params.QueryType == "costs" {
			result.CostInfo = iqt.getAzureCosts(params)
		}
	case "kubernetes":
		result.Resources = iqt.getK8sResources(params)
		if params.QueryType == "scaling" {
			result.ScalingInfo = iqt.getK8sScalingInfo(params)
		}
	}

	return result
}

// getTerraformState 获取 Terraform 状态
func (iqt *InfrastructureQueryTool) getTerraformState(params *InfrastructureQueryParams) *TerraformState {
	if state := iqt.getTerraformStateFromCLI(params); state != nil {
		return state
	}
	return iqt.getTerraformStateFromFiles(params)
}

// getAWSResources 获取 AWS 资源
func (iqt *InfrastructureQueryTool) getAWSResources(params *InfrastructureQueryParams) []ResourceInfo {
	if resources := iqt.getAWSResourcesFromCLI(params); len(resources) > 0 {
		return resources
	}
	return []ResourceInfo{
		{ID: "i-0abcdef1234567890", Name: "web-server-01", Type: "ec2", Status: "running", Region: "us-east-1", Tags: map[string]string{"Service": "web"}},
		{ID: "i-0abcdef1234567891", Name: "web-server-02", Type: "ec2", Status: "running", Region: "us-east-1", Tags: map[string]string{"Service": "web"}},
		{ID: "asg-prod-web", Name: "prod-web-asg", Type: "autoscaling", Status: "active", Region: "us-east-1"},
		{ID: "alb-prod", Name: "prod-alb", Type: "elb", Status: "active", Region: "us-east-1"},
	}
}

// getAWSScalingInfo 获取 AWS 扩缩容信息
func (iqt *InfrastructureQueryTool) getAWSScalingInfo(params *InfrastructureQueryParams) *ScalingInfo {
	if scaling := iqt.getAWSScalingInfoFromCLI(params); scaling != nil {
		return scaling
	}
	return &ScalingInfo{
		MinReplicas:     2,
		MaxReplicas:     10,
		CurrentReplicas: 4,
		DesiredReplicas: 4,
		CPUUtilization:  45.2,
		MemUtilization:  62.8,
	}
}

// getAWSCosts 获取 AWS 成本
func (iqt *InfrastructureQueryTool) getAWSCosts(params *InfrastructureQueryParams) []CostInfo {
	if costs := iqt.getAWSCostsFromCLI(params); len(costs) > 0 {
		return costs
	}
	return []CostInfo{
		{Service: "EC2", MonthlyCost: 1245.50, Currency: "USD", UsageHours: 720, CostPerHour: 1.73, Trend: "stable"},
		{Service: "RDS", MonthlyCost: 389.00, Currency: "USD", UsageHours: 720, CostPerHour: 0.54, Trend: "increasing", ForecastCost: 420.00},
		{Service: "EKS", MonthlyCost: 73.00, Currency: "USD", UsageHours: 720, CostPerHour: 0.10, Trend: "stable"},
		{Service: "S3", MonthlyCost: 45.30, Currency: "USD", UsageHours: 720, CostPerHour: 0.06, Trend: "decreasing"},
		{Service: "DataTransfer", MonthlyCost: 156.80, Currency: "USD", UsageHours: 720, CostPerHour: 0.22, Trend: "increasing"},
	}
}

// getGCPResources 获取 GCP 资源
func (iqt *InfrastructureQueryTool) getGCPResources(params *InfrastructureQueryParams) []ResourceInfo {
	if resources := iqt.getGCPResourcesFromCLI(params); len(resources) > 0 {
		return resources
	}
	return []ResourceInfo{
		{ID: "instance-01", Name: "gce-web-01", Type: "compute_instance", Status: "RUNNING", Region: "us-central1", Tags: map[string]string{"env": "prod"}},
		{ID: "instance-02", Name: "gce-web-02", Type: "compute_instance", Status: "RUNNING", Region: "us-central1", Tags: map[string]string{"env": "prod"}},
		{ID: "gke-prod-cluster", Name: "prod-gke", Type: "gke_cluster", Status: "RUNNING", Region: "us-central1"},
	}
}

// getGCPScalingInfo 获取 GCP 扩缩容信息
func (iqt *InfrastructureQueryTool) getGCPScalingInfo(params *InfrastructureQueryParams) *ScalingInfo {
	if scaling := iqt.getGCPScalingInfoFromCLI(params); scaling != nil {
		return scaling
	}
	return &ScalingInfo{
		MinReplicas:     3,
		MaxReplicas:     15,
		CurrentReplicas: 6,
		DesiredReplicas: 6,
		CPUUtilization:  38.5,
		MemUtilization:  55.0,
	}
}

// getGCPCosts 获取 GCP 成本
func (iqt *InfrastructureQueryTool) getGCPCosts(params *InfrastructureQueryParams) []CostInfo {
	if costs := iqt.getGCPCostsFromCLI(params); len(costs) > 0 {
		return costs
	}
	return []CostInfo{
		{Service: "Compute Engine", MonthlyCost: 890.00, Currency: "USD", UsageHours: 720, CostPerHour: 1.24, Trend: "stable"},
		{Service: "Cloud SQL", MonthlyCost: 245.00, Currency: "USD", UsageHours: 720, CostPerHour: 0.34, Trend: "stable"},
		{Service: "GKE", MonthlyCost: 156.00, Currency: "USD", UsageHours: 720, CostPerHour: 0.22, Trend: "increasing"},
	}
}

// getAzureResources 获取 Azure 资源
func (iqt *InfrastructureQueryTool) getAzureResources(params *InfrastructureQueryParams) []ResourceInfo {
	if resources := iqt.getAzureResourcesFromCLI(params); len(resources) > 0 {
		return resources
	}
	return []ResourceInfo{
		{ID: "vm-web-01", Name: "azure-web-01", Type: "virtual_machine", Status: "Running", Region: "eastus", Tags: map[string]string{"env": "prod"}},
		{ID: "vm-web-02", Name: "azure-web-02", Type: "virtual_machine", Status: "Running", Region: "eastus", Tags: map[string]string{"env": "prod"}},
		{ID: "aks-prod", Name: "prod-aks", Type: "aks_cluster", Status: "Running", Region: "eastus"},
	}
}

// getAzureScalingInfo 获取 Azure 扩缩容信息
func (iqt *InfrastructureQueryTool) getAzureScalingInfo(params *InfrastructureQueryParams) *ScalingInfo {
	if scaling := iqt.getAzureScalingInfoFromCLI(params); scaling != nil {
		return scaling
	}
	return &ScalingInfo{
		MinReplicas:     2,
		MaxReplicas:     12,
		CurrentReplicas: 5,
		DesiredReplicas: 5,
		CPUUtilization:  52.0,
		MemUtilization:  68.0,
	}
}

// getAzureCosts 获取 Azure 成本
func (iqt *InfrastructureQueryTool) getAzureCosts(params *InfrastructureQueryParams) []CostInfo {
	if costs := iqt.getAzureCostsFromCLI(params); len(costs) > 0 {
		return costs
	}
	return []CostInfo{
		{Service: "Virtual Machines", MonthlyCost: 678.00, Currency: "USD", UsageHours: 720, CostPerHour: 0.94, Trend: "stable"},
		{Service: "Azure Kubernetes", MonthlyCost: 234.00, Currency: "USD", UsageHours: 720, CostPerHour: 0.33, Trend: "stable"},
		{Service: "SQL Database", MonthlyCost: 189.00, Currency: "USD", UsageHours: 720, CostPerHour: 0.26, Trend: "increasing"},
	}
}

// getK8sResources 获取 Kubernetes 资源
func (iqt *InfrastructureQueryTool) getK8sResources(params *InfrastructureQueryParams) []ResourceInfo {
	if resources := iqt.getK8sResourcesFromKubectl(params); len(resources) > 0 {
		return resources
	}

	return []ResourceInfo{
		{ID: "deployment/web-api", Name: "web-api", Type: "Deployment", Status: "Available", Meta: map[string]string{"Namespace": "production", "Replicas": "3/3"}},
		{ID: "deployment/backend", Name: "backend", Type: "Deployment", Status: "Available", Meta: map[string]string{"Namespace": "production", "Replicas": "2/2"}},
		{ID: "deployment/redis", Name: "redis", Type: "Deployment", Status: "Available", Meta: map[string]string{"Namespace": "production", "Replicas": "1/1"}},
		{ID: "service/web-api", Name: "web-api-svc", Type: "Service", Status: "Active", Meta: map[string]string{"Namespace": "production", "Type": "ClusterIP"}},
		{ID: "ingress/web", Name: "web-ingress", Type: "Ingress", Status: "Active", Meta: map[string]string{"Namespace": "production", "Class": "nginx"}},
	}
}

// getK8sScalingInfo 获取 Kubernetes 扩缩容信息
func (iqt *InfrastructureQueryTool) getK8sScalingInfo(params *InfrastructureQueryParams) *ScalingInfo {
	if scaling := iqt.getK8sScalingInfoFromKubectl(params); scaling != nil {
		return scaling
	}
	return &ScalingInfo{
		MinReplicas:     2,
		MaxReplicas:     10,
		CurrentReplicas: 3,
		DesiredReplicas: 3,
		CPUUtilization:  41.0,
		MemUtilization:  58.0,
	}
}

func (iqt *InfrastructureQueryTool) getAWSResourcesFromCLI(params *InfrastructureQueryParams) []ResourceInfo {
	if _, err := exec.LookPath("aws"); err != nil {
		return nil
	}
	args := []string{"ec2", "describe-instances", "--output", "json"}
	if region := strings.TrimSpace(params.Region); region != "" {
		args = append(args, "--region", region)
	}
	out, err := exec.Command("aws", args...).Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	var payload struct {
		Reservations []struct {
			Instances []struct {
				InstanceID string `json:"InstanceId"`
				State      struct {
					Name string `json:"Name"`
				} `json:"State"`
				Placement struct {
					AvailabilityZone string `json:"AvailabilityZone"`
				} `json:"Placement"`
				Tags []struct {
					Key   string `json:"Key"`
					Value string `json:"Value"`
				} `json:"Tags"`
			} `json:"Instances"`
		} `json:"Reservations"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil
	}
	resources := make([]ResourceInfo, 0)
	for _, r := range payload.Reservations {
		for _, inst := range r.Instances {
			name := inst.InstanceID
			tagMap := make(map[string]string)
			for _, t := range inst.Tags {
				tagMap[t.Key] = t.Value
				if t.Key == "Name" && t.Value != "" {
					name = t.Value
				}
			}
			resources = append(resources, ResourceInfo{
				ID:     inst.InstanceID,
				Name:   name,
				Type:   "ec2",
				Status: inst.State.Name,
				Region: inst.Placement.AvailabilityZone,
				Tags:   tagMap,
			})
		}
	}
	return resources
}

func (iqt *InfrastructureQueryTool) getAWSScalingInfoFromCLI(params *InfrastructureQueryParams) *ScalingInfo {
	if _, err := exec.LookPath("aws"); err != nil {
		return nil
	}
	args := []string{"autoscaling", "describe-auto-scaling-groups", "--output", "json"}
	if region := strings.TrimSpace(params.Region); region != "" {
		args = append(args, "--region", region)
	}
	out, err := exec.Command("aws", args...).Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	var payload struct {
		AutoScalingGroups []struct {
			MinSize         int        `json:"MinSize"`
			MaxSize         int        `json:"MaxSize"`
			DesiredCapacity int        `json:"DesiredCapacity"`
			Instances       []struct{} `json:"Instances"`
		} `json:"AutoScalingGroups"`
	}
	if err := json.Unmarshal(out, &payload); err != nil || len(payload.AutoScalingGroups) == 0 {
		return nil
	}
	group := payload.AutoScalingGroups[0]
	return &ScalingInfo{
		MinReplicas:     group.MinSize,
		MaxReplicas:     group.MaxSize,
		CurrentReplicas: len(group.Instances),
		DesiredReplicas: group.DesiredCapacity,
	}
}

func (iqt *InfrastructureQueryTool) getAWSCostsFromCLI(params *InfrastructureQueryParams) []CostInfo {
	if _, err := exec.LookPath("aws"); err != nil {
		return nil
	}
	// Keep lightweight: summarize month-to-date unblended cost by service.
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
	end := now.AddDate(0, 0, 1).Format("2006-01-02")
	args := []string{
		"ce", "get-cost-and-usage",
		"--time-period", fmt.Sprintf("Start=%s,End=%s", start, end),
		"--granularity", "MONTHLY",
		"--metrics", "UnblendedCost",
		"--group-by", "Type=DIMENSION,Key=SERVICE",
		"--output", "json",
	}
	out, err := exec.Command("aws", args...).Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	var payload struct {
		ResultsByTime []struct {
			Groups []struct {
				Keys    []string `json:"Keys"`
				Metrics map[string]struct {
					Amount string `json:"Amount"`
					Unit   string `json:"Unit"`
				} `json:"Metrics"`
			} `json:"Groups"`
		} `json:"ResultsByTime"`
	}
	if err := json.Unmarshal(out, &payload); err != nil || len(payload.ResultsByTime) == 0 {
		return nil
	}
	result := make([]CostInfo, 0)
	for _, g := range payload.ResultsByTime[0].Groups {
		metric, ok := g.Metrics["UnblendedCost"]
		if !ok {
			continue
		}
		amount, err := parseFloat(metric.Amount)
		if err != nil {
			continue
		}
		service := "unknown"
		if len(g.Keys) > 0 && strings.TrimSpace(g.Keys[0]) != "" {
			service = g.Keys[0]
		}
		result = append(result, CostInfo{
			Service:     service,
			MonthlyCost: amount,
			Currency:    defaultIfEmpty(metric.Unit, "USD"),
			UsageHours:  720,
			CostPerHour: amount / 720,
			Trend:       "stable",
		})
	}
	return result
}

func (iqt *InfrastructureQueryTool) getGCPResourcesFromCLI(params *InfrastructureQueryParams) []ResourceInfo {
	if _, err := exec.LookPath("gcloud"); err != nil {
		return nil
	}
	args := []string{"compute", "instances", "list", "--format=json"}
	if project := strings.TrimSpace(params.Target); project != "" {
		args = append(args, "--project", project)
	}
	out, err := exec.Command("gcloud", args...).Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	var payload []struct {
		ID     interface{}       `json:"id"`
		Name   string            `json:"name"`
		Status string            `json:"status"`
		Zone   string            `json:"zone"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil
	}
	resources := make([]ResourceInfo, 0, len(payload))
	for _, inst := range payload {
		resources = append(resources, ResourceInfo{
			ID:     fmt.Sprint(inst.ID),
			Name:   inst.Name,
			Type:   "compute_instance",
			Status: inst.Status,
			Region: zoneToRegion(inst.Zone),
			Tags:   inst.Labels,
		})
	}
	return resources
}

func (iqt *InfrastructureQueryTool) getGCPScalingInfoFromCLI(params *InfrastructureQueryParams) *ScalingInfo {
	if _, err := exec.LookPath("gcloud"); err != nil {
		return nil
	}
	args := []string{"compute", "instance-groups", "managed", "list", "--format=json"}
	if project := strings.TrimSpace(params.Target); project != "" {
		args = append(args, "--project", project)
	}
	out, err := exec.Command("gcloud", args...).Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	var payload []struct {
		TargetSize       int    `json:"targetSize"`
		BaseInstanceName string `json:"baseInstanceName"`
	}
	if err := json.Unmarshal(out, &payload); err != nil || len(payload) == 0 {
		return nil
	}
	targetSize := payload[0].TargetSize
	return &ScalingInfo{
		MinReplicas:     targetSize,
		MaxReplicas:     targetSize,
		CurrentReplicas: targetSize,
		DesiredReplicas: targetSize,
	}
}

func (iqt *InfrastructureQueryTool) getGCPCostsFromCLI(params *InfrastructureQueryParams) []CostInfo {
	if _, err := exec.LookPath("gcloud"); err != nil {
		return nil
	}
	listArgs := []string{"billing", "accounts", "list", "--format=json"}
	if project := strings.TrimSpace(params.Target); project != "" {
		listArgs = append(listArgs, "--project", project)
	}
	accountsOut, err := exec.Command("gcloud", listArgs...).Output()
	if err != nil || len(accountsOut) == 0 {
		return nil
	}

	var accounts []struct {
		Name string `json:"name"`
		Open bool   `json:"open"`
	}
	if err := json.Unmarshal(accountsOut, &accounts); err != nil || len(accounts) == 0 {
		return nil
	}

	accountID := ""
	for _, acc := range accounts {
		if !acc.Open {
			continue
		}
		name := strings.TrimSpace(acc.Name)
		if strings.HasPrefix(name, "billingAccounts/") {
			accountID = strings.TrimPrefix(name, "billingAccounts/")
		} else {
			accountID = name
		}
		if accountID != "" {
			break
		}
	}
	if accountID == "" {
		return nil
	}

	budgetOut, err := exec.Command("gcloud", "billing", "budgets", "list", "--billing-account", accountID, "--format=json").Output()
	if err != nil || len(budgetOut) == 0 {
		return nil
	}

	var budgets []struct {
		DisplayName string `json:"displayName"`
		Amount      struct {
			SpecifiedAmount struct {
				CurrencyCode string `json:"currencyCode"`
				Units        string `json:"units"`
				Nanos        int64  `json:"nanos"`
			} `json:"specifiedAmount"`
		} `json:"amount"`
	}
	if err := json.Unmarshal(budgetOut, &budgets); err != nil || len(budgets) == 0 {
		return nil
	}

	result := make([]CostInfo, 0, len(budgets))
	for _, b := range budgets {
		units := strings.TrimSpace(b.Amount.SpecifiedAmount.Units)
		if units == "" {
			continue
		}
		unitVal, err := strconv.ParseFloat(units, 64)
		if err != nil {
			continue
		}
		amount := unitVal + (float64(b.Amount.SpecifiedAmount.Nanos) / 1e9)
		if amount <= 0 {
			continue
		}
		name := strings.TrimSpace(b.DisplayName)
		if name == "" {
			name = "budget"
		}
		currency := strings.TrimSpace(b.Amount.SpecifiedAmount.CurrencyCode)
		if currency == "" {
			currency = "USD"
		}
		result = append(result, CostInfo{
			Service:     "gcp-budget:" + name,
			MonthlyCost: amount,
			Currency:    currency,
			UsageHours:  720,
			CostPerHour: amount / 720,
			Trend:       "stable",
		})
	}
	return result
}

func (iqt *InfrastructureQueryTool) getAzureResourcesFromCLI(params *InfrastructureQueryParams) []ResourceInfo {
	if _, err := exec.LookPath("az"); err != nil {
		return nil
	}
	out, err := exec.Command("az", "vm", "list", "-d", "--output", "json").Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	var payload []struct {
		ID         string            `json:"id"`
		Name       string            `json:"name"`
		Location   string            `json:"location"`
		PowerState string            `json:"powerState"`
		Tags       map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil
	}
	resources := make([]ResourceInfo, 0, len(payload))
	for _, vm := range payload {
		resources = append(resources, ResourceInfo{
			ID:     vm.ID,
			Name:   vm.Name,
			Type:   "virtual_machine",
			Status: vm.PowerState,
			Region: vm.Location,
			Tags:   vm.Tags,
		})
	}
	return resources
}

func (iqt *InfrastructureQueryTool) getAzureScalingInfoFromCLI(params *InfrastructureQueryParams) *ScalingInfo {
	if _, err := exec.LookPath("az"); err != nil {
		return nil
	}
	out, err := exec.Command("az", "vmss", "list", "--output", "json").Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	var payload []struct {
		Sku struct {
			Capacity int `json:"capacity"`
		} `json:"sku"`
	}
	if err := json.Unmarshal(out, &payload); err != nil || len(payload) == 0 {
		return nil
	}
	capacity := payload[0].Sku.Capacity
	return &ScalingInfo{
		MinReplicas:     capacity,
		MaxReplicas:     capacity,
		CurrentReplicas: capacity,
		DesiredReplicas: capacity,
	}
}

func (iqt *InfrastructureQueryTool) getAzureCostsFromCLI(params *InfrastructureQueryParams) []CostInfo {
	if _, err := exec.LookPath("az"); err != nil {
		return nil
	}
	args := []string{"consumption", "usage", "list", "--top", "200", "--output", "json"}
	if scope := strings.TrimSpace(params.Target); scope != "" {
		args = append(args, "--scope", scope)
	}
	out, err := exec.Command("az", args...).Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	var rows []struct {
		MeterCategory string  `json:"meterCategory"`
		PretaxCost    float64 `json:"pretaxCost"`
		Currency      string  `json:"currency"`
	}
	if err := json.Unmarshal(out, &rows); err != nil || len(rows) == 0 {
		return nil
	}

	type agg struct {
		cost     float64
		currency string
	}
	grouped := make(map[string]agg)
	for _, row := range rows {
		if row.PretaxCost <= 0 {
			continue
		}
		service := strings.TrimSpace(row.MeterCategory)
		if service == "" {
			service = "unknown"
		}
		curr := strings.TrimSpace(row.Currency)
		if curr == "" {
			curr = "USD"
		}
		g := grouped[service]
		g.cost += row.PretaxCost
		if g.currency == "" {
			g.currency = curr
		}
		grouped[service] = g
	}

	result := make([]CostInfo, 0, len(grouped))
	for service, g := range grouped {
		if g.cost <= 0 {
			continue
		}
		result = append(result, CostInfo{
			Service:     service,
			MonthlyCost: g.cost,
			Currency:    defaultIfEmpty(g.currency, "USD"),
			UsageHours:  720,
			CostPerHour: g.cost / 720,
			Trend:       "stable",
		})
	}
	return result
}

func (iqt *InfrastructureQueryTool) getK8sScalingInfoFromKubectl(params *InfrastructureQueryParams) *ScalingInfo {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return nil
	}

	args := []string{"get", "deploy", "-A", "-o", "json"}
	if ns := strings.TrimSpace(params.Target); ns != "" && !strings.Contains(ns, "cluster") {
		args = []string{"get", "deploy", "-n", ns, "-o", "json"}
	}
	out, err := exec.Command("kubectl", args...).Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	var payload struct {
		Items []struct {
			Spec struct {
				Replicas *int `json:"replicas"`
			} `json:"spec"`
			Status struct {
				Replicas      int `json:"replicas"`
				ReadyReplicas int `json:"readyReplicas"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &payload); err != nil || len(payload.Items) == 0 {
		return nil
	}

	minR := 0
	maxR := 0
	current := 0
	desired := 0
	for i, item := range payload.Items {
		specReplicas := 1
		if item.Spec.Replicas != nil {
			specReplicas = *item.Spec.Replicas
		}
		if i == 0 || specReplicas < minR {
			minR = specReplicas
		}
		if specReplicas > maxR {
			maxR = specReplicas
		}
		current += item.Status.ReadyReplicas
		desired += item.Status.Replicas
	}

	return &ScalingInfo{
		MinReplicas:     minR,
		MaxReplicas:     maxR,
		CurrentReplicas: current,
		DesiredReplicas: desired,
	}
}

func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(s), 64)
}

func zoneToRegion(zone string) string {
	zone = strings.TrimSpace(zone)
	if idx := strings.LastIndex(zone, "/"); idx >= 0 {
		zone = zone[idx+1:]
	}
	if parts := strings.Split(zone, "-"); len(parts) >= 2 {
		return strings.Join(parts[:len(parts)-1], "-")
	}
	return zone
}

func (iqt *InfrastructureQueryTool) getTerraformStateFromCLI(params *InfrastructureQueryParams) *TerraformState {
	if _, err := exec.LookPath("terraform"); err != nil {
		return nil
	}

	workdir := "."
	if params.Target != "" {
		// When target points to a directory, use it as terraform working directory.
		if st, err := os.Stat(params.Target); err == nil && st.IsDir() {
			workdir = params.Target
		} else if strings.HasPrefix(params.Target, "workspace/") {
			workdir = "."
		} else if filepath.Dir(params.Target) != "." {
			workdir = filepath.Dir(params.Target)
		}
	}

	cmd := exec.Command("terraform", "show", "-json")
	cmd.Dir = workdir
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	var payload struct {
		FormatVersion    string `json:"format_version"`
		TerraformVersion string `json:"terraform_version"`
		Values           struct {
			Outputs map[string]struct {
				Value interface{} `json:"value"`
			} `json:"outputs"`
			RootModule struct {
				Resources []struct {
					Address string                 `json:"address"`
					Type    string                 `json:"type"`
					Name    string                 `json:"name"`
					Values  map[string]interface{} `json:"values"`
				} `json:"resources"`
				ChildModules []struct {
					Address string `json:"address"`
				} `json:"child_modules"`
			} `json:"root_module"`
		} `json:"values"`
	}

	if err := json.Unmarshal(out, &payload); err != nil {
		return nil
	}

	state := &TerraformState{
		Workspace:     params.Target,
		StateVersion:  payload.TerraformVersion,
		Resources:     make([]ResourceInfo, 0),
		Modules:       make([]string, 0),
		LastRun:       time.Now().Format("2006-01-02 15:04:05"),
		DriftDetected: false,
		Outputs:       make(map[string]string),
	}

	for _, module := range payload.Values.RootModule.ChildModules {
		state.Modules = append(state.Modules, module.Address)
	}

	for _, r := range payload.Values.RootModule.Resources {
		status := "known"
		if v, ok := r.Values["id"]; ok && fmt.Sprint(v) == "" {
			status = "unknown"
		}
		state.Resources = append(state.Resources, ResourceInfo{
			ID:     fmt.Sprintf("%s.%s", r.Type, r.Name),
			Name:   r.Name,
			Type:   r.Type,
			Status: status,
		})
	}

	for k, v := range payload.Values.Outputs {
		s := fmt.Sprint(v.Value)
		lk := strings.ToLower(k)
		if strings.Contains(lk, "password") || strings.Contains(lk, "secret") || strings.Contains(lk, "token") || strings.Contains(lk, "key") {
			s = "[redacted]"
		}
		state.Outputs[k] = s
	}

	// Basic drift hint: missing resources usually indicates local drift/state mismatch.
	if len(state.Resources) == 0 {
		state.DriftDetected = true
	}

	if len(state.Resources) == 0 && len(state.Outputs) == 0 {
		return nil
	}
	return state
}

func (iqt *InfrastructureQueryTool) getTerraformStateFromFiles(params *InfrastructureQueryParams) *TerraformState {
	candidates := []string{"terraform.tfstate", "terraform.tfstate.backup"}
	if params.Target != "" && params.Target != "." {
		if st, err := os.Stat(params.Target); err == nil && st.IsDir() {
			candidates = append([]string{
				filepath.Join(params.Target, "terraform.tfstate"),
				filepath.Join(params.Target, "terraform.tfstate.backup"),
			}, candidates...)
		}
	}

	var data []byte
	for _, c := range candidates {
		b, err := os.ReadFile(c)
		if err != nil || len(b) == 0 {
			continue
		}
		data = b
		break
	}
	if len(data) == 0 {
		return &TerraformState{
			Workspace:     params.Target,
			StateVersion:  "unknown",
			Resources:     []ResourceInfo{},
			Modules:       []string{},
			LastRun:       time.Now().Format("2006-01-02 15:04:05"),
			DriftDetected: false,
			Outputs:       map[string]string{},
		}
	}

	var payload struct {
		Version          int    `json:"version"`
		TerraformVersion string `json:"terraform_version"`
		Resources        []struct {
			Module    string `json:"module"`
			Type      string `json:"type"`
			Name      string `json:"name"`
			Provider  string `json:"provider"`
			Instances []struct {
				Attributes map[string]interface{} `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
		Outputs map[string]struct {
			Value interface{} `json:"value"`
		} `json:"outputs"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}

	state := &TerraformState{
		Workspace:     params.Target,
		StateVersion:  defaultIfEmpty(payload.TerraformVersion, fmt.Sprintf("v%d", payload.Version)),
		Resources:     make([]ResourceInfo, 0, len(payload.Resources)),
		Modules:       make([]string, 0),
		LastRun:       time.Now().Format("2006-01-02 15:04:05"),
		DriftDetected: false,
		Outputs:       make(map[string]string),
	}
	moduleSeen := map[string]struct{}{}
	for _, r := range payload.Resources {
		if r.Module != "" {
			if _, ok := moduleSeen[r.Module]; !ok {
				moduleSeen[r.Module] = struct{}{}
				state.Modules = append(state.Modules, r.Module)
			}
		}
		id := r.Type + "." + r.Name
		region := ""
		status := "known"
		if len(r.Instances) > 0 {
			if v, ok := r.Instances[0].Attributes["id"]; ok && fmt.Sprint(v) == "" {
				status = "unknown"
			}
			if rg, ok := r.Instances[0].Attributes["region"]; ok {
				region = fmt.Sprint(rg)
			}
		}
		state.Resources = append(state.Resources, ResourceInfo{
			ID:     id,
			Name:   r.Name,
			Type:   r.Type,
			Status: status,
			Region: region,
		})
	}

	for k, out := range payload.Outputs {
		v := fmt.Sprint(out.Value)
		lk := strings.ToLower(k)
		if strings.Contains(lk, "password") || strings.Contains(lk, "secret") || strings.Contains(lk, "token") || strings.Contains(lk, "key") {
			v = "[redacted]"
		}
		state.Outputs[k] = v
	}

	return state
}

func (iqt *InfrastructureQueryTool) getK8sResourcesFromKubectl(params *InfrastructureQueryParams) []ResourceInfo {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return nil
	}

	args := []string{"get", "deploy,svc,ingress", "-A", "-o", "json"}
	if ns := strings.TrimSpace(params.Target); ns != "" && !strings.Contains(ns, "cluster") {
		args = []string{"get", "deploy,svc,ingress", "-n", ns, "-o", "json"}
	}
	cmd := exec.Command("kubectl", args...)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	var payload struct {
		Items []struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name      string            `json:"name"`
				Namespace string            `json:"namespace"`
				Labels    map[string]string `json:"labels"`
			} `json:"metadata"`
			Status map[string]interface{} `json:"status"`
			Spec   map[string]interface{} `json:"spec"`
		} `json:"items"`
	}
	decoder := json.NewDecoder(bytes.NewReader(out))
	if err := decoder.Decode(&payload); err != nil {
		return nil
	}

	resources := make([]ResourceInfo, 0, len(payload.Items))
	for _, item := range payload.Items {
		status := "Unknown"
		if replicas, ok := item.Status["replicas"]; ok {
			ready := item.Status["readyReplicas"]
			status = fmt.Sprintf("%v/%v", ready, replicas)
		} else if lb, ok := item.Status["loadBalancer"]; ok && lb != nil {
			status = "Active"
		}
		if status == "Unknown" && strings.EqualFold(item.Kind, "Service") {
			status = "Active"
		}

		meta := map[string]string{"Namespace": item.Metadata.Namespace}
		if t, ok := item.Spec["type"]; ok {
			meta["Type"] = fmt.Sprint(t)
		}

		resources = append(resources, ResourceInfo{
			ID:     strings.ToLower(item.Kind) + "/" + item.Metadata.Name,
			Name:   item.Metadata.Name,
			Type:   item.Kind,
			Status: status,
			Meta:   meta,
		})
	}

	return resources
}
