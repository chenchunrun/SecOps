package secops

import (
	"fmt"
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
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Status     string            `json:"status"`
	Region     string            `json:"region,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	CreatedAt  string            `json:"created_at,omitempty"`
	UpdatedAt  string            `json:"updated_at,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`
}

// ScalingInfo 扩缩容信息
type ScalingInfo struct {
	MinReplicas    int     `json:"min_replicas"`
	MaxReplicas    int     `json:"max_replicas"`
	CurrentReplicas int    `json:"current_replicas"`
	DesiredReplicas int     `json:"desired_replicas"`
	CPUUtilization float64 `json:"cpu_utilization,omitempty"`
	MemUtilization float64 `json:"mem_utilization,omitempty"`
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
	Workspace     string     `json:"workspace"`
	StateVersion  string     `json:"state_version"`
	Resources     []ResourceInfo `json:"resources"`
	Modules      []string   `json:"modules,omitempty"`
	LastRun      string     `json:"last_run"`
	DriftDetected bool      `json:"drift_detected"`
	Outputs      map[string]string `json:"outputs,omitempty"`
}

// InfrastructureQueryResult 基础设施查询结果
type InfrastructureQueryResult struct {
	SystemType   string            `json:"system_type"`
	QueryType    string            `json:"query_type"`
	Resources    []ResourceInfo    `json:"resources,omitempty"`
	ScalingInfo  *ScalingInfo      `json:"scaling_info,omitempty"`
	CostInfo     []CostInfo        `json:"cost_info,omitempty"`
	TerraformState *TerraformState `json:"terraform_state,omitempty"`
	Error        string            `json:"error,omitempty"`
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
	state := &TerraformState{
		Workspace:     params.Target,
		StateVersion:  "1.6.0",
		Resources:     make([]ResourceInfo, 0),
		Modules:       []string{"module.vpc", "module.ecs", "module.rds"},
		LastRun:       time.Now().Add(-2 * time.Hour).Format("2006-01-02 15:04:05"),
		DriftDetected: true,
		Outputs: map[string]string{
			"vpc_id":           "vpc-0a1b2c3d4e5f",
			"cluster_endpoint": "https://eks.us-east-1.amazonaws.com/clusters/prod",
			"database_url":     "[redacted]",
			"redis_endpoint":   "redis-prod.xxxxxx.0001.usw2.cache.amazonaws.com:6379",
		},
	}

	state.Resources = append(state.Resources,
		ResourceInfo{
			ID:        "i-0abcdef1234567890",
			Name:      "prod-web-server-01",
			Type:      "aws_instance",
			Status:    "running",
			Region:    "us-east-1",
			Tags:      map[string]string{"Environment": "production", "Team": "platform"},
			CreatedAt: "2026-01-15 10:00:00",
		},
		ResourceInfo{
			ID:        "vpc-0a1b2c3d4e5f",
			Name:      "prod-vpc",
			Type:      "aws_vpc",
			Status:    "available",
			Region:    "us-east-1",
			Tags:      map[string]string{"Environment": "production"},
			CreatedAt: "2026-01-01 00:00:00",
		},
		ResourceInfo{
			ID:        "sg-0123456789abcdef",
			Name:      "prod-web-sg",
			Type:      "aws_security_group",
			Status:    "active",
			Region:    "us-east-1",
			Tags:      map[string]string{"Environment": "production"},
			CreatedAt: "2026-01-01 00:00:00",
		},
		ResourceInfo{
			ID:        "rds-db-0123456789abcdef",
			Name:      "prod-postgres",
			Type:      "aws_db_instance",
			Status:    "available",
			Region:    "us-east-1",
			Tags:      map[string]string{"Environment": "production", "Tier": "database"},
			CreatedAt: "2026-01-10 00:00:00",
		},
	)

	return state
}

// getAWSResources 获取 AWS 资源
func (iqt *InfrastructureQueryTool) getAWSResources(params *InfrastructureQueryParams) []ResourceInfo {
	return []ResourceInfo{
		{ID: "i-0abcdef1234567890", Name: "web-server-01", Type: "ec2", Status: "running", Region: "us-east-1", Tags: map[string]string{"Service": "web"}},
		{ID: "i-0abcdef1234567891", Name: "web-server-02", Type: "ec2", Status: "running", Region: "us-east-1", Tags: map[string]string{"Service": "web"}},
		{ID: "asg-prod-web", Name: "prod-web-asg", Type: "autoscaling", Status: "active", Region: "us-east-1"},
		{ID: "alb-prod", Name: "prod-alb", Type: "elb", Status: "active", Region: "us-east-1"},
	}
}

// getAWSScalingInfo 获取 AWS 扩缩容信息
func (iqt *InfrastructureQueryTool) getAWSScalingInfo(params *InfrastructureQueryParams) *ScalingInfo {
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
	return []ResourceInfo{
		{ID: "instance-01", Name: "gce-web-01", Type: "compute_instance", Status: "RUNNING", Region: "us-central1", Tags: map[string]string{"env": "prod"}},
		{ID: "instance-02", Name: "gce-web-02", Type: "compute_instance", Status: "RUNNING", Region: "us-central1", Tags: map[string]string{"env": "prod"}},
		{ID: "gke-prod-cluster", Name: "prod-gke", Type: "gke_cluster", Status: "RUNNING", Region: "us-central1"},
	}
}

// getGCPScalingInfo 获取 GCP 扩缩容信息
func (iqt *InfrastructureQueryTool) getGCPScalingInfo(params *InfrastructureQueryParams) *ScalingInfo {
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
	return []CostInfo{
		{Service: "Compute Engine", MonthlyCost: 890.00, Currency: "USD", UsageHours: 720, CostPerHour: 1.24, Trend: "stable"},
		{Service: "Cloud SQL", MonthlyCost: 245.00, Currency: "USD", UsageHours: 720, CostPerHour: 0.34, Trend: "stable"},
		{Service: "GKE", MonthlyCost: 156.00, Currency: "USD", UsageHours: 720, CostPerHour: 0.22, Trend: "increasing"},
	}
}

// getAzureResources 获取 Azure 资源
func (iqt *InfrastructureQueryTool) getAzureResources(params *InfrastructureQueryParams) []ResourceInfo {
	return []ResourceInfo{
		{ID: "vm-web-01", Name: "azure-web-01", Type: "virtual_machine", Status: "Running", Region: "eastus", Tags: map[string]string{"env": "prod"}},
		{ID: "vm-web-02", Name: "azure-web-02", Type: "virtual_machine", Status: "Running", Region: "eastus", Tags: map[string]string{"env": "prod"}},
		{ID: "aks-prod", Name: "prod-aks", Type: "aks_cluster", Status: "Running", Region: "eastus"},
	}
}

// getAzureScalingInfo 获取 Azure 扩缩容信息
func (iqt *InfrastructureQueryTool) getAzureScalingInfo(params *InfrastructureQueryParams) *ScalingInfo {
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
	return []CostInfo{
		{Service: "Virtual Machines", MonthlyCost: 678.00, Currency: "USD", UsageHours: 720, CostPerHour: 0.94, Trend: "stable"},
		{Service: "Azure Kubernetes", MonthlyCost: 234.00, Currency: "USD", UsageHours: 720, CostPerHour: 0.33, Trend: "stable"},
		{Service: "SQL Database", MonthlyCost: 189.00, Currency: "USD", UsageHours: 720, CostPerHour: 0.26, Trend: "increasing"},
	}
}

// getK8sResources 获取 Kubernetes 资源
func (iqt *InfrastructureQueryTool) getK8sResources(params *InfrastructureQueryParams) []ResourceInfo {
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
	return &ScalingInfo{
		MinReplicas:     2,
		MaxReplicas:     10,
		CurrentReplicas: 3,
		DesiredReplicas: 3,
		CPUUtilization:  41.0,
		MemUtilization:  58.0,
	}
}
