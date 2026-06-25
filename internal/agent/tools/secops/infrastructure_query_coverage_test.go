package secops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// infraRunCmd is the canonical signature of the InfrastructureQueryTool.runCmd
// field, repeated here so table-driven tests can store stub overrides inline.
type infraRunCmd func(ctx context.Context, name string, args ...string) ([]byte, []byte, error)

// TestInfrastructureQueryTool_getAWSResourcesFromCLI 覆盖 AWS 资源 CLI 解析的各种分支。
func TestInfrastructureQueryTool_getAWSResourcesFromCLI(t *testing.T) {
	// 多实例 + Name 标签 + region 参数，覆盖完整解析路径。
	fullJSON := `{"Reservations":[{"Instances":[
		{"InstanceId":"i-aaa","State":{"Name":"running"},"Placement":{"AvailabilityZone":"us-east-1a"},"Tags":[{"Key":"Name","Value":"web-01"},{"Key":"env","Value":"prod"}]},
		{"InstanceId":"i-bbb","State":{"Name":"stopped"},"Placement":{"AvailabilityZone":"us-east-1b"},"Tags":[]}
	]}]}`

	tests := []struct {
		name   string
		params *InfrastructureQueryParams
		runCmd infraRunCmd
		// 校验回调
		check func(t *testing.T, resources []ResourceInfo)
	}{
		{
			name:   "正常解析多实例含Name标签",
			params: &InfrastructureQueryParams{SystemType: "aws", Region: "us-east-1"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(fullJSON), nil, nil
			},
			check: func(t *testing.T, resources []ResourceInfo) {
				if len(resources) != 2 {
					t.Fatalf("期望 2 个资源, 得到 %d", len(resources))
				}
				if resources[0].Name != "web-01" {
					t.Errorf("期望 Name=web-01, 得到 %q", resources[0].Name)
				}
				if resources[0].Tags["env"] != "prod" {
					t.Errorf("期望标签 env=prod, 得到 %q", resources[0].Tags["env"])
				}
				if resources[0].Region != "us-east-1a" {
					t.Errorf("期望 Region=us-east-1a, 得到 %q", resources[0].Region)
				}
				if resources[1].Status != "stopped" {
					t.Errorf("期望 Status=stopped, 得到 %q", resources[1].Status)
				}
				// 无 Name 标签时应回退为 InstanceId。
				if resources[1].Name != "i-bbb" {
					t.Errorf("期望无Name标签时 Name=InstanceId, 得到 %q", resources[1].Name)
				}
			},
		},
		{
			name:   "空输出返回nil",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, []byte("empty"), nil
			},
			check: func(t *testing.T, resources []ResourceInfo) {
				if len(resources) != 0 {
					t.Fatalf("期望空结果, 得到 %d", len(resources))
				}
			},
		},
		{
			name:   "命令错误返回nil",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, []byte("boom"), errors.New("boom")
			},
			check: func(t *testing.T, resources []ResourceInfo) {
				if resources != nil {
					t.Fatalf("期望 nil, 得到 %v", resources)
				}
			},
		},
		{
			name:   "非法JSON返回nil",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte("{not-json"), nil, nil
			},
			check: func(t *testing.T, resources []ResourceInfo) {
				if resources != nil {
					t.Fatalf("期望 nil, 得到 %v", resources)
				}
			},
		},
		{
			name:   "空Reservations列表返回空切片",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"Reservations":[]}`), nil, nil
			},
			check: func(t *testing.T, resources []ResourceInfo) {
				if len(resources) != 0 {
					t.Fatalf("期望 0 个资源, 得到 %d", len(resources))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := NewInfrastructureQueryTool(nil)
			tool.runCmd = tt.runCmd
			resources := tool.getAWSResourcesFromCLI(tt.params)
			tt.check(t, resources)
		})
	}
}

// TestInfrastructureQueryTool_getAWSScalingInfoFromCLI 覆盖 ASG 扩缩容解析。
func TestInfrastructureQueryTool_getAWSScalingInfoFromCLI(t *testing.T) {
	tests := []struct {
		name    string
		params  *InfrastructureQueryParams
		runCmd  infraRunCmd
		wantNil bool
		check   func(t *testing.T, s *ScalingInfo)
	}{
		{
			name:   "正常解析ASG扩缩容",
			params: &InfrastructureQueryParams{SystemType: "aws", Region: "ap-east-1"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"AutoScalingGroups":[{"MinSize":2,"MaxSize":10,"DesiredCapacity":4,"Instances":[{},{},{},{}]}]}`), nil, nil
			},
			check: func(t *testing.T, s *ScalingInfo) {
				if s == nil {
					t.Fatal("期望非 nil")
				}
				if s.MinReplicas != 2 || s.MaxReplicas != 10 || s.DesiredReplicas != 4 || s.CurrentReplicas != 4 {
					t.Errorf("解析不匹配: %+v", s)
				}
			},
		},
		{
			name:   "命令错误返回nil",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, []byte("err"), errors.New("err")
			},
			wantNil: true,
		},
		{
			name:   "空AutoScalingGroups返回nil",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"AutoScalingGroups":[]}`), nil, nil
			},
			wantNil: true,
		},
		{
			name:   "非法JSON返回nil",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`not-json`), nil, nil
			},
			wantNil: true,
		},
		{
			name:   "空输出返回nil",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, nil, nil
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := NewInfrastructureQueryTool(nil)
			tool.runCmd = tt.runCmd
			scaling := tool.getAWSScalingInfoFromCLI(tt.params)
			if tt.wantNil {
				if scaling != nil {
					t.Fatalf("期望 nil, 得到 %+v", scaling)
				}
				return
			}
			tt.check(t, scaling)
		})
	}
}

// TestInfrastructureQueryTool_getAWSCostsFromCLI 覆盖成本查询解析与分组。
func TestInfrastructureQueryTool_getAWSCostsFromCLI(t *testing.T) {
	tests := []struct {
		name    string
		params  *InfrastructureQueryParams
		runCmd  infraRunCmd
		wantNil bool
		check   func(t *testing.T, costs []CostInfo)
	}{
		{
			name:   "正常解析成本分组",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"ResultsByTime":[{"Groups":[
					{"Keys":["EC2"],"Metrics":{"UnblendedCost":{"Amount":"1245.50","Unit":"USD"}}},
					{"Keys":["RDS"],"Metrics":{"UnblendedCost":{"Amount":"389.00","Unit":"USD"}}}
				]}]}`), nil, nil
			},
			check: func(t *testing.T, costs []CostInfo) {
				if len(costs) != 2 {
					t.Fatalf("期望 2 条成本, 得到 %d", len(costs))
				}
				bySvc := map[string]CostInfo{}
				for _, c := range costs {
					bySvc[c.Service] = c
				}
				if bySvc["EC2"].MonthlyCost < 1245.4 || bySvc["EC2"].MonthlyCost > 1245.6 {
					t.Errorf("EC2 月成本不匹配: %f", bySvc["EC2"].MonthlyCost)
				}
				if bySvc["EC2"].Currency != "USD" {
					t.Errorf("期望货币 USD, 得到 %q", bySvc["EC2"].Currency)
				}
				if bySvc["EC2"].Trend != "stable" {
					t.Errorf("期望 trend=stable, 得到 %q", bySvc["EC2"].Trend)
				}
			},
		},
		{
			name:   "空Service键默认unknown",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"ResultsByTime":[{"Groups":[
					{"Keys":["   "],"Metrics":{"UnblendedCost":{"Amount":"10.0","Unit":"USD"}}}
				]}]}`), nil, nil
			},
			check: func(t *testing.T, costs []CostInfo) {
				if len(costs) != 1 {
					t.Fatalf("期望 1 条, 得到 %d", len(costs))
				}
				if costs[0].Service != "unknown" {
					t.Errorf("期望 Service=unknown, 得到 %q", costs[0].Service)
				}
			},
		},
		{
			name:   "缺失UnblendedCost指标跳过",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"ResultsByTime":[{"Groups":[
					{"Keys":["EC2"],"Metrics":{"BlendedCost":{"Amount":"1.0"}}}
				]}]}`), nil, nil
			},
			check: func(t *testing.T, costs []CostInfo) {
				if len(costs) != 0 {
					t.Fatalf("期望 0 条, 得到 %d", len(costs))
				}
			},
		},
		{
			name:   "非数字Amount跳过",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"ResultsByTime":[{"Groups":[
					{"Keys":["EC2"],"Metrics":{"UnblendedCost":{"Amount":"not-a-number"}}}
				]}]}`), nil, nil
			},
			check: func(t *testing.T, costs []CostInfo) {
				if len(costs) != 0 {
					t.Fatalf("期望 0 条, 得到 %d", len(costs))
				}
			},
		},
		{
			name:   "空Unit默认USD",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"ResultsByTime":[{"Groups":[
					{"Keys":["EC2"],"Metrics":{"UnblendedCost":{"Amount":"10.0","Unit":""}}}
				]}]}`), nil, nil
			},
			check: func(t *testing.T, costs []CostInfo) {
				if len(costs) != 1 {
					t.Fatalf("期望 1 条, 得到 %d", len(costs))
				}
				if costs[0].Currency != "USD" {
					t.Errorf("期望默认 USD, 得到 %q", costs[0].Currency)
				}
			},
		},
		{
			name:   "空ResultsByTime返回nil",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"ResultsByTime":[]}`), nil, nil
			},
			wantNil: true,
		},
		{
			name:   "命令错误返回nil",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, []byte("fail"), errors.New("fail")
			},
			wantNil: true,
		},
		{
			name:   "非法JSON返回nil",
			params: &InfrastructureQueryParams{SystemType: "aws"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{bad`), nil, nil
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := NewInfrastructureQueryTool(nil)
			tool.runCmd = tt.runCmd
			costs := tool.getAWSCostsFromCLI(tt.params)
			if tt.wantNil {
				if costs != nil {
					t.Fatalf("期望 nil, 得到 %v", costs)
				}
				return
			}
			tt.check(t, costs)
		})
	}
}

// TestInfrastructureQueryTool_getAzureResourcesFromCLI 覆盖 Azure 虚拟机资源解析。
func TestInfrastructureQueryTool_getAzureResourcesFromCLI(t *testing.T) {
	tests := []struct {
		name    string
		params  *InfrastructureQueryParams
		runCmd  infraRunCmd
		wantNil bool
		check   func(t *testing.T, resources []ResourceInfo)
	}{
		{
			name:   "正常解析Azure虚拟机",
			params: &InfrastructureQueryParams{SystemType: "azure"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`[
					{"id":"/subscriptions/x/vm/web01","name":"web01","location":"eastus","powerState":"VM running","tags":{"env":"prod"}},
					{"id":"/subscriptions/x/vm/web02","name":"web02","location":"westus","powerState":"VM stopped","tags":null}
				]`), nil, nil
			},
			check: func(t *testing.T, resources []ResourceInfo) {
				if len(resources) != 2 {
					t.Fatalf("期望 2 个资源, 得到 %d", len(resources))
				}
				if resources[0].Name != "web01" || resources[0].Type != "virtual_machine" {
					t.Errorf("第一个资源解析错误: %+v", resources[0])
				}
				if resources[0].Region != "eastus" || resources[0].Status != "VM running" {
					t.Errorf("第一个资源字段错误: %+v", resources[0])
				}
				if resources[0].Tags["env"] != "prod" {
					t.Errorf("期望标签 env=prod, 得到 %v", resources[0].Tags)
				}
				if resources[1].Region != "westus" {
					t.Errorf("期望 Region=westus, 得到 %q", resources[1].Region)
				}
			},
		},
		{
			name:   "空输出返回nil",
			params: &InfrastructureQueryParams{SystemType: "azure"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, nil, nil
			},
			wantNil: true,
		},
		{
			name:   "命令错误返回nil",
			params: &InfrastructureQueryParams{SystemType: "azure"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, []byte("err"), errors.New("err")
			},
			wantNil: true,
		},
		{
			name:   "非法JSON返回nil",
			params: &InfrastructureQueryParams{SystemType: "azure"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`not-json`), nil, nil
			},
			wantNil: true,
		},
		{
			name:   "空数组返回空切片",
			params: &InfrastructureQueryParams{SystemType: "azure"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`[]`), nil, nil
			},
			check: func(t *testing.T, resources []ResourceInfo) {
				if len(resources) != 0 {
					t.Fatalf("期望 0 个资源, 得到 %d", len(resources))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := NewInfrastructureQueryTool(nil)
			tool.runCmd = tt.runCmd
			resources := tool.getAzureResourcesFromCLI(tt.params)
			if tt.wantNil {
				if resources != nil {
					t.Fatalf("期望 nil, 得到 %v", resources)
				}
				return
			}
			tt.check(t, resources)
		})
	}
}

// TestInfrastructureQueryTool_getAzureScalingInfoFromCLI 覆盖 Azure VMSS 扩缩容解析。
func TestInfrastructureQueryTool_getAzureScalingInfoFromCLI(t *testing.T) {
	tests := []struct {
		name    string
		params  *InfrastructureQueryParams
		runCmd  infraRunCmd
		wantNil bool
		check   func(t *testing.T, s *ScalingInfo)
	}{
		{
			name:   "正常解析VMSS扩缩容",
			params: &InfrastructureQueryParams{SystemType: "azure"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`[{"sku":{"capacity":5}},{"sku":{"capacity":3}}]`), nil, nil
			},
			check: func(t *testing.T, s *ScalingInfo) {
				if s == nil {
					t.Fatal("期望非 nil")
				}
				// 取首个 VMSS 的 capacity。
				if s.MinReplicas != 5 || s.MaxReplicas != 5 || s.CurrentReplicas != 5 || s.DesiredReplicas != 5 {
					t.Errorf("解析不匹配: %+v", s)
				}
			},
		},
		{
			name:   "命令错误返回nil",
			params: &InfrastructureQueryParams{SystemType: "azure"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, []byte("err"), errors.New("err")
			},
			wantNil: true,
		},
		{
			name:   "空输出返回nil",
			params: &InfrastructureQueryParams{SystemType: "azure"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, nil, nil
			},
			wantNil: true,
		},
		{
			name:   "空数组返回nil",
			params: &InfrastructureQueryParams{SystemType: "azure"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`[]`), nil, nil
			},
			wantNil: true,
		},
		{
			name:   "非法JSON返回nil",
			params: &InfrastructureQueryParams{SystemType: "azure"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{bad`), nil, nil
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := NewInfrastructureQueryTool(nil)
			tool.runCmd = tt.runCmd
			scaling := tool.getAzureScalingInfoFromCLI(tt.params)
			if tt.wantNil {
				if scaling != nil {
					t.Fatalf("期望 nil, 得到 %+v", scaling)
				}
				return
			}
			tt.check(t, scaling)
		})
	}
}

// TestInfrastructureQueryTool_getK8sScalingInfoFromKubectl 覆盖 kubectl 扩缩容解析。
func TestInfrastructureQueryTool_getK8sScalingInfoFromKubectl(t *testing.T) {
	replicas := int(5)
	tests := []struct {
		name    string
		params  *InfrastructureQueryParams
		runCmd  infraRunCmd
		wantNil bool
		check   func(t *testing.T, s *ScalingInfo)
	}{
		{
			name:   "正常解析多个Deployment带namespace",
			params: &InfrastructureQueryParams{SystemType: "kubernetes", Target: "production"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(fmt.Sprintf(`{"items":[
					{"spec":{"replicas":3},"status":{"replicas":3,"readyReplicas":3}},
					{"spec":{"replicas":%d},"status":{"replicas":%d,"readyReplicas":%d}},
					{"spec":{},"status":{"replicas":1,"readyReplicas":0}}
				]}`, replicas, replicas, replicas)), nil, nil
			},
			check: func(t *testing.T, s *ScalingInfo) {
				if s == nil {
					t.Fatal("期望非 nil")
				}
				// minR 应为最小 spec.replicas（无 spec 默认 1），maxR=5。
				if s.MinReplicas != 1 {
					t.Errorf("期望 MinReplicas=1, 得到 %d", s.MinReplicas)
				}
				if s.MaxReplicas != 5 {
					t.Errorf("期望 MaxReplicas=5, 得到 %d", s.MaxReplicas)
				}
				// current = 3+5+0=8, desired = 3+5+1=9。
				if s.CurrentReplicas != 8 {
					t.Errorf("期望 CurrentReplicas=8, 得到 %d", s.CurrentReplicas)
				}
				if s.DesiredReplicas != 9 {
					t.Errorf("期望 DesiredReplicas=9, 得到 %d", s.DesiredReplicas)
				}
			},
		},
		{
			name:   "集群范围查询",
			params: &InfrastructureQueryParams{SystemType: "kubernetes", Target: "cluster-wide"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"items":[{"spec":{"replicas":2},"status":{"replicas":2,"readyReplicas":2}}]}`), nil, nil
			},
			check: func(t *testing.T, s *ScalingInfo) {
				if s == nil {
					t.Fatal("期望非 nil")
				}
				if s.MinReplicas != 2 || s.MaxReplicas != 2 || s.CurrentReplicas != 2 || s.DesiredReplicas != 2 {
					t.Errorf("解析不匹配: %+v", s)
				}
			},
		},
		{
			name:   "命令错误返回nil",
			params: &InfrastructureQueryParams{SystemType: "kubernetes"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, []byte("err"), errors.New("err")
			},
			wantNil: true,
		},
		{
			name:   "空items返回nil",
			params: &InfrastructureQueryParams{SystemType: "kubernetes"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"items":[]}`), nil, nil
			},
			wantNil: true,
		},
		{
			name:   "空输出返回nil",
			params: &InfrastructureQueryParams{SystemType: "kubernetes"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, nil, nil
			},
			wantNil: true,
		},
		{
			name:   "非法JSON返回nil",
			params: &InfrastructureQueryParams{SystemType: "kubernetes"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{not-json`), nil, nil
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := NewInfrastructureQueryTool(nil)
			tool.runCmd = tt.runCmd
			scaling := tool.getK8sScalingInfoFromKubectl(tt.params)
			if tt.wantNil {
				if scaling != nil {
					t.Fatalf("期望 nil, 得到 %+v", scaling)
				}
				return
			}
			tt.check(t, scaling)
		})
	}
}

// TestInfrastructureQueryTool_getTerraformStateFromCLI 覆盖 terraform show -json 解析。
func TestInfrastructureQueryTool_getTerraformStateFromCLI(t *testing.T) {
	tests := []struct {
		name    string
		params  *InfrastructureQueryParams
		runCmd  infraRunCmd
		wantNil bool
		check   func(t *testing.T, st *TerraformState)
	}{
		{
			name: "正常解析带模块和资源",
			params: &InfrastructureQueryParams{
				SystemType: "terraform",
				Target:     "/tmp/tf-workspace",
			},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{
					"format_version":"1.0",
					"terraform_version":"1.5.7",
					"values":{
						"outputs":{
							"region":{"value":"us-east-1"},
							"db_password":{"value":"supersecret"},
							"api_key":{"value":"abc123"}
						},
						"root_module":{
							"resources":[
								{"address":"aws_instance.web","type":"aws_instance","name":"web","values":{"id":"i-123"}},
								{"address":"aws_instance.db","type":"aws_instance","name":"db","values":{"id":""}}
							],
							"child_modules":[{"address":"module.vpc"},{"address":"module.eks"}]
						}
					}
				}`), nil, nil
			},
			check: func(t *testing.T, st *TerraformState) {
				if st == nil {
					t.Fatal("期望非 nil")
				}
				if st.StateVersion != "1.5.7" {
					t.Errorf("期望 StateVersion=1.5.7, 得到 %q", st.StateVersion)
				}
				if len(st.Resources) != 2 {
					t.Fatalf("期望 2 个资源, 得到 %d", len(st.Resources))
				}
				// 空 id 的资源 status=unknown。
				foundUnknown := false
				for _, r := range st.Resources {
					if r.ID == "aws_instance.db" && r.Status == "unknown" {
						foundUnknown = true
					}
				}
				if !foundUnknown {
					t.Errorf("期望存在 status=unknown 的资源, %+v", st.Resources)
				}
				if len(st.Modules) != 2 {
					t.Errorf("期望 2 个模块, 得到 %d", len(st.Modules))
				}
				// 敏感输出应脱敏。
				if st.Outputs["db_password"] != "[redacted]" {
					t.Errorf("期望 db_password 脱敏, 得到 %q", st.Outputs["db_password"])
				}
				if st.Outputs["api_key"] != "[redacted]" {
					t.Errorf("期望 api_key 脱敏, 得到 %q", st.Outputs["api_key"])
				}
				if st.Outputs["region"] != "us-east-1" {
					t.Errorf("期望 region 原样输出, 得到 %q", st.Outputs["region"])
				}
				if st.DriftDetected {
					t.Errorf("期望 DriftDetected=false")
				}
			},
		},
		{
			name:   "命令错误返回nil",
			params: &InfrastructureQueryParams{SystemType: "terraform"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, []byte("err"), errors.New("err")
			},
			wantNil: true,
		},
		{
			name:   "空输出返回nil",
			params: &InfrastructureQueryParams{SystemType: "terraform"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, nil, nil
			},
			wantNil: true,
		},
		{
			name:   "非法JSON返回nil",
			params: &InfrastructureQueryParams{SystemType: "terraform"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{bad`), nil, nil
			},
			wantNil: true,
		},
		{
			name:   "空资源空输出返回nil",
			params: &InfrastructureQueryParams{SystemType: "terraform"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"format_version":"1.0","terraform_version":"1.5.7","values":{}}`), nil, nil
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := NewInfrastructureQueryTool(nil)
			tool.runCmd = tt.runCmd
			st := tool.getTerraformStateFromCLI(tt.params)
			if tt.wantNil {
				if st != nil {
					t.Fatalf("期望 nil, 得到 %+v", st)
				}
				return
			}
			tt.check(t, st)
		})
	}
}

// TestInfrastructureQueryTool_getTerraformStateFromCLI_WorkdirArgs 验证
// target 指向目录/文件时构造 -chdir 参数的行为。
func TestInfrastructureQueryTool_getTerraformStateFromCLI_WorkdirArgs(t *testing.T) {
	tmp := t.TempDir()

	tests := []struct {
		name          string
		target        string
		wantChdirIn   string // 期望 args 中包含此 chdir 片段
		wantChdirAbsent bool
	}{
		{name: "target为目录生成chdir", target: tmp, wantChdirIn: "-chdir=" + tmp},
		{name: "target为空不生成chdir", target: "", wantChdirAbsent: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := NewInfrastructureQueryTool(nil)
			var gotArgs []string
			tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				gotArgs = append([]string(nil), args...)
				// 返回有效状态避免触发文件回退。
				return []byte(`{"format_version":"1.0","terraform_version":"1.5.7","values":{"root_module":{"resources":[{"type":"null_resource","name":"x","values":{"id":"abc"}}]}}}`), nil, nil
			}

			params := &InfrastructureQueryParams{SystemType: "terraform", Target: tt.target}
			_ = tool.getTerraformStateFromCLI(params)

			joined := strings.Join(gotArgs, " ")
			if tt.wantChdirIn != "" && !strings.Contains(joined, tt.wantChdirIn) {
				t.Errorf("期望 args 包含 %q, 得到 %q", tt.wantChdirIn, joined)
			}
			if tt.wantChdirAbsent && strings.Contains(joined, "-chdir=") {
				t.Errorf("不期望 chdir 参数, 得到 %q", joined)
			}
			// 始终应包含 show -json。
			if !strings.Contains(joined, "show") || !strings.Contains(joined, "-json") {
				t.Errorf("期望 show -json 子命令, 得到 %q", joined)
			}
		})
	}
}

// TestInfrastructureQueryTool_getTerraformStateFromFiles 覆盖本地 tfstate 文件解析。
func TestInfrastructureQueryTool_getTerraformStateFromFiles(t *testing.T) {
	t.Run("正常解析tfstate文件", func(t *testing.T) {
		dir := t.TempDir()
		stateContent := `{
			"version":4,
			"terraform_version":"1.6.0",
			"resources":[
				{"type":"aws_instance","name":"web","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]","instances":[{"attributes":{"id":"i-abc","region":"us-east-1"}}]},
				{"type":"null_resource","name":"x","instances":[{"attributes":{"id":""}}]},
				{"module":"module.vpc","type":"aws_vpc","name":"main","instances":[{"attributes":{"id":"vpc-1"}}]}
			],
			"outputs":{
				"region":{"value":"us-east-1"},
				"secret_token":{"value":"tk_abc"}
			}
		}`
		if err := os.WriteFile(filepath.Join(dir, "terraform.tfstate"), []byte(stateContent), 0o644); err != nil {
			t.Fatal(err)
		}

		tool := NewInfrastructureQueryTool(nil)
		st := tool.getTerraformStateFromFiles(&InfrastructureQueryParams{
			SystemType: "terraform",
			Target:     dir,
		})
		if st == nil {
			t.Fatal("期望非 nil")
		}
		if st.StateVersion != "1.6.0" {
			t.Errorf("期望 StateVersion=1.6.0, 得到 %q", st.StateVersion)
		}
		if len(st.Resources) != 3 {
			t.Fatalf("期望 3 个资源, 得到 %d", len(st.Resources))
		}
		// 模块去重收集。
		if len(st.Modules) != 1 || st.Modules[0] != "module.vpc" {
			t.Errorf("期望模块 [module.vpc], 得到 %v", st.Modules)
		}
		// 带 region 的资源应解析 region 字段。
		var webRes *ResourceInfo
		for i := range st.Resources {
			if st.Resources[i].ID == "aws_instance.web" {
				webRes = &st.Resources[0]
			}
		}
		if webRes != nil && st.Resources[0].Region != "us-east-1" {
			t.Errorf("期望 region=us-east-1, 得到 %q", st.Resources[0].Region)
		}
		// 空 id 资源 status=unknown。
		hasUnknown := false
		for _, r := range st.Resources {
			if r.Status == "unknown" {
				hasUnknown = true
			}
		}
		if !hasUnknown {
			t.Errorf("期望存在 status=unknown 的资源, %+v", st.Resources)
		}
		// 敏感输出脱敏。
		if st.Outputs["secret_token"] != "[redacted]" {
			t.Errorf("期望 secret_token 脱敏, 得到 %q", st.Outputs["secret_token"])
		}
		if st.Outputs["region"] != "us-east-1" {
			t.Errorf("期望 region 原样, 得到 %q", st.Outputs["region"])
		}
	})

	t.Run("无tfstate文件返回unknown版本", func(t *testing.T) {
		dir := t.TempDir()
		tool := NewInfrastructureQueryTool(nil)
		st := tool.getTerraformStateFromFiles(&InfrastructureQueryParams{
			SystemType: "terraform",
			Target:     dir,
		})
		if st == nil {
			t.Fatal("期望非 nil 兜底状态")
		}
		if st.StateVersion != "unknown" {
			t.Errorf("期望 StateVersion=unknown, 得到 %q", st.StateVersion)
		}
		if len(st.Resources) != 0 {
			t.Errorf("期望 0 资源, 得到 %d", len(st.Resources))
		}
		if st.DriftDetected {
			t.Errorf("期望 DriftDetected=false")
		}
	})

	t.Run("空目录但无Target回退到默认候选", func(t *testing.T) {
		// 无 Target 时候选文件为相对路径, 找不到则返回 unknown 状态。
		tool := NewInfrastructureQueryTool(nil)
		st := tool.getTerraformStateFromFiles(&InfrastructureQueryParams{
			SystemType: "terraform",
			Target:     "",
		})
		if st == nil {
			t.Fatal("期望非 nil 兜底状态")
		}
		if st.StateVersion != "unknown" {
			t.Errorf("期望 StateVersion=unknown, 得到 %q", st.StateVersion)
		}
	})

	t.Run("非法JSON返回nil", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "terraform.tfstate"), []byte(`{bad-json`), 0o644); err != nil {
			t.Fatal(err)
		}
		tool := NewInfrastructureQueryTool(nil)
		st := tool.getTerraformStateFromFiles(&InfrastructureQueryParams{
			SystemType: "terraform",
			Target:     dir,
		})
		if st != nil {
			t.Fatalf("期望 nil, 得到 %+v", st)
		}
	})

	t.Run("仅terraform_version缺省时按version回退", func(t *testing.T) {
		dir := t.TempDir()
		// 不包含 terraform_version, 只有 version 字段 -> 走 defaultIfEmpty 回退到 vN。
		stateContent := `{"version":12,"resources":[],"outputs":{}}`
		if err := os.WriteFile(filepath.Join(dir, "terraform.tfstate"), []byte(stateContent), 0o644); err != nil {
			t.Fatal(err)
		}
		tool := NewInfrastructureQueryTool(nil)
		st := tool.getTerraformStateFromFiles(&InfrastructureQueryParams{
			SystemType: "terraform",
			Target:     dir,
		})
		if st == nil {
			t.Fatal("期望非 nil")
		}
		if st.StateVersion != "v12" {
			t.Errorf("期望 StateVersion=v12 (version 回退), 得到 %q", st.StateVersion)
		}
	})

	t.Run("读取backup候选文件", func(t *testing.T) {
		dir := t.TempDir()
		// 仅写 backup 文件, 主文件不存在 -> 应读取 backup。
		stateContent := `{"version":4,"terraform_version":"1.7.0","resources":[{"type":"aws_s3_bucket","name":"b","instances":[{"attributes":{"id":"b1"}}]}],"outputs":{}}`
		if err := os.WriteFile(filepath.Join(dir, "terraform.tfstate.backup"), []byte(stateContent), 0o644); err != nil {
			t.Fatal(err)
		}
		tool := NewInfrastructureQueryTool(nil)
		st := tool.getTerraformStateFromFiles(&InfrastructureQueryParams{
			SystemType: "terraform",
			Target:     dir,
		})
		if st == nil {
			t.Fatal("期望非 nil (读取 backup)")
		}
		if st.StateVersion != "1.7.0" {
			t.Errorf("期望 StateVersion=1.7.0, 得到 %q", st.StateVersion)
		}
		if len(st.Resources) != 1 {
			t.Fatalf("期望 1 个资源来自 backup, 得到 %d", len(st.Resources))
		}
	})
}

// TestInfrastructureQueryTool_getTerraformStateRemoteHostNil 当 RemoteHost 非空且
// CLI 返回 nil 时, getTerraformState 应返回 nil 而非读本地文件。
func TestInfrastructureQueryTool_getTerraformStateRemoteHostNil(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, nil, nil
	}

	st := tool.getTerraformState(&InfrastructureQueryParams{
		SystemType: "terraform",
		RemoteHost: "10.0.0.99",
	})
	if st != nil {
		t.Fatalf("期望 RemoteHost 非空且 CLI 失败时返回 nil, 得到 %+v", st)
	}
}

// TestInfrastructureQueryTool_commandOutputRemoteError 覆盖远程 SSH 命令出错
// 但 stdout 非空时的分支（应忽略错误返回 stdout）。
func TestInfrastructureQueryTool_commandOutputRemoteError(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		// stdout 非空 + stderr + 错误, 应返回 stdout。
		return []byte(`{"Reservations":[]}`), []byte("warning on stderr"), errors.New("exit status 0")
	}

	out, err := tool.commandOutput(&InfrastructureQueryParams{
		RemoteHost: "10.0.0.99",
		RemoteUser: "ops",
	}, "aws", "ec2", "describe-instances", "--output", "json")
	if err != nil {
		t.Fatalf("期望无错（stdout 非空覆盖错误）, 得到 %v", err)
	}
	if string(out) != `{"Reservations":[]}` {
		t.Errorf("期望 stdout 原样返回, 得到 %q", string(out))
	}
}

// TestInfrastructureQueryTool_commandOutputRemoteStdoutEmptyError 覆盖远程 SSH 命令
// stdout 为空且出错时返回错误的分支。
func TestInfrastructureQueryTool_commandOutputRemoteStdoutEmptyError(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, []byte("connection refused"), errors.New("connection refused")
	}

	_, err := tool.commandOutput(&InfrastructureQueryParams{
		RemoteHost: "10.0.0.99",
	}, "aws", "ec2", "describe-instances")
	if err == nil {
		t.Fatal("期望错误, 得到 nil")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("期望错误信息包含 'connection refused', 得到 %q", err.Error())
	}
}

// TestInfrastructureQueryTool_commandOutputLocalError 覆盖本地命令出错分支。
func TestInfrastructureQueryTool_commandOutputLocalError(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, []byte("local failure"), errors.New("local failure")
	}

	_, err := tool.commandOutput(&InfrastructureQueryParams{}, "aws", "ec2", "describe-instances")
	if err == nil {
		t.Fatal("期望错误, 得到 nil")
	}
	if !strings.Contains(err.Error(), "local command failed") {
		t.Errorf("期望错误信息包含 'local command failed', 得到 %q", err.Error())
	}
}

// TestInfrastructureQueryTool_commandOutputNilRunCmd 覆盖 runCmd 为 nil 时
// 自动回退到默认 runInfrastructureCommand 的分支（触发 PATH 上不存在的命令）。
func TestInfrastructureQueryTool_commandOutputNilRunCmd(t *testing.T) {
	tool := NewInfrastructureQueryTool(nil)
	tool.runCmd = nil
	// PATH 中刻意不包含 aws，使 exec.CommandContext 失败。
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", "/nonexistent")

	_, err := tool.commandOutput(&InfrastructureQueryParams{}, "aws", "ec2", "describe-instances")
	if err == nil {
		t.Fatal("期望错误（命令不存在）, 得到 nil")
	}

	// 恢复以便后续测试。
	t.Setenv("PATH", origPath)
}

// TestInfrastructureQueryTool_getGCPResourcesFromCLI 覆盖 GCP compute instances 解析。
func TestInfrastructureQueryTool_getGCPResourcesFromCLI(t *testing.T) {
	tests := []struct {
		name    string
		params  *InfrastructureQueryParams
		runCmd  infraRunCmd
		wantNil bool
		check   func(t *testing.T, resources []ResourceInfo)
	}{
		{
			name:   "正常解析含zone到region转换",
			params: &InfrastructureQueryParams{SystemType: "gcp", Target: "my-project"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`[
					{"id":"123","name":"gce-1","status":"RUNNING","zone":"us-central1-a","labels":{"env":"prod"}},
					{"id":456,"name":"gce-2","status":"RUNNING","zone":"projects/x/zones/europe-west1-b","labels":null}
				]`), nil, nil
			},
			check: func(t *testing.T, resources []ResourceInfo) {
				if len(resources) != 2 {
					t.Fatalf("期望 2 个资源, 得到 %d", len(resources))
				}
				if resources[0].Region != "us-central1" {
					t.Errorf("期望 Region=us-central1, 得到 %q", resources[0].Region)
				}
				if resources[1].Region != "europe-west1" {
					t.Errorf("期望 Region=europe-west1, 得到 %q", resources[1].Region)
				}
				// id 为数字时应通过 fmt.Sprint 转换。
				if resources[1].ID != "456" {
					t.Errorf("期望 ID=456, 得到 %q", resources[1].ID)
				}
				if resources[0].Tags["env"] != "prod" {
					t.Errorf("期望标签 env=prod, 得到 %v", resources[0].Tags)
				}
			},
		},
		{
			name:   "命令错误返回nil",
			params: &InfrastructureQueryParams{SystemType: "gcp"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, []byte("err"), errors.New("err")
			},
			wantNil: true,
		},
		{
			name:   "空输出返回nil",
			params: &InfrastructureQueryParams{SystemType: "gcp"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, nil, nil
			},
			wantNil: true,
		},
		{
			name:   "非法JSON返回nil",
			params: &InfrastructureQueryParams{SystemType: "gcp"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{bad`), nil, nil
			},
			wantNil: true,
		},
		{
			name:   "空数组返回空切片",
			params: &InfrastructureQueryParams{SystemType: "gcp"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`[]`), nil, nil
			},
			check: func(t *testing.T, resources []ResourceInfo) {
				if len(resources) != 0 {
					t.Fatalf("期望 0 个资源, 得到 %d", len(resources))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := NewInfrastructureQueryTool(nil)
			tool.runCmd = tt.runCmd
			resources := tool.getGCPResourcesFromCLI(tt.params)
			if tt.wantNil {
				if resources != nil {
					t.Fatalf("期望 nil, 得到 %v", resources)
				}
				return
			}
			tt.check(t, resources)
		})
	}
}

// TestInfrastructureQueryTool_getGCPScalingInfoFromCLI 覆盖 GCP MIG 扩缩容解析。
func TestInfrastructureQueryTool_getGCPScalingInfoFromCLI(t *testing.T) {
	tests := []struct {
		name    string
		params  *InfrastructureQueryParams
		runCmd  infraRunCmd
		wantNil bool
		check   func(t *testing.T, s *ScalingInfo)
	}{
		{
			name:   "正常解析MIG targetSize",
			params: &InfrastructureQueryParams{SystemType: "gcp", Target: "my-project"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`[{"targetSize":6,"baseInstanceName":"gce-web"},{"targetSize":3}]`), nil, nil
			},
			check: func(t *testing.T, s *ScalingInfo) {
				if s == nil {
					t.Fatal("期望非 nil")
				}
				// 取首个 MIG 的 targetSize。
				if s.MinReplicas != 6 || s.MaxReplicas != 6 || s.CurrentReplicas != 6 || s.DesiredReplicas != 6 {
					t.Errorf("解析不匹配: %+v", s)
				}
			},
		},
		{
			name:   "命令错误返回nil",
			params: &InfrastructureQueryParams{SystemType: "gcp"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, []byte("err"), errors.New("err")
			},
			wantNil: true,
		},
		{
			name:   "空数组返回nil",
			params: &InfrastructureQueryParams{SystemType: "gcp"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`[]`), nil, nil
			},
			wantNil: true,
		},
		{
			name:   "非法JSON返回nil",
			params: &InfrastructureQueryParams{SystemType: "gcp"},
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{bad`), nil, nil
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := NewInfrastructureQueryTool(nil)
			tool.runCmd = tt.runCmd
			scaling := tool.getGCPScalingInfoFromCLI(tt.params)
			if tt.wantNil {
				if scaling != nil {
					t.Fatalf("期望 nil, 得到 %+v", scaling)
				}
				return
			}
			tt.check(t, scaling)
		})
	}
}

// TestInfrastructureQueryTool_parseFloatAndZoneToRegion 直接覆盖 0% 的辅助函数。
func TestInfrastructureQueryTool_parseFloatAndZoneToRegion(t *testing.T) {
	// parseFloat
	got, err := parseFloat("  123.45  ")
	if err != nil {
		t.Fatalf("parseFloat 期望无错, 得到 %v", err)
	}
	if got < 123.4 || got > 123.5 {
		t.Errorf("parseFloat 期望 123.45, 得到 %f", got)
	}
	if _, err := parseFloat("not-a-number"); err == nil {
		t.Errorf("parseFloat 非数字期望错误")
	}

	// zoneToRegion: 各类 zone 格式。
	cases := map[string]string{
		"us-central1-a":          "us-central1",
		"europe-west1-b":         "europe-west1",
		"projects/x/zones/asia-east1-a": "asia-east1",
		"single":                 "single", // 无连字符原样返回
		"":                       "",       // 空字符串
		"  us-east1-c  ":         "us-east1", // 含空白会被 trim 后按 zone 处理
	}
	for zone, want := range cases {
		if got := zoneToRegion(zone); got != want {
			t.Errorf("zoneToRegion(%q) = %q, 期望 %q", zone, got, want)
		}
	}
}

// TestInfrastructureQueryTool_shellQuoteInfra 覆盖 shellQuoteInfra 边界。
func TestInfrastructureQueryTool_shellQuoteInfra(t *testing.T) {
	if got := shellQuoteInfra(""); got != "''" {
		t.Errorf("空字符串期望 '', 得到 %q", got)
	}
	// 含单引号 -> 应触发 '"'"' 转义。
	if got := shellQuoteInfra("it's"); !strings.Contains(got, `'"'"'`) {
		t.Errorf("含单引号期望转义, 得到 %q", got)
	}
	if !strings.HasPrefix(shellQuoteInfra("abc"), "'abc'") {
		t.Errorf("普通字符串期望单引号包裹")
	}
}

// TestInfrastructureQueryTool_getK8sResourcesFromKubectl_StatusBranches
// 覆盖 kubectl 资源解析的 Service/LoadBalancer 状态分支。
func TestInfrastructureQueryTool_getK8sResourcesFromKubectl_StatusBranches(t *testing.T) {
	tests := []struct {
		name   string
		runCmd infraRunCmd
		check  func(t *testing.T, resources []ResourceInfo)
	}{
		{
			name: "Deployment replicas状态与Service loadBalancer状态",
			runCmd: func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return []byte(`{"items":[
					{"kind":"Deployment","metadata":{"name":"web","namespace":"prod"},"status":{"replicas":3,"readyReplicas":2},"spec":{}},
					{"kind":"Service","metadata":{"name":"web-svc","namespace":"prod"},"status":{"loadBalancer":{"ingress":[{"ip":"1.2.3.4"}]}},"spec":{"type":"LoadBalancer"}},
					{"kind":"Service","metadata":{"name":"internal-svc","namespace":"prod"},"status":{},"spec":{"type":"ClusterIP"}}
				]}`), nil, nil
			},
			check: func(t *testing.T, resources []ResourceInfo) {
				if len(resources) != 3 {
					t.Fatalf("期望 3 个资源, 得到 %d", len(resources))
				}
				// Deployment: replicas 状态 "2/3"。
				if resources[0].Status != "2/3" {
					t.Errorf("期望 Deployment Status=2/3, 得到 %q", resources[0].Status)
				}
				// 带 loadBalancer -> Active。
				if resources[1].Status != "Active" {
					t.Errorf("期望带LB的 Service Status=Active, 得到 %q", resources[1].Status)
				}
				// spec.type 写入 meta。
				if resources[1].Meta["Type"] != "LoadBalancer" {
					t.Errorf("期望 meta Type=LoadBalancer, 得到 %q", resources[1].Meta["Type"])
				}
				// 无 status 字段的 Service -> Active（兜底）。
				if resources[2].Status != "Active" {
					t.Errorf("期望无状态 Service Status=Active, 得到 %q", resources[2].Status)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := NewInfrastructureQueryTool(nil)
			tool.runCmd = tt.runCmd
			resources := tool.getK8sResourcesFromKubectl(&InfrastructureQueryParams{
				SystemType: "kubernetes",
				Target:     "prod",
			})
			tt.check(t, resources)
		})
	}
}
