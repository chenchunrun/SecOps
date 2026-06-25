package secops

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// runCmdOverride 构造一个根据命令名分发预置输出的 runCmd 桩函数。
// 每个 binary 对应一组 (stdout, stderr, err)，命中即返回；未命中返回错误。
func runCmdOverride(t *testing.T, responses map[string]struct {
	stdout string
	stderr string
	err    error
},
) func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	t.Helper()
	return func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		if r, ok := responses[name]; ok {
			return []byte(r.stdout), []byte(r.stderr), r.err
		}
		return nil, []byte(name + ": command not found"), errors.New(name + ": not found")
	}
}

// runCmdMulti 用于同一 binary 需要根据子参数返回不同输出的场景（例如 kubectl
// 的 get deployment 与 rollout status 与 get events）。
type cmdExpect struct {
	matchSub string // 参数连接后需包含的子串；空表示默认兜底
	stdout   string
	stderr   string
	err      error
}

func runCmdByArgs(t *testing.T, byName map[string][]cmdExpect) func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	t.Helper()
	return func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		expects, ok := byName[name]
		if !ok {
			return nil, []byte(name + ": command not found"), errors.New(name + ": not found")
		}
		joined := strings.Join(args, " ")
		var fallback *cmdExpect
		for i := range expects {
			e := expects[i]
			if e.matchSub == "" {
				fallback = &expects[i]
				continue
			}
			if strings.Contains(joined, e.matchSub) {
				return []byte(e.stdout), []byte(e.stderr), e.err
			}
		}
		if fallback != nil {
			return []byte(fallback.stdout), []byte(fallback.stderr), fallback.err
		}
		return nil, []byte(name + ": unmatched args"), errors.New(name + ": unmatched args")
	}
}

// ---------- DeploymentStatusTool 基础元信息 ----------

func TestDeploymentStatusTool_元信息(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	if tool.Type() != ToolTypeDeploymentStatus {
		t.Errorf("Type 不匹配: got %v", tool.Type())
	}
	if tool.Name() != "Deployment Status" {
		t.Errorf("Name 不匹配: got %q", tool.Name())
	}
	if tool.Description() == "" {
		t.Error("Description 不应为空")
	}
	caps := tool.RequiredCapabilities()
	if len(caps) != 2 {
		t.Fatalf("RequiredCapabilities 数量: got %d", len(caps))
	}
}

// ---------- ValidateParams ----------

func TestDeploymentStatusTool_ValidateParams_覆盖补全(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)

	tests := []struct {
		name    string
		params  interface{}
		wantErr bool
	}{
		{
			name:    "参数类型错误返回 ErrInvalidParams",
			params:  &struct{}{},
			wantErr: true,
		},
		{
			name:    "空 platform 报错",
			params:  &DeploymentStatusParams{Deployment: "svc"},
			wantErr: true,
		},
		{
			name: "不支持的 platform 报错",
			params: &DeploymentStatusParams{
				Platform:   "aliyun",
				Deployment: "svc",
			},
			wantErr: true,
		},
		{
			name: "空 deployment 报错",
			params: &DeploymentStatusParams{
				Platform: "kubernetes",
			},
			wantErr: true,
		},
		{
			name: "合法 kubernetes 参数通过",
			params: &DeploymentStatusParams{
				Platform:   "kubernetes",
				Deployment: "web-api",
				Namespace:  "prod",
			},
			wantErr: false,
		},
		{
			name: "合法 aws 参数通过",
			params: &DeploymentStatusParams{
				Platform:   "aws",
				Deployment: "web-api",
				Target:     "my-cluster",
			},
			wantErr: false,
		},
		{
			name: "合法 gcp 参数通过",
			params: &DeploymentStatusParams{
				Platform:   "gcp",
				Deployment: "web-api",
				Target:     "us-central1",
			},
			wantErr: false,
		},
		{
			name: "合法 azure 参数通过",
			params: &DeploymentStatusParams{
				Platform:   "azure",
				Deployment: "web-api",
				Target:     "rg-prod",
			},
			wantErr: false,
		},
		{
			name: "远程端口非法报错",
			params: &DeploymentStatusParams{
				Platform:   "kubernetes",
				Deployment: "web-api",
				RemoteHost: "10.0.0.5",
				RemotePort: 70000,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tool.ValidateParams(tt.params)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateParams err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ---------- Execute 参数错误路径 ----------

func TestDeploymentStatusTool_Execute_参数错误(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)

	// 非 DeploymentStatusParams 类型
	if _, err := tool.Execute(&struct{}{}); err == nil {
		t.Error("非合法参数类型应返回错误")
	}

	// 校验失败
	if _, err := tool.Execute(&DeploymentStatusParams{Platform: "unknown", Deployment: "x"}); err == nil {
		t.Error("未知 platform 应返回错误")
	}
}

// ---------- getK8sDeploymentStatusFromKubectl ----------

const k8sDeploymentJSON = `{
  "metadata": {
    "labels": {"app.kubernetes.io/version": "v2.3.1"},
    "annotations": {"deployment.kubernetes.io/revision": "5"}
  },
  "spec": {"replicas": 3, "strategy": {"type": "RollingUpdate"}},
  "status": {
    "replicas": 3,
    "readyReplicas": 3,
    "availableReplicas": 3,
    "updatedReplicas": 3,
    "conditions": [
      {"type": "Available", "status": "True", "reason": "MinimumReplicasAvailable", "message": "ok"},
      {"type": "Progressing", "status": "True", "reason": "NewReplicaSetAvailable", "message": "done"}
    ]
  }
}`

const k8sEventsJSON = `{
  "items": [
    {"type": "Normal", "reason": "ScalingReplicaSet", "message": "scaled up", "lastTimestamp": "2026-06-25 10:00:00Z"},
    {"type": "Warning", "reason": "BackOff", "message": "backoff", "eventTime": ""},
    {"type": " Weird ", "reason": "UnknownReason", "message": "x", "creationTimestamp": "2026-06-25 09:00:00Z"}
  ]
}`

func TestDeploymentStatusTool_K8s从Kubectl实时获取健康状态(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdByArgs(t, map[string][]cmdExpect{
		"kubectl": {
			{matchSub: "get deployment", stdout: k8sDeploymentJSON},
			{matchSub: "rollout status", stdout: "deployment successfully rolled out\n"},
			{matchSub: "get events", stdout: k8sEventsJSON},
		},
	})

	res := tool.getK8sDeploymentStatusFromKubectl(&DeploymentStatusParams{
		Deployment: "web-api",
		Namespace:  "prod",
	})
	if res == nil {
		t.Fatal("期望返回实时结果，got nil")
	}
	if res.Health == nil || res.Health.Status != "healthy" {
		t.Fatalf("期望健康状态 healthy，got %+v", res.Health)
	}
	if res.Version != "v2.3.1" {
		t.Errorf("版本推断错误: got %q", res.Version)
	}
	if res.PreviousVersion != "5" {
		t.Errorf("前序版本（revision）错误: got %q", res.PreviousVersion)
	}
	if res.Health == nil || len(res.Health.Events) != 3 {
		t.Errorf("事件数量错误: got %d", func() int {
			if res.Health == nil {
				return -1
			}
			return len(res.Health.Events)
		}())
	}
	// 第三条事件类型非法应被规范化为 Normal
	if res.Health.Events[2].Type != "Normal" {
		t.Errorf("非法事件类型应规范化为 Normal，got %q", res.Health.Events[2].Type)
	}
	if res.DataSource != "" {
		t.Errorf("FromKubectl 不应设置 DataSource（由上层填充），got %q", res.DataSource)
	}
}

func TestDeploymentStatusTool_K8s降级状态_副本不足(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	degradedJSON := strings.Replace(k8sDeploymentJSON,
		`"availableReplicas": 3`, `"availableReplicas": 1`, 1)
	tool.runCmd = runCmdByArgs(t, map[string][]cmdExpect{
		"kubectl": {
			{matchSub: "get deployment", stdout: degradedJSON},
			{matchSub: "rollout status", stdout: "deployment successfully rolled out\n"},
			{matchSub: "get events", stdout: `{}`},
		},
	})

	res := tool.getK8sDeploymentStatusFromKubectl(&DeploymentStatusParams{
		Deployment: "web-api",
		Namespace:  "prod",
	})
	if res == nil || res.Health == nil || res.Health.Status != "degraded" {
		t.Fatalf("期望 degraded，got %+v", res)
	}
}

func TestDeploymentStatusTool_K8s不健康状态_零可用副本(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	unhealthyJSON := strings.Replace(strings.Replace(k8sDeploymentJSON,
		`"availableReplicas": 3`, `"availableReplicas": 0`, 1),
		`"readyReplicas": 3`, `"readyReplicas": 0`, 1)
	tool.runCmd = runCmdByArgs(t, map[string][]cmdExpect{
		"kubectl": {
			{matchSub: "get deployment", stdout: unhealthyJSON},
			{matchSub: "rollout status", stdout: "deployment successfully rolled out\n"},
			{matchSub: "get events", stdout: `{}`},
		},
	})

	res := tool.getK8sDeploymentStatusFromKubectl(&DeploymentStatusParams{
		Deployment: "web-api",
		Namespace:  "prod",
	})
	if res == nil || res.Health == nil || res.Health.Status != "unhealthy" {
		t.Fatalf("期望 unhealthy，got %+v", res)
	}
}

func TestDeploymentStatusTool_K8sCanary策略触发金丝雀分析(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	canaryJSON := strings.Replace(k8sDeploymentJSON,
		`"RollingUpdate"`, `"Canary"`, 1)
	tool.runCmd = runCmdByArgs(t, map[string][]cmdExpect{
		"kubectl": {
			{matchSub: "get deployment", stdout: canaryJSON},
			{matchSub: "rollout status", stdout: "deployment successfully rolled out\n"},
			{matchSub: "get events", stdout: `{}`},
		},
	})

	res := tool.getK8sDeploymentStatusFromKubectl(&DeploymentStatusParams{
		Deployment: "web-api",
		Namespace:  "prod",
	})
	if res == nil {
		t.Fatal("期望非空结果")
	}
	if res.Rollout == nil || res.Rollout.Strategy != "Canary" {
		t.Fatalf("期望 Canary 策略，got %+v", res.Rollout)
	}
	if res.CanaryAnalysis == nil {
		t.Fatal("Canary 策略应触发金丝雀分析")
	}
}

func TestDeploymentStatusTool_K8s默认命名空间回退(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	var seenArgs string
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		seenArgs = strings.Join(args, " ")
		if strings.Contains(seenArgs, "get deployment") {
			return []byte(k8sDeploymentJSON), nil, nil
		}
		if strings.Contains(seenArgs, "rollout status") {
			return []byte("rolled out\n"), nil, nil
		}
		return []byte(`{}`), nil, nil
	}

	res := tool.getK8sDeploymentStatusFromKubectl(&DeploymentStatusParams{
		Deployment: "web-api",
	})
	if res == nil {
		t.Fatal("期望非空结果")
	}
	if res.Namespace != "default" {
		t.Errorf("空命名空间应回退到 default，got %q", res.Namespace)
	}
	if !strings.Contains(seenArgs, "-n default") {
		t.Errorf("命令应使用 default 命名空间，got %q", seenArgs)
	}
}

func TestDeploymentStatusTool_K8s命令失败返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"kubectl": {err: errors.New("kubectl: connection refused")},
	})

	res := tool.getK8sDeploymentStatusFromKubectl(&DeploymentStatusParams{
		Deployment: "web-api",
		Namespace:  "prod",
	})
	if res != nil {
		t.Fatalf("命令失败应返回 nil，got %+v", res)
	}
}

func TestDeploymentStatusTool_K8s空输出返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"kubectl": {stdout: ""},
	})

	res := tool.getK8sDeploymentStatusFromKubectl(&DeploymentStatusParams{
		Deployment: "web-api",
		Namespace:  "prod",
	})
	if res != nil {
		t.Fatalf("空输出应返回 nil，got %+v", res)
	}
}

func TestDeploymentStatusTool_K8s非法JSON返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"kubectl": {stdout: "not-json{"},
	})

	res := tool.getK8sDeploymentStatusFromKubectl(&DeploymentStatusParams{
		Deployment: "web-api",
		Namespace:  "prod",
	})
	if res != nil {
		t.Fatalf("非法 JSON 应返回 nil，got %+v", res)
	}
}

// ---------- getK8sDeploymentStatus (上层：实时优先，否则回退样例) ----------

func TestDeploymentStatusTool_K8s回退样例(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	// runCmd 不命中 kubectl → commandOutput 报错 → 返回 nil → 回退样例
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, []byte("not found"), errors.New("missing")
	}

	res := tool.getK8sDeploymentStatus(&DeploymentStatusParams{
		Deployment: "web-api",
		Namespace:  "prod",
	})
	if res == nil {
		t.Fatal("期望回退样例结果")
	}
	if res.DataSource != "fallback_sample" {
		t.Errorf("期望 fallback_sample，got %q", res.DataSource)
	}
	if res.FallbackReason == "" {
		t.Error("回退原因不应为空")
	}
	if res.Health == nil || res.Health.Status != "healthy" {
		t.Errorf("回退样例应为 healthy，got %+v", res.Health)
	}
}

func TestDeploymentStatusTool_K8sCanaryStatus包装(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, []byte("missing"), errors.New("missing")
	}

	res := tool.getK8sCanaryStatus(&DeploymentStatusParams{
		Deployment: "web-api",
		Namespace:  "prod",
	})
	if res == nil {
		t.Fatal("期望非空结果")
	}
	if res.Rollout == nil || !res.Rollout.InProgress || res.Rollout.Strategy != "Canary" {
		t.Fatalf("期望 Canary 进行中，got %+v", res.Rollout)
	}
	if res.CanaryAnalysis == nil || res.CanaryAnalysis.MetricsChecked != 5 {
		t.Errorf("期望金丝雀分析 5 个指标，got %+v", res.CanaryAnalysis)
	}
}

// ---------- performCheck 分发 ----------

func TestDeploymentStatusTool_performCheck分发(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, []byte("missing"), errors.New("missing")
	}

	for _, platform := range []string{"kubernetes", "aws", "gcp", "azure"} {
		res := tool.performCheck(&DeploymentStatusParams{
			Platform:   platform,
			Deployment: "web-api",
			Namespace:  "prod",
		})
		if res == nil {
			t.Fatalf("platform %s 期望非空结果", platform)
		}
		if res.Health == nil {
			t.Fatalf("platform %s 期望非空健康状态", platform)
		}
		if res.Health.Status == "" {
			t.Fatalf("platform %s 健康状态不应为空", platform)
		}
	}
}

// ---------- getAWSDeploymentStatusFromCLI ----------

const awsECSJSON = `{
  "services": [
    {
      "desiredCount": 4,
      "runningCount": 4,
      "deployments": [{"status": "PRIMARY", "rolloutState": "COMPLETED"}]
    }
  ]
}`

func TestDeploymentStatusTool_AWS从CLI实时获取(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"aws": {stdout: awsECSJSON},
	})

	res := tool.getAWSDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "prod-cluster",
	})
	if res == nil {
		t.Fatal("期望实时结果")
	}
	if res.Health == nil || res.Health.Status != "healthy" {
		t.Fatalf("期望 healthy，got %+v", res.Health)
	}
	if res.Replicas.Desired != 4 || res.Replicas.Available != 4 {
		t.Errorf("副本数错误: %+v", res.Replicas)
	}
	if res.DataSource != "live" {
		t.Errorf("期望 live，got %q", res.DataSource)
	}
}

func TestDeploymentStatusTool_AWS降级_运行数少于期望(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	degradedJSON := strings.Replace(awsECSJSON,
		`"runningCount": 4`, `"runningCount": 2`, 1)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"aws": {stdout: degradedJSON},
	})

	res := tool.getAWSDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "prod-cluster",
	})
	if res == nil || res.Health == nil || res.Health.Status != "degraded" {
		t.Fatalf("期望 degraded，got %+v", res)
	}
}

func TestDeploymentStatusTool_AWS滚动发布进行中(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	inProgressJSON := strings.Replace(awsECSJSON,
		`"rolloutState": "COMPLETED"`, `"rolloutState": "IN_PROGRESS"`, 1)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"aws": {stdout: inProgressJSON},
	})

	res := tool.getAWSDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "prod-cluster",
	})
	if res == nil {
		t.Fatal("期望非空结果")
	}
	if res.Rollout == nil || !res.Rollout.InProgress {
		t.Fatalf("期望滚动发布进行中，got %+v", res.Rollout)
	}
}

func TestDeploymentStatusTool_AWS发布失败标记为不健康(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	failedJSON := strings.Replace(awsECSJSON,
		`"rolloutState": "COMPLETED"`, `"rolloutState": "FAILED"`, 1)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"aws": {stdout: failedJSON},
	})

	res := tool.getAWSDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "prod-cluster",
	})
	if res == nil || res.Health == nil || res.Health.Status != "unhealthy" {
		t.Fatalf("期望 unhealthy，got %+v", res)
	}
}

func TestDeploymentStatusTool_AWS默认集群名(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	var seenArgs string
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		seenArgs = strings.Join(args, " ")
		return []byte(awsECSJSON), nil, nil
	}

	res := tool.getAWSDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
	})
	if res == nil {
		t.Fatal("期望非空结果")
	}
	if !strings.Contains(seenArgs, "--cluster default") {
		t.Errorf("空 target 应回退 default，got %q", seenArgs)
	}
}

func TestDeploymentStatusTool_AWS命令失败返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"aws": {err: errors.New("aws cli error")},
	})

	res := tool.getAWSDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
	})
	if res != nil {
		t.Fatalf("命令失败应返回 nil，got %+v", res)
	}
}

func TestDeploymentStatusTool_AWS无服务条目返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"aws": {stdout: `{"services": []}`},
	})

	res := tool.getAWSDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
	})
	if res != nil {
		t.Fatalf("空 services 应返回 nil，got %+v", res)
	}
}

func TestDeploymentStatusTool_AWS非法JSON返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"aws": {stdout: "not-json"},
	})

	res := tool.getAWSDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
	})
	if res != nil {
		t.Fatalf("非法 JSON 应返回 nil，got %+v", res)
	}
}

func TestDeploymentStatusTool_AWS空输出返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"aws": {stdout: ""},
	})

	res := tool.getAWSDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
	})
	if res != nil {
		t.Fatalf("空输出应返回 nil，got %+v", res)
	}
}

func TestDeploymentStatusTool_AWS回退样例(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, nil, errors.New("missing")
	}

	res := tool.getAWSDeploymentStatus(&DeploymentStatusParams{Deployment: "web-api"})
	if res == nil || res.DataSource != "fallback_sample" {
		t.Fatalf("期望回退样例，got %+v", res)
	}
}

// ---------- getGCPDeploymentStatusFromCLI ----------

const gcpCloudRunJSON = `{
  "status": {
    "url": "https://web-api-abc.a.run.app",
    "traffic": [{"percent": 100}],
    "conditions": [
      {"type": "Ready", "status": "True"},
      {"type": "ConfigurationsReady", "status": "True"}
    ]
  },
  "spec": {
    "template": {"metadata": {"name": "web-api-00012-hey"}}
  }
}`

func TestDeploymentStatusTool_GCP从CLI实时获取(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"gcloud": {stdout: gcpCloudRunJSON},
	})

	res := tool.getGCPDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "us-central1",
	})
	if res == nil {
		t.Fatal("期望实时结果")
	}
	if res.Health == nil || res.Health.Status != "healthy" {
		t.Fatalf("期望 healthy，got %+v", res.Health)
	}
	if res.Version != "web-api-00012-hey" {
		t.Errorf("版本（revision name）错误: got %q", res.Version)
	}
	if res.Replicas == nil || res.Replicas.Desired != 1 {
		t.Errorf("期望副本 1，got %+v", res.Replicas)
	}
	if res.Health.Conditions[0].Status != "True" {
		t.Errorf("URL 条件应为 True，got %+v", res.Health.Conditions[0])
	}
}

func TestDeploymentStatusTool_GCP就绪False标记为降级(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	notReadyJSON := strings.Replace(gcpCloudRunJSON,
		`{"type": "Ready", "status": "True"}`, `{"type": "Ready", "status": "False"}`, 1)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"gcloud": {stdout: notReadyJSON},
	})

	res := tool.getGCPDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
	})
	if res == nil || res.Health == nil || res.Health.Status != "degraded" {
		t.Fatalf("期望 degraded，got %+v", res)
	}
}

func TestDeploymentStatusTool_GCP无就绪条件标记为未知(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	noCondJSON := `{
  "status": {"url": "", "traffic": [{"percent": 100}], "conditions": []},
  "spec": {"template": {"metadata": {"name": ""}}}
}`
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"gcloud": {stdout: noCondJSON},
	})

	res := tool.getGCPDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
	})
	if res == nil {
		t.Fatal("期望非空结果")
	}
	if res.Health == nil || res.Health.Status != "unknown" {
		t.Fatalf("期望 unknown，got %+v", res.Health)
	}
	if res.Version != "unknown" {
		t.Errorf("空 revision name 应回退 unknown，got %q", res.Version)
	}
}

func TestDeploymentStatusTool_GCP无流量配置零副本(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	noTrafficJSON := `{
  "status": {
    "url": "https://web-api.a.run.app",
    "traffic": [],
    "conditions": [{"type": "Ready", "status": "True"}]
  },
  "spec": {"template": {"metadata": {"name": "rev-1"}}}
}`
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"gcloud": {stdout: noTrafficJSON},
	})

	res := tool.getGCPDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
	})
	if res == nil {
		t.Fatal("期望非空结果")
	}
	if res.Replicas == nil || res.Replicas.Desired != 0 {
		t.Errorf("无流量应得 0 副本，got %+v", res.Replicas)
	}
}

func TestDeploymentStatusTool_GCP命令失败返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"gcloud": {err: errors.New("gcloud auth error")},
	})

	res := tool.getGCPDeploymentStatusFromCLI(&DeploymentStatusParams{Deployment: "web-api"})
	if res != nil {
		t.Fatalf("命令失败应返回 nil，got %+v", res)
	}
}

func TestDeploymentStatusTool_GCP非法JSON返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"gcloud": {stdout: "garbage"},
	})

	res := tool.getGCPDeploymentStatusFromCLI(&DeploymentStatusParams{Deployment: "web-api"})
	if res != nil {
		t.Fatalf("非法 JSON 应返回 nil，got %+v", res)
	}
}

func TestDeploymentStatusTool_GCP回退样例(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, nil, errors.New("missing")
	}

	res := tool.getGCPDDeploymentStatus(&DeploymentStatusParams{Deployment: "web-api"})
	if res == nil || res.DataSource != "fallback_sample" {
		t.Fatalf("期望回退样例，got %+v", res)
	}
}

// ---------- getAzureDeploymentStatusFromCLI ----------

const azureWebappJSON = `{
  "state": "Running",
  "location": "eastasia",
  "defaultHostName": "web-api.azurewebsites.net"
}`

func TestDeploymentStatusTool_Azure从CLI实时获取(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"az": {stdout: azureWebappJSON},
	})

	res := tool.getAzureDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "rg-prod",
	})
	if res == nil {
		t.Fatal("期望实时结果")
	}
	if res.Health == nil || res.Health.Status != "healthy" {
		t.Fatalf("期望 healthy，got %+v", res.Health)
	}
	if len(res.Health.Conditions) != 2 {
		t.Errorf("期望 2 个条件，got %d", len(res.Health.Conditions))
	}
	if res.Health.Conditions[0].Message != "web-api.azurewebsites.net" {
		t.Errorf("HostName 条件消息错误: got %+v", res.Health.Conditions[0])
	}
}

func TestDeploymentStatusTool_Azure非运行状态标记为降级(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	stoppedJSON := strings.Replace(azureWebappJSON,
		`"Running"`, `"Stopped"`, 1)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"az": {stdout: stoppedJSON},
	})

	res := tool.getAzureDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "rg-prod",
	})
	if res == nil || res.Health == nil || res.Health.Status != "degraded" {
		t.Fatalf("期望 degraded，got %+v", res)
	}
}

func TestDeploymentStatusTool_Azure空资源组返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"az": {stdout: azureWebappJSON},
	})

	res := tool.getAzureDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "  ",
	})
	if res != nil {
		t.Fatalf("空资源组应直接返回 nil（不调用 CLI），got %+v", res)
	}
}

func TestDeploymentStatusTool_Azure命令失败返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"az": {err: errors.New("az login required")},
	})

	res := tool.getAzureDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "rg-prod",
	})
	if res != nil {
		t.Fatalf("命令失败应返回 nil，got %+v", res)
	}
}

func TestDeploymentStatusTool_Azure非法JSON返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"az": {stdout: "{broken"},
	})

	res := tool.getAzureDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "rg-prod",
	})
	if res != nil {
		t.Fatalf("非法 JSON 应返回 nil，got %+v", res)
	}
}

func TestDeploymentStatusTool_Azure回退样例(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		return nil, nil, errors.New("missing")
	}

	res := tool.getAzureDeploymentStatus(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "rg-prod",
	})
	if res == nil || res.DataSource != "fallback_sample" {
		t.Fatalf("期望回退样例，got %+v", res)
	}
}

// ---------- getK8sRolloutInfo: 等待中/进行中 与 错误兜底 ----------

func TestDeploymentStatusTool_K8s滚动发布等待中(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdByArgs(t, map[string][]cmdExpect{
		"kubectl": {
			{matchSub: "rollout status", stdout: "", stderr: "Waiting for rollout to finish: 2 of 3 updated replicas...\n"},
		},
	})

	rollout := tool.getK8sRolloutInfo(&DeploymentStatusParams{Deployment: "web-api"}, "prod", "RollingUpdate")
	if rollout == nil {
		t.Fatal("期望非空 rollout")
	}
	if !rollout.InProgress {
		t.Error("等待中应标记 InProgress=true")
	}
	if !strings.Contains(rollout.Progress, "Waiting") {
		t.Errorf("进度信息应包含等待说明，got %q", rollout.Progress)
	}
}

func TestDeploymentStatusTool_K8s滚动发布命令错误兜底(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdByArgs(t, map[string][]cmdExpect{
		"kubectl": {
			{matchSub: "rollout status", stdout: "", stderr: "", err: errors.New("boom")},
		},
	})

	rollout := tool.getK8sRolloutInfo(&DeploymentStatusParams{Deployment: "web-api"}, "prod", "RollingUpdate")
	if rollout == nil || !rollout.InProgress {
		t.Fatalf("命令错误应标记 InProgress=true，got %+v", rollout)
	}
	if rollout.Progress != "Rollout status unavailable" {
		t.Errorf("空消息应回退默认文案，got %q", rollout.Progress)
	}
}

func TestDeploymentStatusTool_K8s滚动发布完成(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdByArgs(t, map[string][]cmdExpect{
		"kubectl": {
			{matchSub: "rollout status", stdout: "deployment successfully rolled out\n"},
		},
	})

	rollout := tool.getK8sRolloutInfo(&DeploymentStatusParams{Deployment: "web-api"}, "prod", "RollingUpdate")
	if rollout == nil {
		t.Fatal("期望非空 rollout")
	}
	if rollout.InProgress {
		t.Error("已完成发布不应标记 InProgress")
	}
	if !strings.Contains(rollout.Progress, "rolled out") {
		t.Errorf("进度信息错误: got %q", rollout.Progress)
	}
}

// ---------- getK8sRecentEvents: 错误兜底 ----------

func TestDeploymentStatusTool_K8s事件获取失败返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdByArgs(t, map[string][]cmdExpect{
		"kubectl": {
			{matchSub: "get events", stdout: "", stderr: "err", err: errors.New("no events")},
		},
	})

	events := tool.getK8sRecentEvents(&DeploymentStatusParams{Deployment: "web-api"}, "prod")
	if events != nil {
		t.Fatalf("命令失败应返回 nil，got %+v", events)
	}
}

func TestDeploymentStatusTool_K8s事件非法JSON返回nil(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdByArgs(t, map[string][]cmdExpect{
		"kubectl": {
			{matchSub: "get events", stdout: "nope"},
		},
	})

	events := tool.getK8sRecentEvents(&DeploymentStatusParams{Deployment: "web-api"}, "prod")
	if events != nil {
		t.Fatalf("非法 JSON 应返回 nil，got %+v", events)
	}
}

func TestDeploymentStatusTool_K8s事件空类型与时间戳回退(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	// 全部字段缺失，触发类型/时间戳默认值
	tool.runCmd = runCmdByArgs(t, map[string][]cmdExpect{
		"kubectl": {
			{matchSub: "get events", stdout: `{"items":[{"reason":"R","message":"M"}]}`},
		},
	})

	events := tool.getK8sRecentEvents(&DeploymentStatusParams{Deployment: "web-api"}, "prod")
	if len(events) != 1 {
		t.Fatalf("期望 1 条事件，got %d", len(events))
	}
	if events[0].Type != "Normal" {
		t.Errorf("空类型应回退 Normal，got %q", events[0].Type)
	}
	if events[0].Timestamp == "" {
		t.Error("空时间戳应回退当前时间，got 空")
	}
}

// ---------- 纯函数：inferDeploymentVersions / normalizedStrategy / boolToStatus / emptyAs / shellQuoteDeployment ----------

func TestDeploymentStatusTool_版本推断(t *testing.T) {
	tests := []struct {
		name        string
		labels      map[string]string
		annotations map[string]string
		wantVer     string
		wantPrev    string
	}{
		{
			name:        "label 优先 app.kubernetes.io/version",
			labels:      map[string]string{"app.kubernetes.io/version": "v1.2.3"},
			annotations: map[string]string{"version": "v9"},
			wantVer:     "v1.2.3",
			wantPrev:    "",
		},
		{
			name:    "回退到 version label",
			labels:  map[string]string{"version": "v2"},
			wantVer: "v2",
		},
		{
			name:    "回退到 image.tag label",
			labels:  map[string]string{"image.tag": "v3"},
			wantVer: "v3",
		},
		{
			name:        "回退到 helm.sh/chart annotation",
			labels:      map[string]string{},
			annotations: map[string]string{"helm.sh/chart": "chart-0.1"},
			wantVer:     "chart-0.1",
		},
		{
			name:        "revision 注解作为前序版本",
			labels:      map[string]string{"app.kubernetes.io/version": "v1"},
			annotations: map[string]string{"deployment.kubernetes.io/revision": "7"},
			wantVer:     "v1",
			wantPrev:    "7",
		},
		{
			name:    "全部缺失回退 unknown",
			wantVer: "unknown",
		},
		{
			name:    "空白值视为缺失",
			labels:  map[string]string{"app.kubernetes.io/version": "  "},
			wantVer: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, p := inferDeploymentVersions(tt.labels, tt.annotations)
			if v != tt.wantVer {
				t.Errorf("version = %q, want %q", v, tt.wantVer)
			}
			if p != tt.wantPrev {
				t.Errorf("previous = %q, want %q", p, tt.wantPrev)
			}
		})
	}
}

func TestDeploymentStatusTool_策略归一化(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"rollingupdate", "RollingUpdate"},
		{"RollingUpdate", "RollingUpdate"},
		{"bluegreen", "BlueGreen"},
		{"blue_green", "BlueGreen"},
		{"canary", "Canary"},
		{"Canary", "Canary"},
		{"", "RollingUpdate"},
		{"  ", "RollingUpdate"},
		{"Recreate", "Recreate"}, // 未识别原样保留
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalizedStrategy(tt.in); got != tt.want {
				t.Errorf("normalizedStrategy(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDeploymentStatusTool_boolToStatus(t *testing.T) {
	if got := boolToStatus(true); got != "True" {
		t.Errorf("boolToStatus(true) = %q, want True", got)
	}
	if got := boolToStatus(false); got != "False" {
		t.Errorf("boolToStatus(false) = %q, want False", got)
	}
}

func TestDeploymentStatusTool_emptyAs(t *testing.T) {
	if got := emptyAs("x", "fallback"); got != "x" {
		t.Errorf("emptyAs 非空应原样返回，got %q", got)
	}
	if got := emptyAs("  ", "fallback"); got != "fallback" {
		t.Errorf("emptyAs 空白应回退，got %q", got)
	}
}

func TestDeploymentStatusTool_shellQuoteDeployment(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "''"},
		{"simple", "'simple'"},
		{"it's", "'it'\"'\"'s'"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := shellQuoteDeployment(tt.in); got != tt.want {
				t.Errorf("shellQuoteDeployment(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ---------- estimateCanaryAnalysis: 三种健康状态推荐 ----------

func TestDeploymentStatusTool_金丝雀推荐分健康状态(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tests := []struct {
		name    string
		health  string
		wantRec string
	}{
		{"健康->promote", "healthy", "promote"},
		{"降级->hold", "degraded", "hold"},
		{"不健康->rollback", "unhealthy", "rollback"},
		{"空健康->promote", "", "promote"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &DeploymentStatusResult{Health: &DeploymentHealth{Status: tt.health}}
			ca := tool.estimateCanaryAnalysis(res)
			if ca == nil {
				t.Fatal("期望非空金丝雀分析")
			}
			if ca.Recommendation != tt.wantRec {
				t.Errorf("推荐 = %q, want %q", ca.Recommendation, tt.wantRec)
			}
		})
	}
}

// ---------- buildDeploymentSSHArgs: 远程 SSH 参数拼装 ----------

func TestDeploymentStatusTool_SSH参数拼装(t *testing.T) {
	tests := []struct {
		name     string
		params   *DeploymentStatusParams
		wantErr  bool
		wantSubs []string
	}{
		{
			name: "完整远程参数",
			params: &DeploymentStatusParams{
				RemoteHost: "10.0.0.5", RemoteUser: "ops", RemotePort: 2222,
				RemoteKeyPath: "/tmp/key", RemoteProxyJump: "bastion",
			},
			wantSubs: []string{"ops@10.0.0.5", "-p 2222", "-i", "/tmp/key", "-J", "bastion"},
		},
		{
			name:     "仅 host 无 user",
			params:   &DeploymentStatusParams{RemoteHost: "10.0.0.5"},
			wantSubs: []string{"10.0.0.5"},
		},
		{
			name:    "nil params 报错",
			params:  nil,
			wantErr: true,
		},
		{
			name:    "空 host 报错",
			params:  &DeploymentStatusParams{RemoteUser: "ops"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, err := buildDeploymentSSHArgs(tt.params, "kubectl", "get", "pods")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			joined := strings.Join(args, " ")
			for _, sub := range tt.wantSubs {
				if !strings.Contains(joined, sub) {
					t.Errorf("期望包含 %q，got %q", sub, joined)
				}
			}
			// 应包含远程命令 shell 包装
			if !strings.Contains(joined, "sh -lc") {
				t.Errorf("期望包含 sh -lc 包装，got %q", joined)
			}
		})
	}
}

// ---------- commandRun 远程 SSH 分支 ----------

func TestDeploymentStatusTool_远程执行走SSH通道(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	var gotName string
	var gotArgs []string
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return []byte(awsECSJSON), nil, nil
	}

	res := tool.getAWSDeploymentStatusFromCLI(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "cluster",
		RemoteHost: "10.0.0.5",
		RemoteUser: "ops",
	})
	if res == nil {
		t.Fatal("期望实时结果")
	}
	if gotName != "ssh" {
		t.Fatalf("期望命令名 ssh，got %q", gotName)
	}
	joined := strings.Join(gotArgs, " ")
	if !strings.Contains(joined, "ops@10.0.0.5") {
		t.Errorf("SSH 参数应包含目标主机，got %q", joined)
	}
}

// ---------- runCmd 为 nil 时回退默认实现 ----------

func TestDeploymentStatusTool_runCmdNil回退默认实现(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = nil // 触发 commandRun 内部的 nil 回退

	// 不存在的 binary 应返回错误而非 panic
	stdout, _, err := tool.commandRun(&DeploymentStatusParams{Deployment: "x"}, "this-binary-does-not-exist-xyz", "arg")
	if err == nil {
		t.Error("期望不存在的 binary 返回错误")
	}
	if stdout != nil {
		t.Errorf("期望空 stdout，got %q", stdout)
	}
}

// ---------- commandOutput 错误信息兜底 ----------

func TestDeploymentStatusTool_commandOutput错误信息(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
		// stderr 为空，触发 err.Error() 兜底
		return nil, nil, errors.New("some-failure")
	}

	out, err := tool.commandOutput(&DeploymentStatusParams{}, "aws", "ecs", "x")
	if err == nil {
		t.Fatal("期望错误")
	}
	if !strings.Contains(err.Error(), "aws command failed") {
		t.Errorf("错误应包含命令名前缀，got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "some-failure") {
		t.Errorf("错误应包含底层信息，got %q", err.Error())
	}
	if out != nil {
		t.Errorf("期望空输出，got %q", out)
	}
}

// ---------- 上层包装函数的实时路径（live 分支，DataSource=live） ----------

func TestDeploymentStatusTool_K8s上层走实时路径(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdByArgs(t, map[string][]cmdExpect{
		"kubectl": {
			{matchSub: "get deployment", stdout: k8sDeploymentJSON},
			{matchSub: "rollout status", stdout: "deployment successfully rolled out\n"},
			{matchSub: "get events", stdout: k8sEventsJSON},
		},
	})

	res := tool.getK8sDeploymentStatus(&DeploymentStatusParams{
		Deployment: "web-api",
		Namespace:  "prod",
	})
	if res == nil {
		t.Fatal("期望非空结果")
	}
	if res.DataSource != "live" {
		t.Errorf("期望走实时路径 DataSource=live，got %q", res.DataSource)
	}
}

func TestDeploymentStatusTool_AWS上层走实时路径(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"aws": {stdout: awsECSJSON},
	})

	res := tool.getAWSDeploymentStatus(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "cluster",
	})
	if res == nil || res.DataSource != "live" {
		t.Fatalf("期望走实时路径 DataSource=live，got %+v", res)
	}
}

func TestDeploymentStatusTool_GCP上层走实时路径(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"gcloud": {stdout: gcpCloudRunJSON},
	})

	res := tool.getGCPDDeploymentStatus(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "us-central1",
	})
	if res == nil || res.DataSource != "live" {
		t.Fatalf("期望走实时路径 DataSource=live，got %+v", res)
	}
}

func TestDeploymentStatusTool_Azure上层走实时路径(t *testing.T) {
	tool := NewDeploymentStatusTool(nil)
	tool.runCmd = runCmdOverride(t, map[string]struct {
		stdout string
		stderr string
		err    error
	}{
		"az": {stdout: azureWebappJSON},
	})

	res := tool.getAzureDeploymentStatus(&DeploymentStatusParams{
		Deployment: "web-api",
		Target:     "rg-prod",
	})
	if res == nil || res.DataSource != "live" {
		t.Fatalf("期望走实时路径 DataSource=live，got %+v", res)
	}
}
