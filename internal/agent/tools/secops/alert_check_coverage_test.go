package secops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAlertCheckTool_resolveEndpointAndToken 覆盖 resolveEndpoint / resolveToken 的参数优先与环境变量回退分支。
// 注意: 本测试使用 t.Setenv 修改进程级环境变量, 不能并行。
func TestAlertCheckTool_resolveEndpointAndToken(t *testing.T) {
	t.Run("参数优先于环境变量", func(t *testing.T) {
		t.Setenv("SECOPS_PROMETHEUS_ENDPOINT", "http://from-env:9090/")
		t.Setenv("SECOPS_PROMETHEUS_TOKEN", "env-token")

		tool := NewAlertCheckTool(nil)
		params := &AlertCheckParams{
			Endpoint: "http://from-param:9090/",
			APIToken: "param-token",
		}

		if got := tool.resolveEndpoint(params, "SECOPS_PROMETHEUS_ENDPOINT"); got != "http://from-param:9090" {
			t.Fatalf("resolveEndpoint 应优先使用参数并去除尾部斜杠, got %q", got)
		}
		if got := tool.resolveToken(params, "SECOPS_PROMETHEUS_TOKEN"); got != "param-token" {
			t.Fatalf("resolveToken 应优先使用参数, got %q", got)
		}
	})

	t.Run("空白参数回退到环境变量", func(t *testing.T) {
		t.Setenv("SECOPS_GRAFANA_ENDPOINT", "http://grafana-env:3000/")
		t.Setenv("SECOPS_GRAFANA_TOKEN", "grafana-env-token")

		tool := NewAlertCheckTool(nil)
		params := &AlertCheckParams{}

		if got := tool.resolveEndpoint(params, "SECOPS_GRAFANA_ENDPOINT"); got != "http://grafana-env:3000" {
			t.Fatalf("resolveEndpoint 应回退到环境变量, got %q", got)
		}
		if got := tool.resolveToken(params, "SECOPS_GRAFANA_TOKEN"); got != "grafana-env-token" {
			t.Fatalf("resolveToken 应回退到环境变量, got %q", got)
		}
	})

	t.Run("参数和环境变量均为空返回空", func(t *testing.T) {
		t.Setenv("SECOPS_PAGERDUTY_ENDPOINT", "   ")
		t.Setenv("SECOPS_PAGERDUTY_TOKEN", "   ")

		tool := NewAlertCheckTool(nil)
		params := &AlertCheckParams{Endpoint: "   ", APIToken: "   "}

		if got := tool.resolveEndpoint(params, "SECOPS_PAGERDUTY_ENDPOINT"); got != "" {
			t.Fatalf("resolveEndpoint 应返回空, got %q", got)
		}
		if got := tool.resolveToken(params, "SECOPS_PAGERDUTY_TOKEN"); got != "" {
			t.Fatalf("resolveToken 应返回空, got %q", got)
		}
	})
}

// TestAlertCheckTool_queryPrometheusAlerts 覆盖 queryPrometheusAlerts 的成功、空端点、非 2xx 与坏 JSON 分支。
func TestAlertCheckTool_queryPrometheusAlerts(t *testing.T) {
	t.Parallel()

	promPayload := `{
		"status": "success",
		"data": {
			"alerts": [
				{
					"labels": {"alertname": "HighCPU", "severity": "critical", "job": "api"},
					"annotations": {"summary": "CPU high", "description": "cpu above 90%"},
					"state": "firing",
					"activeAt": "2026-06-25T08:00:00Z"
				},
				{
					"labels": {"severity": "warning"},
					"annotations": {"description": "no alertname set"},
					"state": "resolved",
					"activeAt": "2026-06-25T07:00:00Z"
				}
			]
		}
	}`

	cases := []struct {
		name      string
		handler   http.HandlerFunc
		endpoint  string
		wantCount int
		wantName  string
	}{
		{
			name: "成功解析 Prometheus 告警",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/alerts" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(promPayload))
			},
			wantCount: 2,
			wantName:  "HighCPU",
		},
		{
			name: "服务端返回 500 时无告警",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantCount: 0,
		},
		{
			name: "返回非法 JSON 时无告警",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{not-json`))
			},
			wantCount: 0,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewServer(tc.handler)
			defer ts.Close()

			tool := NewAlertCheckTool(nil)
			params := &AlertCheckParams{
				System:   "prometheus",
				Endpoint: ts.URL,
			}

			alerts := tool.queryPrometheusAlerts(params)
			if len(alerts) != tc.wantCount {
				t.Fatalf("expected %d alerts, got %d", tc.wantCount, len(alerts))
			}
			if tc.wantName != "" && alerts[0].Name != tc.wantName {
				t.Fatalf("expected first alert name %q, got %q", tc.wantName, alerts[0].Name)
			}
			if tc.wantName != "" {
				if alerts[0].Status != "firing" || alerts[0].Severity != "critical" {
					t.Fatalf("unexpected first alert: %+v", alerts[0])
				}
			}
		})
	}

	t.Run("非法 URL 请求构造失败返回 nil", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		// http.NewRequestWithContext 在 URL 以 "://" 这种无法解析的形式时返回错误。
		params := &AlertCheckParams{
			System:   "prometheus",
			Endpoint: "ht!tp://invalid url with space",
		}
		alerts := tool.queryPrometheusAlerts(params)
		if alerts != nil {
			t.Fatalf("expected nil alerts on bad URL, got %v", alerts)
		}
	})
}

// TestAlertCheckTool_queryPrometheusAlerts_EmptyEndpoint 覆盖端点为空时提前返回 nil。
// 使用 t.Setenv, 不可并行。
func TestAlertCheckTool_queryPrometheusAlerts_EmptyEndpoint(t *testing.T) {
	t.Setenv("SECOPS_PROMETHEUS_ENDPOINT", "")
	tool := NewAlertCheckTool(nil)
	alerts := tool.queryPrometheusAlerts(&AlertCheckParams{System: "prometheus"})
	if alerts != nil {
		t.Fatalf("expected nil alerts for empty endpoint, got %v", alerts)
	}
}

// TestAlertCheckTool_queryGrafanaAlerts 覆盖 queryGrafanaAlerts 的 v2 端点、回退端点、空端点与坏 JSON 分支。
func TestAlertCheckTool_queryGrafanaAlerts(t *testing.T) {
	t.Parallel()

	v2Payload := `[
		{
			"labels": {"alertname": "DBPoolExhausted", "severity": "critical"},
			"annotations": {"summary": "db pool at 95%"},
			"status": {"state": "alerting"},
			"startsAt": "2026-06-25T08:00:00Z"
		},
		{
			"labels": {"severity": "warning"},
			"annotations": {"description": "no name"},
			"status": {"state": "resolved"},
			"startsAt": "2026-06-25T07:00:00Z"
		}
	]`

	t.Run("v2 端点返回告警", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer gtoken" {
				t.Errorf("expected bearer token header, got %q", r.Header.Get("Authorization"))
			}
			if r.URL.Path == "/api/alertmanager/grafana/api/v2/alerts" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(v2Payload))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()

		tool := NewAlertCheckTool(nil)
		alerts := tool.queryGrafanaAlerts(&AlertCheckParams{
			System:   "grafana",
			Endpoint: ts.URL,
			APIToken: "gtoken",
		})
		if len(alerts) != 2 {
			t.Fatalf("expected 2 alerts, got %d", len(alerts))
		}
		if alerts[0].Name != "DBPoolExhausted" {
			t.Fatalf("expected first alert DBPoolExhausted, got %q", alerts[0].Name)
		}
		if alerts[0].Status != "firing" || alerts[0].Severity != "critical" {
			t.Fatalf("unexpected first alert: %+v", alerts[0])
		}
	})

	t.Run("v2 端点 404 时回退到 /api/alerts", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/alertmanager/grafana/api/v2/alerts" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.URL.Path == "/api/alerts" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(v2Payload))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()

		tool := NewAlertCheckTool(nil)
		alerts := tool.queryGrafanaAlerts(&AlertCheckParams{
			System:   "grafana",
			Endpoint: ts.URL,
		})
		if len(alerts) != 2 {
			t.Fatalf("expected 2 alerts from fallback path, got %d", len(alerts))
		}
	})

	t.Run("两路径均返回坏 JSON 时返回 nil", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`not-json`))
		}))
		defer ts.Close()

		tool := NewAlertCheckTool(nil)
		alerts := tool.queryGrafanaAlerts(&AlertCheckParams{
			System:   "grafana",
			Endpoint: ts.URL,
		})
		if alerts != nil {
			t.Fatalf("expected nil on bad JSON, got %v", alerts)
		}
	})
}

// TestAlertCheckTool_queryGrafanaAlerts_EmptyEndpoint 覆盖端点为空时返回 nil。使用 t.Setenv, 不可并行。
func TestAlertCheckTool_queryGrafanaAlerts_EmptyEndpoint(t *testing.T) {
	t.Setenv("SECOPS_GRAFANA_ENDPOINT", "")
	tool := NewAlertCheckTool(nil)
	alerts := tool.queryGrafanaAlerts(&AlertCheckParams{System: "grafana"})
	if alerts != nil {
		t.Fatalf("expected nil for empty endpoint, got %v", alerts)
	}
}

// TestAlertCheckTool_queryDatadogAlerts 覆盖 queryDatadogAlerts 的成功、缺少凭据与坏 JSON 分支。
// 注意: app key 仅来自环境变量, 多个子测试使用 t.Setenv, 故整体串行 (父测试不可并行)。
func TestAlertCheckTool_queryDatadogAlerts(t *testing.T) {
	monitorsPayload := `{
		"monitors": [
			{
				"id": 12345,
				"name": "SyntheticCheckoutFail",
				"message": "checkout synthetic failed",
				"overall_state": "Alert",
				"tags": ["env:prod"],
				"classification": "critical"
			},
			{
				"id": 67890,
				"name": "LowDisk",
				"message": "",
				"overall_state": "OK",
				"classification": ""
			}
		]
	}`

	t.Run("提供 api+app key 时解析告警", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("DD-API-KEY") != "dd-api" {
				t.Errorf("expected DD-API-KEY header, got %q", r.Header.Get("DD-API-KEY"))
			}
			if r.Header.Get("DD-APPLICATION-KEY") != "dd-app" {
				t.Errorf("expected DD-APPLICATION-KEY header, got %q", r.Header.Get("DD-APPLICATION-KEY"))
			}
			if !strings.HasPrefix(r.URL.Path, "/api/v1/monitor/search") {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(monitorsPayload))
		}))
		defer ts.Close()

		t.Setenv("SECOPS_DATADOG_APP_KEY", "dd-app")
		tool := NewAlertCheckTool(nil)
		alerts := tool.queryDatadogAlerts(&AlertCheckParams{
			System:   "datadog",
			Endpoint: ts.URL,
			APIToken: "dd-api",
			Filter:   "checkout",
		})
		if len(alerts) != 2 {
			t.Fatalf("expected 2 alerts, got %d", len(alerts))
		}
		if alerts[0].Name != "SyntheticCheckoutFail" || alerts[0].Status != "firing" {
			t.Fatalf("unexpected first alert: %+v", alerts[0])
		}
		if alerts[1].Status != "resolved" {
			t.Fatalf("expected second alert resolved, got %+v", alerts[1])
		}
	})

	t.Run("缺少 app key 时返回 nil", func(t *testing.T) {
		t.Setenv("SECOPS_DATADOG_APP_KEY", "")
		tool := NewAlertCheckTool(nil)
		alerts := tool.queryDatadogAlerts(&AlertCheckParams{
			System:   "datadog",
			Endpoint: "http://localhost",
			APIToken: "dd-api",
		})
		if alerts != nil {
			t.Fatalf("expected nil without app key, got %v", alerts)
		}
	})

	t.Run("缺少 api key 时返回 nil", func(t *testing.T) {
		t.Setenv("SECOPS_DATADOG_APP_KEY", "dd-app")
		tool := NewAlertCheckTool(nil)
		alerts := tool.queryDatadogAlerts(&AlertCheckParams{
			System:   "datadog",
			Endpoint: "http://localhost",
		})
		if alerts != nil {
			t.Fatalf("expected nil without api key, got %v", alerts)
		}
	})

	t.Run("坏 JSON 时返回 nil", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{bad`))
		}))
		defer ts.Close()

		t.Setenv("SECOPS_DATADOG_APP_KEY", "dd-app")
		tool := NewAlertCheckTool(nil)
		alerts := tool.queryDatadogAlerts(&AlertCheckParams{
			System:   "datadog",
			Endpoint: ts.URL,
			APIToken: "dd-api",
		})
		if alerts != nil {
			t.Fatalf("expected nil on bad JSON, got %v", alerts)
		}
	})
}

// TestAlertCheckTool_queryPagerDutyAlerts 覆盖 queryPagerDutyAlerts 的成功、缺 token 与坏 JSON 分支。
func TestAlertCheckTool_queryPagerDutyAlerts(t *testing.T) {
	t.Parallel()

	incidentsPayload := `{
		"incidents": [
			{
				"id": "PDX-1",
				"title": "DB Lag High",
				"status": "triggered",
				"urgency": "high",
				"created_at": "2026-06-25T08:00:00Z"
			},
			{
				"id": "PDX-2",
				"title": "",
				"status": "resolved",
				"urgency": "",
				"created_at": "2026-06-25T07:00:00Z"
			}
		]
	}`

	t.Run("提供 token 时解析事件", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Token token=pdtoken" {
				t.Errorf("unexpected auth header: %q", r.Header.Get("Authorization"))
			}
			if r.URL.Path != "/incidents" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(incidentsPayload))
		}))
		defer ts.Close()

		tool := NewAlertCheckTool(nil)
		alerts := tool.queryPagerDutyAlerts(&AlertCheckParams{
			System:   "pagerduty",
			Endpoint: ts.URL,
			APIToken: "pdtoken",
		})
		if len(alerts) != 2 {
			t.Fatalf("expected 2 alerts, got %d", len(alerts))
		}
		if alerts[0].Name != "DB Lag High" || alerts[0].Status != "firing" {
			t.Fatalf("unexpected first alert: %+v", alerts[0])
		}
		if alerts[1].Status != "resolved" {
			t.Fatalf("expected second alert resolved, got %+v", alerts[1])
		}
	})

	t.Run("坏 JSON 时返回 nil", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`not json`))
		}))
		defer ts.Close()

		tool := NewAlertCheckTool(nil)
		alerts := tool.queryPagerDutyAlerts(&AlertCheckParams{
			System:   "pagerduty",
			Endpoint: ts.URL,
			APIToken: "pdtoken",
		})
		if alerts != nil {
			t.Fatalf("expected nil on bad JSON, got %v", alerts)
		}
	})

	t.Run("非 2xx 时返回 nil", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer ts.Close()

		tool := NewAlertCheckTool(nil)
		alerts := tool.queryPagerDutyAlerts(&AlertCheckParams{
			System:   "pagerduty",
			Endpoint: ts.URL,
			APIToken: "pdtoken",
		})
		if alerts != nil {
			t.Fatalf("expected nil on non-2xx, got %v", alerts)
		}
	})
}

// TestAlertCheckTool_queryPagerDutyAlerts_NoToken 覆盖缺少 token 时返回 nil。使用 t.Setenv, 不可并行。
func TestAlertCheckTool_queryPagerDutyAlerts_NoToken(t *testing.T) {
	t.Setenv("SECOPS_PAGERDUTY_TOKEN", "")
	tool := NewAlertCheckTool(nil)
	alerts := tool.queryPagerDutyAlerts(&AlertCheckParams{
		System:   "pagerduty",
		Endpoint: "http://localhost",
	})
	if alerts != nil {
		t.Fatalf("expected nil without token, got %v", alerts)
	}
}

// TestAlertCheckTool_queryGrafanaAlertsRemote 覆盖通过 runCmd 远程拉取 Grafana 告警的路径。
func TestAlertCheckTool_queryGrafanaAlertsRemote(t *testing.T) {
	t.Parallel()

	v2Payload := `[{"labels":{"alertname":"RemoteGrafana","severity":"critical"},"annotations":{"summary":"remote grafana"},"status":{"state":"alerting"},"startsAt":"2026-06-25T08:00:00Z"}]`

	t.Run("远程 stdout 返回有效告警", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		var gotHeaders map[string]string
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			cmdline := strings.Join(args, " ")
			// 捕获 curl 命令中的 Authorization 头透传
			if strings.Contains(cmdline, "Authorization") {
				gotHeaders = map[string]string{"auth": "present"}
			}
			return []byte(v2Payload), nil, nil
		}

		alerts := tool.queryGrafanaAlertsRemote(&AlertCheckParams{
			System:     "grafana",
			Endpoint:   "http://127.0.0.1:3000",
			APIToken:   "remote-token",
			RemoteHost: "10.0.0.60",
			RemoteUser: "ops",
		})
		if len(alerts) != 1 {
			t.Fatalf("expected 1 remote alert, got %d", len(alerts))
		}
		if alerts[0].Name != "RemoteGrafana" || alerts[0].Status != "firing" {
			t.Fatalf("unexpected remote alert: %+v", alerts[0])
		}
		if gotHeaders == nil || gotHeaders["auth"] != "present" {
			t.Fatal("expected Authorization header to be forwarded to remote curl")
		}
	})

	t.Run("runCmd 失败时返回 nil", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			return nil, []byte("connection refused"), errRemoteFailure
		}
		alerts := tool.queryGrafanaAlertsRemote(&AlertCheckParams{
			System:     "grafana",
			RemoteHost: "10.0.0.60",
			RemoteUser: "ops",
		})
		if alerts != nil {
			t.Fatalf("expected nil on runCmd failure, got %v", alerts)
		}
	})

	t.Run("远程返回坏 JSON 时返回 nil", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			return []byte(`not-json`), nil, nil
		}
		alerts := tool.queryGrafanaAlertsRemote(&AlertCheckParams{
			System:     "grafana",
			RemoteHost: "10.0.0.60",
			RemoteUser: "ops",
		})
		if alerts != nil {
			t.Fatalf("expected nil on bad remote JSON, got %v", alerts)
		}
	})
}

// TestAlertCheckTool_queryPrometheusAlertsRemote 覆盖通过 runCmd 远程拉取 Prometheus 告警的路径。
func TestAlertCheckTool_queryPrometheusAlertsRemote(t *testing.T) {
	t.Parallel()

	payload := `{"status":"success","data":{"alerts":[{"labels":{"alertname":"RemoteProm","severity":"critical"},"annotations":{"summary":"remote prom"},"state":"firing","activeAt":"2026-06-25T08:00:00Z"}]}}`

	t.Run("远程 stdout 返回有效告警", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			return []byte(payload), nil, nil
		}
		alerts := tool.queryPrometheusAlertsRemote(&AlertCheckParams{
			System:     "prometheus",
			Endpoint:   "http://127.0.0.1:9090",
			RemoteHost: "10.0.0.60",
			RemoteUser: "ops",
		})
		if len(alerts) != 1 {
			t.Fatalf("expected 1 remote alert, got %d", len(alerts))
		}
		if alerts[0].Name != "RemoteProm" || alerts[0].Status != "firing" {
			t.Fatalf("unexpected remote alert: %+v", alerts[0])
		}
	})

	t.Run("runCmd 失败时返回 nil", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			return nil, []byte("ssh: connect to host"), errRemoteFailure
		}
		alerts := tool.queryPrometheusAlertsRemote(&AlertCheckParams{
			System:     "prometheus",
			RemoteHost: "10.0.0.60",
			RemoteUser: "ops",
		})
		if alerts != nil {
			t.Fatalf("expected nil on runCmd failure, got %v", alerts)
		}
	})
}

// TestAlertCheckTool_runRemoteHTTPGet 覆盖 runRemoteHTTPGet 的成功与命令失败分支。
func TestAlertCheckTool_runRemoteHTTPGet(t *testing.T) {
	t.Parallel()

	t.Run("成功返回 stdout", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			if name != "ssh" {
				t.Errorf("expected ssh command, got %s", name)
			}
			return []byte(`{"ok":true}`), nil, nil
		}
		out, err := tool.runRemoteHTTPGet(&AlertCheckParams{
			RemoteHost: "10.0.0.60",
			RemoteUser: "ops",
		}, "http://127.0.0.1:9090/api/v1/alerts", map[string]string{"Authorization": "Bearer x"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(out) != `{"ok":true}` {
			t.Fatalf("unexpected output: %s", string(out))
		}
	})

	t.Run("命令失败且 stdout 为空时返回错误", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			return nil, []byte("curl: (7) connection refused"), errRemoteFailure
		}
		_, err := tool.runRemoteHTTPGet(&AlertCheckParams{
			RemoteHost: "10.0.0.60",
			RemoteUser: "ops",
		}, "http://127.0.0.1:9090/api/v1/alerts", nil)
		if err == nil {
			t.Fatal("expected error on remote failure")
		}
		if !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("expected error to mention stderr, got %v", err)
		}
	})

	t.Run("命令失败但 stdout 非空时仍返回 stdout", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
			// curl 部分输出后非零退出,stdout 已有内容时应保留。
			return []byte(`{"partial":true}`), []byte("warning"), errRemoteFailure
		}
		out, err := tool.runRemoteHTTPGet(&AlertCheckParams{
			RemoteHost: "10.0.0.60",
			RemoteUser: "ops",
		}, "http://127.0.0.1:9090/api/v1/alerts", nil)
		if err != nil {
			t.Fatalf("expected nil error when stdout present, got %v", err)
		}
		if string(out) != `{"partial":true}` {
			t.Fatalf("unexpected output: %s", string(out))
		}
	})

	t.Run("缺少 remote host 时返回构造错误", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		_, err := tool.runRemoteHTTPGet(&AlertCheckParams{}, "http://127.0.0.1:9090/api/v1/alerts", nil)
		if err == nil {
			t.Fatal("expected error when remote_host missing")
		}
	})
}

// TestAlertCheckTool_alertMatchesFilter 覆盖 alertMatchesFilter 的各匹配分支与未命中。
func TestAlertCheckTool_alertMatchesFilter(t *testing.T) {
	t.Parallel()

	alert := AlertInfo{
		ID:      "prom-1",
		Name:    "HighCPU",
		Message: "cpu above threshold",
		Labels: map[string]string{
			"namespace": "production",
			"pod":       "api-server",
		},
		Annotations: map[string]string{
			"runbook": "https://runbook.example.com/cpu",
		},
	}

	cases := []struct {
		name   string
		needle string
		want   bool
	}{
		{"名称匹配", "highcpu", true},
		{"消息匹配", "threshold", true},
		{"ID 匹配", "prom-1", true},
		{"标签键匹配", "namespace", true},
		{"标签值匹配", "production", true},
		{"注解键匹配", "runbook", true},
		{"注解值匹配", "cpu", true},
		{"完全不匹配", "disk-space", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := alertMatchesFilter(alert, tc.needle); got != tc.want {
				t.Fatalf("alertMatchesFilter(%q) = %v, want %v", tc.needle, got, tc.want)
			}
		})
	}
}

// TestAlertCheckTool_applyAlertFilters 覆盖时间范围与关键字过滤组合。
func TestAlertCheckTool_applyAlertFilters(t *testing.T) {
	t.Parallel()

	now := time.Now()
	alerts := []AlertInfo{
		{ID: "1", Name: "RecentFiring", Status: "firing", FiredAt: now.Add(-1 * time.Minute), Message: "recent"},
		{ID: "2", Name: "OldResolved", Status: "resolved", FiredAt: now.Add(-2 * time.Hour), Message: "old"},
		{ID: "3", Name: "RecentDisk", Status: "firing", FiredAt: now.Add(-2 * time.Minute), Message: "disk full"},
	}

	t.Run("时间范围过滤掉过旧告警", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		got := tool.applyAlertFilters(alerts, &AlertCheckParams{TimeRange: "10m"})
		if len(got) != 2 {
			t.Fatalf("expected 2 recent alerts, got %d (%+v)", len(got), got)
		}
	})

	t.Run("关键字过滤保留匹配项", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		got := tool.applyAlertFilters(alerts, &AlertCheckParams{Filter: "disk"})
		if len(got) != 1 || got[0].Name != "RecentDisk" {
			t.Fatalf("expected only RecentDisk, got %+v", got)
		}
	})

	t.Run("零 FiredAt 不被时间范围剔除", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		noTime := []AlertInfo{{ID: "x", Name: "NoTime", Status: "firing"}}
		got := tool.applyAlertFilters(noTime, &AlertCheckParams{TimeRange: "1m"})
		if len(got) != 1 {
			t.Fatalf("expected zero-time alert to survive, got %d", len(got))
		}
	})

	t.Run("非法时间范围被忽略", func(t *testing.T) {
		t.Parallel()
		tool := NewAlertCheckTool(nil)
		got := tool.applyAlertFilters(alerts, &AlertCheckParams{TimeRange: "not-a-duration"})
		if len(got) != 3 {
			t.Fatalf("expected all alerts preserved on invalid duration, got %d", len(got))
		}
	})
}

// TestAlertCheckTool_getDispatchersFallback 覆盖 get*Alerts 在远程失败时回退到内置样本告警的分支。
func TestAlertCheckTool_getDispatchersFallback(t *testing.T) {
	t.Parallel()

	cases := []struct {
		system     string
		invoke     func(*AlertCheckTool) []AlertInfo
		wantMinLen int
	}{
		{"prometheus", func(t *AlertCheckTool) []AlertInfo {
			return t.getPrometheusAlerts(&AlertCheckParams{System: "prometheus"})
		}, 1},
		{"grafana", func(t *AlertCheckTool) []AlertInfo { return t.getGrafanaAlerts(&AlertCheckParams{System: "grafana"}) }, 1},
		{"datadog", func(t *AlertCheckTool) []AlertInfo { return t.getDatadogAlerts(&AlertCheckParams{System: "datadog"}) }, 1},
		{"pagerduty", func(t *AlertCheckTool) []AlertInfo {
			return t.getPagerDutyAlerts(&AlertCheckParams{System: "pagerduty"})
		}, 1},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.system, func(t *testing.T) {
			t.Parallel()
			tool := NewAlertCheckTool(nil)
			// 让远程/HTTP 查询全部失败,确保走到内置样本分支。
			tool.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
				return nil, []byte("forced failure"), errRemoteFailure
			}
			alerts := tc.invoke(tool)
			if len(alerts) < tc.wantMinLen {
				t.Fatalf("expected at least %d fallback alerts, got %d", tc.wantMinLen, len(alerts))
			}
			for _, a := range alerts {
				if a.ID == "" || a.Name == "" {
					t.Fatalf("expected populated fallback alert, got %+v", a)
				}
			}
		})
	}
}

// TestAlertCheckTool_performCheckLiveViaHTTP 通过 httptest 驱动 performCheck,确认 live 数据源分支被命中。
func TestAlertCheckTool_performCheckLiveViaHTTP(t *testing.T) {
	t.Parallel()

	t.Run("Prometheus live 数据源", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"success","data":{"alerts":[{"labels":{"alertname":"LiveCPU","severity":"critical"},"annotations":{"summary":"live"},"state":"firing","activeAt":"2026-06-25T08:00:00Z"}]}}`))
		}))
		defer ts.Close()

		tool := NewAlertCheckTool(nil)
		result := tool.performCheck(&AlertCheckParams{System: "prometheus", Endpoint: ts.URL})
		if result.DataSource != "live" {
			t.Fatalf("expected live data source, got %q", result.DataSource)
		}
		if result.Total != 1 || result.Firing != 1 {
			t.Fatalf("expected 1 firing live alert, got %+v", result)
		}
	})

	t.Run("Grafana live 数据源", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/alertmanager/grafana/api/v2/alerts" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`[{"labels":{"alertname":"LiveGrafana","severity":"critical"},"annotations":{"summary":"live"},"status":{"state":"alerting"},"startsAt":"2026-06-25T08:00:00Z"}]`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()

		tool := NewAlertCheckTool(nil)
		result := tool.performCheck(&AlertCheckParams{System: "grafana", Endpoint: ts.URL, APIToken: "t"})
		if result.DataSource != "live" {
			t.Fatalf("expected live data source, got %q", result.DataSource)
		}
		if result.Total != 1 {
			t.Fatalf("expected 1 live alert, got %+v", result)
		}
	})

	t.Run("PagerDuty live 数据源", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"incidents":[{"id":"PD1","title":"LivePD","status":"triggered","urgency":"high","created_at":"2026-06-25T08:00:00Z"}]}`))
		}))
		defer ts.Close()

		tool := NewAlertCheckTool(nil)
		result := tool.performCheck(&AlertCheckParams{System: "pagerduty", Endpoint: ts.URL, APIToken: "tok"})
		if result.DataSource != "live" {
			t.Fatalf("expected live data source, got %q", result.DataSource)
		}
		if result.Total != 1 {
			t.Fatalf("expected 1 live alert, got %+v", result)
		}
	})
}

// TestAlertCheckTool_performCheckLiveViaHTTP_EnvScoped groups the subtests that
// mutate process environment via t.Setenv. These cannot run under a parallel
// parent, so they live in their own non-parallel test.
func TestAlertCheckTool_performCheckLiveViaHTTP_EnvScoped(t *testing.T) {
	t.Run("Datadog live 数据源", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"monitors":[{"id":1,"name":"LiveDD","message":"m","overall_state":"Alert","classification":"critical"}]}`))
		}))
		defer ts.Close()
		t.Setenv("SECOPS_DATADOG_APP_KEY", "app")

		tool := NewAlertCheckTool(nil)
		result := tool.performCheck(&AlertCheckParams{System: "datadog", Endpoint: ts.URL, APIToken: "api"})
		if result.DataSource != "live" {
			t.Fatalf("expected live data source, got %q", result.DataSource)
		}
		if result.Total != 1 {
			t.Fatalf("expected 1 live alert, got %+v", result)
		}
	})

	t.Run("查询失败时回退到样本数据源", func(t *testing.T) {
		t.Setenv("SECOPS_PROMETHEUS_ENDPOINT", "")
		tool := NewAlertCheckTool(nil)
		result := tool.performCheck(&AlertCheckParams{System: "prometheus"})
		if result.DataSource != "fallback_sample" {
			t.Fatalf("expected fallback_sample data source, got %q", result.DataSource)
		}
		if result.FallbackReason == "" {
			t.Fatal("expected fallback_reason to be set")
		}
	})
}

// errRemoteFailure 是测试用的哨兵错误,避免引入真实网络调用。
var errRemoteFailure = newRemoteFailureSentinel()

func newRemoteFailureSentinel() error {
	return &remoteFailureErr{msg: "remote failure"}
}

type remoteFailureErr struct{ msg string }

func (e *remoteFailureErr) Error() string { return e.msg }
