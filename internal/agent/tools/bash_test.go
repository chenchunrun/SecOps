package tools

import (
	"context"
	"encoding/json"
	"testing"

	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/pubsub"
	"github.com/chenchunrun/SecOps/internal/shell"
	"github.com/stretchr/testify/require"
)

type mockBashPermissionService struct {
	*pubsub.Broker[permission.PermissionRequest]
	requests []permission.CreatePermissionRequest
}

func (m *mockBashPermissionService) Request(ctx context.Context, req permission.CreatePermissionRequest) (bool, error) {
	m.requests = append(m.requests, req)
	return true, nil
}

func (m *mockBashPermissionService) Grant(req permission.PermissionRequest) {}

func (m *mockBashPermissionService) Deny(req permission.PermissionRequest) {}

func (m *mockBashPermissionService) GrantPersistent(req permission.PermissionRequest) {}

func (m *mockBashPermissionService) AutoApproveSession(sessionID string) {}

func (m *mockBashPermissionService) SetSkipRequests(skip bool) {}

func (m *mockBashPermissionService) SkipRequests() bool {
	return false
}

func (m *mockBashPermissionService) SubscribeNotifications(ctx context.Context) <-chan pubsub.Event[permission.PermissionNotification] {
	return make(<-chan pubsub.Event[permission.PermissionNotification])
}

func TestBashTool_DefaultAutoBackgroundThreshold(t *testing.T) {
	workingDir := t.TempDir()
	tool := newBashToolForTest(workingDir)
	ctx := context.WithValue(context.Background(), SessionIDContextKey, "test-session")

	resp := runBashTool(t, tool, ctx, BashParams{
		Description: "default threshold",
		Command:     "echo done",
	})

	require.False(t, resp.IsError)
	var meta BashResponseMetadata
	require.NoError(t, json.Unmarshal([]byte(resp.Metadata), &meta))
	require.False(t, meta.Background)
	require.Empty(t, meta.ShellID)
	require.Contains(t, meta.Output, "done")
}

func TestBashDescriptionWithNilAttributionDoesNotPanic(t *testing.T) {
	require.NotPanics(t, func() {
		desc := bashDescription(nil, "test-model")
		require.NotEmpty(t, desc)
	})
}

func TestBashTool_CustomAutoBackgroundThreshold(t *testing.T) {
	workingDir := t.TempDir()
	tool := newBashToolForTest(workingDir)
	ctx := context.WithValue(context.Background(), SessionIDContextKey, "test-session")

	resp := runBashTool(t, tool, ctx, BashParams{
		Description:         "custom threshold",
		Command:             "sleep 1.5 && echo done",
		AutoBackgroundAfter: 1,
	})

	require.False(t, resp.IsError)
	var meta BashResponseMetadata
	require.NoError(t, json.Unmarshal([]byte(resp.Metadata), &meta))
	require.True(t, meta.Background)
	require.NotEmpty(t, meta.ShellID)
	require.Contains(t, resp.Content, "moved to background")

	bgManager := shell.GetBackgroundShellManager()
	require.NoError(t, bgManager.Kill(meta.ShellID))
}

func TestFormatRemoteTarget(t *testing.T) {
	require.Equal(t, "10.0.0.10", formatRemoteTarget("", "10.0.0.10"))
	require.Equal(t, "ops@10.0.0.10", formatRemoteTarget("ops", "10.0.0.10"))
	require.Equal(t, "", formatRemoteTarget("ops", ""))
}

func TestShellQuoteSingle(t *testing.T) {
	require.Equal(t, "'/var/log/app'", shellQuoteSingle("/var/log/app"))
	require.Equal(t, `'a'"'"'b'`, shellQuoteSingle("a'b"))
}

func TestApplyRemoteProfile(t *testing.T) {
	params := BashParams{Command: "hostname", RemoteProfile: "prod-web"}
	remoteCfg := &config.Remote{
		Profiles: []config.RemoteProfile{
			{
				ID:        "prod-web",
				Host:      "10.0.0.12",
				User:      "ops",
				Port:      2222,
				ProxyJump: "bastion",
				Auth:      config.RemoteAuth{Type: "ssh_key", KeyPath: "~/.ssh/id_ed25519"},
			},
		},
	}

	merged, profile, err := applyRemoteProfile(params, remoteCfg)
	require.NoError(t, err)
	require.NotNil(t, profile)
	require.Equal(t, "10.0.0.12", merged.RemoteHost)
	require.Equal(t, "ops", merged.RemoteUser)
	require.Equal(t, 2222, merged.RemotePort)
	require.Equal(t, "bastion", merged.RemoteProxyJump)
	require.Equal(t, "~/.ssh/id_ed25519", merged.RemoteKeyPath)
}

func TestApplyRemoteProfileNotFound(t *testing.T) {
	_, _, err := applyRemoteProfile(
		BashParams{Command: "hostname", RemoteProfile: "missing"},
		&config.Remote{},
	)
	require.Error(t, err)
}

func TestApplyDefaultRemoteProfile(t *testing.T) {
	params := BashParams{Command: "hostname", RemoteHost: "10.0.0.12"}
	remoteCfg := &config.Remote{
		DefaultProfile: "prod-web",
		Profiles: []config.RemoteProfile{
			{
				ID:        "prod-web",
				Host:      "10.0.0.12",
				User:      "ops",
				Port:      2222,
				ProxyJump: "bastion",
				Env:       "prod",
				Auth:      config.RemoteAuth{Type: "ssh_key", KeyPath: "~/.ssh/id_ed25519"},
			},
		},
	}

	merged, profile, err := applyDefaultRemoteProfile(params, remoteCfg)
	require.NoError(t, err)
	require.NotNil(t, profile)
	require.Equal(t, "prod-web", merged.RemoteProfile)
	require.Equal(t, "10.0.0.12", merged.RemoteHost)
	require.Equal(t, "ops", merged.RemoteUser)
	require.Equal(t, 2222, merged.RemotePort)
	require.Equal(t, "bastion", merged.RemoteProxyJump)
	require.Equal(t, "prod", merged.RemoteEnv)
	require.Equal(t, "~/.ssh/id_ed25519", merged.RemoteKeyPath)
}

func TestEnforceRemoteCommandPolicy(t *testing.T) {
	profile := &config.RemoteProfile{
		ID:              "prod",
		AllowedCommands: []string{"systemctl status *", "journalctl *"},
		DenyCommands:    []string{"*rm -rf*"},
	}

	allowDecision, err := enforceRemoteCommandPolicy(profile, "systemctl status nginx")
	require.NoError(t, err)
	require.Equal(t, "allow_list", allowDecision.Type)
	require.Equal(t, "allow", allowDecision.Result)
	require.Equal(t, "systemctl status *", allowDecision.Rule)

	denyByAllowList, err := enforceRemoteCommandPolicy(profile, "cat /etc/passwd")
	require.Error(t, err)
	require.Equal(t, "allow_list", denyByAllowList.Type)
	require.Equal(t, "deny", denyByAllowList.Result)

	denyByDenyList, err := enforceRemoteCommandPolicy(profile, "echo ok && rm -rf /tmp/a")
	require.Error(t, err)
	require.Equal(t, "deny_list", denyByDenyList.Type)
	require.Equal(t, "deny", denyByDenyList.Result)
}

func TestCommandPatternMatch(t *testing.T) {
	require.True(t, commandPatternMatch("systemctl status *", "systemctl status nginx"))
	require.True(t, commandPatternMatch("journalctl", "journalctl -u sshd -n 100"))
	require.False(t, commandPatternMatch("systemctl restart *", "systemctl status nginx"))
}

func TestBashTool_RemoteExecutionPermissionMetadata(t *testing.T) {
	workingDir := t.TempDir()
	permissions := &mockBashPermissionService{Broker: pubsub.NewBroker[permission.PermissionRequest]()}
	attribution := &config.Attribution{TrailerStyle: config.TrailerStyleNone}
	tool := NewBashTool(
		permissions,
		workingDir,
		attribution,
		"test-model",
		&config.Remote{
			Profiles: []config.RemoteProfile{
				{
					ID:        "prod-web",
					Host:      "127.0.0.1",
					User:      "ops",
					Port:      1,
					Env:       "prod",
					ProxyJump: "",
				},
			},
		},
	)
	ctx := context.WithValue(context.Background(), SessionIDContextKey, "test-session")

	resp := runBashTool(t, tool, ctx, BashParams{
		Description:   "remote test",
		Command:       "echo hello",
		RemoteProfile: "prod-web",
	})

	require.True(t, resp.IsError)
	require.Len(t, permissions.requests, 1)
	req := permissions.requests[0]
	require.Equal(t, "ssh", req.Transport)
	require.Equal(t, "ops@127.0.0.1", req.TargetHost)
	require.Equal(t, "prod", req.TargetEnv)
	require.Equal(t, "prod-web", req.TargetID)
	require.Equal(t, "ssh://ops@127.0.0.1", req.Path)
}

func TestBashTool_RemotePolicyDenyRecordedToAudit(t *testing.T) {
	workingDir := t.TempDir()
	permissions := &mockBashPermissionService{Broker: pubsub.NewBroker[permission.PermissionRequest]()}
	attribution := &config.Attribution{TrailerStyle: config.TrailerStyleNone}
	store := audit.NewInMemoryAuditStore()
	audit.SetGlobalStore(store)
	t.Cleanup(func() { audit.SetGlobalStore(audit.NewInMemoryAuditStore()) })

	tool := NewBashTool(
		permissions,
		workingDir,
		attribution,
		"test-model",
		&config.Remote{
			Profiles: []config.RemoteProfile{
				{
					ID:              "prod-web",
					Host:            "127.0.0.1",
					User:            "ops",
					Port:            1,
					Env:             "prod",
					AllowedCommands: []string{"systemctl status *"},
				},
			},
		},
	)
	ctx := context.WithValue(context.Background(), SessionIDContextKey, "test-session")

	resp := runBashTool(t, tool, ctx, BashParams{
		Description:   "remote deny audit",
		Command:       "cat /etc/passwd",
		RemoteProfile: "prod-web",
	})

	require.True(t, resp.IsError)

	events, err := store.ListEvents(&audit.AuditFilter{SessionID: "test-session"})
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, audit.EventTypePermissionDenied, events[0].EventType)
	require.Equal(t, "remote_policy_deny", events[0].Action)
	require.Equal(t, "ssh", events[0].Transport)
	require.Equal(t, "ops@127.0.0.1", events[0].TargetHost)
	require.Equal(t, "prod-web", events[0].TargetID)
	require.Equal(t, "deny", events[0].Details["policy_result"])
}

func TestBashTool_RemotePolicyDenyRecordedToAudit_DefaultProfile(t *testing.T) {
	workingDir := t.TempDir()
	permissions := &mockBashPermissionService{Broker: pubsub.NewBroker[permission.PermissionRequest]()}
	attribution := &config.Attribution{TrailerStyle: config.TrailerStyleNone}
	store := audit.NewInMemoryAuditStore()
	audit.SetGlobalStore(store)
	t.Cleanup(func() { audit.SetGlobalStore(audit.NewInMemoryAuditStore()) })

	tool := NewBashTool(
		permissions,
		workingDir,
		attribution,
		"test-model",
		&config.Remote{
			DefaultProfile: "prod-web",
			Profiles: []config.RemoteProfile{
				{
					ID:              "prod-web",
					Host:            "127.0.0.1",
					User:            "ops",
					Port:            1,
					Env:             "prod",
					AllowedCommands: []string{"systemctl status *"},
				},
			},
		},
	)
	ctx := context.WithValue(context.Background(), SessionIDContextKey, "test-session")

	resp := runBashTool(t, tool, ctx, BashParams{
		Description: "remote deny audit default profile",
		Command:     "cat /etc/passwd",
		RemoteHost:  "127.0.0.1",
	})

	require.True(t, resp.IsError)

	events, err := store.ListEvents(&audit.AuditFilter{SessionID: "test-session"})
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, audit.EventTypePermissionDenied, events[0].EventType)
	require.Equal(t, "remote_policy_deny", events[0].Action)
	require.Equal(t, "ssh", events[0].Transport)
	require.Equal(t, "ops@127.0.0.1", events[0].TargetHost)
	require.Equal(t, "prod-web", events[0].TargetID)
	require.Equal(t, "deny", events[0].Details["policy_result"])
}

func newBashToolForTest(workingDir string) fantasy.AgentTool {
	permissions := &mockBashPermissionService{Broker: pubsub.NewBroker[permission.PermissionRequest]()}
	attribution := &config.Attribution{TrailerStyle: config.TrailerStyleNone}
	return NewBashTool(permissions, workingDir, attribution, "test-model")
}

func runBashTool(t *testing.T, tool fantasy.AgentTool, ctx context.Context, params BashParams) fantasy.ToolResponse {
	t.Helper()

	input, err := json.Marshal(params)
	require.NoError(t, err)

	call := fantasy.ToolCall{
		ID:    "test-call",
		Name:  BashToolName,
		Input: string(input),
	}

	resp, err := tool.Run(ctx, call)
	require.NoError(t, err)
	return resp
}
