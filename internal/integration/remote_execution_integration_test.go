package integration

import (
	"context"
	"encoding/json"
	"testing"

	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/agent/tools"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/pubsub"
)

type remotePermissionCapture struct {
	*pubsub.Broker[permission.PermissionRequest]
	requests []permission.CreatePermissionRequest
}

func (m *remotePermissionCapture) Request(ctx context.Context, req permission.CreatePermissionRequest) (bool, error) {
	m.requests = append(m.requests, req)
	return true, nil
}

func (m *remotePermissionCapture) GrantPersistent(req permission.PermissionRequest) {}
func (m *remotePermissionCapture) Grant(req permission.PermissionRequest)           {}
func (m *remotePermissionCapture) Deny(req permission.PermissionRequest)            {}
func (m *remotePermissionCapture) AutoApproveSession(sessionID string)              {}
func (m *remotePermissionCapture) SetSkipRequests(skip bool)                        {}
func (m *remotePermissionCapture) SkipRequests() bool                               { return false }
func (m *remotePermissionCapture) SubscribeNotifications(ctx context.Context) <-chan pubsub.Event[permission.PermissionNotification] {
	return make(<-chan pubsub.Event[permission.PermissionNotification])
}

func TestRemoteProfilePermissionMetadataPropagation(t *testing.T) {
	perm := &remotePermissionCapture{Broker: pubsub.NewBroker[permission.PermissionRequest]()}
	attr := &config.Attribution{TrailerStyle: config.TrailerStyleNone}
	tool := tools.NewBashTool(
		perm,
		t.TempDir(),
		attr,
		"test-model",
		&config.Remote{
			Profiles: []config.RemoteProfile{{
				ID:   "prod-web",
				Host: "127.0.0.1",
				User: "ops",
				Port: 1,
				Env:  "prod",
			}},
		},
	)

	params := tools.BashParams{
		Description:   "remote integration",
		Command:       "echo hello",
		RemoteProfile: "prod-web",
	}
	input, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	ctx := context.WithValue(context.Background(), tools.SessionIDContextKey, "sess-remote-1")
	_, err = tool.Run(ctx, fantasy.ToolCall{ID: "call-remote-1", Name: tools.BashToolName, Input: string(input)})
	if err != nil {
		t.Fatalf("run bash tool: %v", err)
	}

	if len(perm.requests) != 1 {
		t.Fatalf("expected 1 permission request, got %d", len(perm.requests))
	}
	req := perm.requests[0]
	if req.Transport != "ssh" {
		t.Fatalf("expected transport ssh, got %q", req.Transport)
	}
	if req.TargetHost != "ops@127.0.0.1" {
		t.Fatalf("expected target host ops@127.0.0.1, got %q", req.TargetHost)
	}
	if req.TargetEnv != "prod" {
		t.Fatalf("expected target env prod, got %q", req.TargetEnv)
	}
	if req.TargetID != "prod-web" {
		t.Fatalf("expected target id prod-web, got %q", req.TargetID)
	}
	if req.Path != "ssh://ops@127.0.0.1" {
		t.Fatalf("expected path ssh://ops@127.0.0.1, got %q", req.Path)
	}
}

func TestRemoteDefaultProfilePermissionMetadataPropagation(t *testing.T) {
	perm := &remotePermissionCapture{Broker: pubsub.NewBroker[permission.PermissionRequest]()}
	attr := &config.Attribution{TrailerStyle: config.TrailerStyleNone}
	tool := tools.NewBashTool(
		perm,
		t.TempDir(),
		attr,
		"test-model",
		&config.Remote{
			DefaultProfile: "prod-web",
			Profiles: []config.RemoteProfile{{
				ID:   "prod-web",
				Host: "127.0.0.1",
				User: "ops",
				Port: 1,
				Env:  "prod",
			}},
		},
	)

	params := tools.BashParams{
		Description: "remote integration default profile",
		Command:     "echo hello",
		RemoteHost:  "127.0.0.1",
	}
	input, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	ctx := context.WithValue(context.Background(), tools.SessionIDContextKey, "sess-remote-2")
	_, err = tool.Run(ctx, fantasy.ToolCall{ID: "call-remote-2", Name: tools.BashToolName, Input: string(input)})
	if err != nil {
		t.Fatalf("run bash tool: %v", err)
	}

	if len(perm.requests) != 1 {
		t.Fatalf("expected 1 permission request, got %d", len(perm.requests))
	}
	req := perm.requests[0]
	if req.Transport != "ssh" {
		t.Fatalf("expected transport ssh, got %q", req.Transport)
	}
	if req.TargetHost != "ops@127.0.0.1" {
		t.Fatalf("expected target host ops@127.0.0.1, got %q", req.TargetHost)
	}
	if req.TargetEnv != "prod" {
		t.Fatalf("expected target env prod, got %q", req.TargetEnv)
	}
	if req.TargetID != "prod-web" {
		t.Fatalf("expected target id prod-web, got %q", req.TargetID)
	}
	if req.Path != "ssh://ops@127.0.0.1" {
		t.Fatalf("expected path ssh://ops@127.0.0.1, got %q", req.Path)
	}
}
