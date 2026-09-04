package model

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/security"
	"github.com/chenchunrun/SecOps/internal/ui/util"
	"github.com/stretchr/testify/require"
)

func TestParseCapabilityControlCommand(t *testing.T) {
	t.Parallel()

	command, matched, err := parseCapabilityControlCommand("/capabilities")
	require.True(t, matched)
	require.NoError(t, err)
	require.Equal(t, capabilityCommandList, command.kind)

	command, matched, err = parseCapabilityControlCommand("/authorize network:scan --target 10.0.0.8 --ttl 45m")
	require.True(t, matched)
	require.NoError(t, err)
	require.Equal(t, capabilityCommandAuthorize, command.kind)
	require.Equal(t, "network:scan", command.capability)
	require.Equal(t, "10.0.0.8", command.target)
	require.Equal(t, 45*time.Minute, command.ttl)

	command, matched, err = parseCapabilityControlCommand("/revoke network:scan --target=10.0.0.8")
	require.True(t, matched)
	require.NoError(t, err)
	require.Equal(t, capabilityCommandRevoke, command.kind)
	require.Equal(t, "10.0.0.8", command.target)
}

func TestParseCapabilityControlCommandRejectsUnsafeOrInvalidInput(t *testing.T) {
	t.Parallel()

	_, matched, err := parseCapabilityControlCommand("/authorize network:scan")
	require.True(t, matched)
	require.ErrorContains(t, err, "requires --target")

	_, matched, err = parseCapabilityControlCommand("/authorize admin --target '*' ")
	require.True(t, matched)
	require.ErrorContains(t, err, "expected namespace:action")

	_, matched, err = parseCapabilityControlCommand("/authorize network:scan --target 10.0.0.8 --ttl 25h")
	require.True(t, matched)
	require.ErrorContains(t, err, "no more than 24h")

	_, matched, err = parseCapabilityControlCommand("/authorize network:scan --target '*'")
	require.True(t, matched)
	require.ErrorContains(t, err, "bounded target")
}

func TestAuthorizeAndRevokeSessionCapability(t *testing.T) {
	auditStore, err := audit.NewFileAuditStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	require.NoError(t, err)
	audit.SetGlobalStore(auditStore)
	audit.SetGlobalWAL(nil)
	security.SetGlobalEngagementAuthorizationStore(security.NewInMemoryEngagementAuthorizationStore())
	t.Cleanup(func() {
		audit.SetGlobalStore(audit.NewInMemoryAuditStore())
		audit.SetGlobalWAL(nil)
		security.SetGlobalEngagementAuthorizationStore(nil)
	})

	service := permission.NewDefaultService()
	command := capabilityControlCommand{
		kind:       capabilityCommandAuthorize,
		capability: "network:scan",
		target:     "api.example.com",
		ttl:        time.Hour,
	}
	msg := authorizeSessionCapability(service, "session-1", "analyst", command)
	info, ok := msg.(util.InfoMsg)
	require.True(t, ok)
	require.Contains(t, info.Msg, "authorization_id=")
	grant, ok := service.FindSessionCapability("session-1", "analyst", "network:scan", "api.example.com")
	require.True(t, ok)
	require.NotEmpty(t, grant.AuthorizationID)
	previousAuthorizationID := grant.AuthorizationID

	msg = authorizeSessionCapability(service, "session-1", "analyst", command)
	info, ok = msg.(util.InfoMsg)
	require.True(t, ok)
	grant, ok = service.FindSessionCapability("session-1", "analyst", "network:scan", "api.example.com")
	require.True(t, ok)
	require.NotEqual(t, previousAuthorizationID, grant.AuthorizationID)
	require.NoError(t, security.ValidateGlobalEngagementAuthorizationForSession(
		grant.AuthorizationID,
		"network:scan",
		"api.example.com",
		"session-1",
		time.Now().UTC(),
	))
	require.Error(t, security.ValidateGlobalEngagementAuthorizationForSession(
		grant.AuthorizationID,
		"network:scan",
		"api.example.com",
		"session-2",
		time.Now().UTC(),
	))
	require.Error(t, security.ValidateGlobalEngagementAuthorization(
		previousAuthorizationID,
		"network:scan",
		"api.example.com",
		time.Now().UTC(),
	))

	msg = revokeSessionCapability(service, "session-1", "analyst", capabilityControlCommand{
		kind:       capabilityCommandRevoke,
		capability: "network:scan",
		target:     "api.example.com",
	})
	info, ok = msg.(util.InfoMsg)
	require.True(t, ok)
	require.Contains(t, info.Msg, "Revoked 1")
	_, ok = service.FindSessionCapability("session-1", "analyst", "network:scan", "api.example.com")
	require.False(t, ok)

	events, err := auditStore.ListEvents(&audit.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, events, 3)
	require.Equal(t, audit.EventTypeCapabilityGranted, events[0].EventType)
	require.Equal(t, audit.EventTypeCapabilityGranted, events[1].EventType)
	require.Equal(t, audit.EventTypeCapabilityRevoked, events[2].EventType)
}
