package security

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEngagementAuthorizationValidateScopeCapabilityAndExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	auth := EngagementAuthorization{
		ID:           "auth-1",
		Capability:   "redteam:execute",
		Targets:      []string{"*.example.com", "10.20.0.0/16"},
		AuthorizedBy: "security-admin",
		NotBefore:    now.Add(-time.Minute),
		ExpiresAt:    now.Add(time.Hour),
	}

	require.NoError(t, auth.Validate("redteam:execute", "api.example.com", now))
	require.NoError(t, auth.Validate("redteam:execute", "10.20.4.8", now))
	require.Error(t, auth.Validate("redteam:execute", "example.com.evil.test", now))
	require.Error(t, auth.Validate("redteam:intrude", "api.example.com", now))
	require.Error(t, auth.Validate("redteam:execute", "api.example.com", now.Add(2*time.Hour)))
}

func TestFileEngagementAuthorizationStorePersists(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "authorizations.json")
	store, err := NewFileEngagementAuthorizationStore(path)
	require.NoError(t, err)
	require.NoError(t, store.Put(EngagementAuthorization{ID: "auth-1", Capability: "redteam:execute"}))

	reopened, err := NewFileEngagementAuthorizationStore(path)
	require.NoError(t, err)
	got, err := reopened.Get("auth-1")
	require.NoError(t, err)
	require.Equal(t, "redteam:execute", got.Capability)
}

func TestIssueAndRevokeGlobalEngagementAuthorization(t *testing.T) {
	store := NewInMemoryEngagementAuthorizationStore()
	SetGlobalEngagementAuthorizationStore(store)
	t.Cleanup(func() { SetGlobalEngagementAuthorizationStore(nil) })

	auth, err := IssueGlobalEngagementAuthorization("network:scan", "API.EXAMPLE.COM", "tester", time.Hour)
	if err != nil {
		t.Fatalf("issue authorization: %v", err)
	}
	if err := ValidateGlobalEngagementAuthorization(auth.ID, "network:scan", "api.example.com", time.Now().UTC()); err != nil {
		t.Fatalf("validate authorization: %v", err)
	}
	if err := RevokeGlobalEngagementAuthorization(auth.ID); err != nil {
		t.Fatalf("revoke authorization: %v", err)
	}
	if err := ValidateGlobalEngagementAuthorization(auth.ID, "network:scan", "api.example.com", time.Now().UTC()); err == nil {
		t.Fatal("expected revoked authorization to be denied")
	}
}

func TestSessionEngagementAuthorizationRejectsOtherSessions(t *testing.T) {
	store := NewInMemoryEngagementAuthorizationStore()
	SetGlobalEngagementAuthorizationStore(store)
	t.Cleanup(func() { SetGlobalEngagementAuthorizationStore(nil) })

	auth, err := IssueSessionEngagementAuthorization(
		"session-1",
		"network:scan",
		"api.example.com",
		"tester",
		time.Hour,
	)
	if err != nil {
		t.Fatalf("issue session authorization: %v", err)
	}
	now := time.Now().UTC()
	if err := ValidateGlobalEngagementAuthorizationForSession(auth.ID, "network:scan", "api.example.com", "session-1", now); err != nil {
		t.Fatalf("validate matching session: %v", err)
	}
	if err := ValidateGlobalEngagementAuthorizationForSession(auth.ID, "network:scan", "api.example.com", "session-2", now); err == nil {
		t.Fatal("expected authorization to be denied in another session")
	}
}
