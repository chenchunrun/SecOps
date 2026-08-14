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
