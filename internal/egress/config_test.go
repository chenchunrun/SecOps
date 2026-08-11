package egress

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigBuildsValidatedRuntimeDependencies(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "egress.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
  "rules": [{
    "id": "github-api",
    "protocol": "https",
    "host": "api.github.com",
    "ports": [443],
    "credential_refs": ["github/actions"]
  }],
  "credential_environment": {"github/actions": "SECOPS_GITHUB_TOKEN"},
  "max_credential_ttl": "2m",
  "audit_path": "audit/egress.jsonl"
}`), 0o600))

	config, err := LoadConfig(path)
	require.NoError(t, err)
	require.Equal(t, 2*time.Minute, config.MaxCredentialTTL)
	require.Equal(t, filepath.Join(directory, "audit", "egress.jsonl"), config.AuditPath)

	decision, err := config.Policy.Authorize(Request{
		Protocol:       ProtocolHTTPS,
		Host:           "api.github.com",
		Port:           443,
		CredentialRefs: []string{"github/actions"},
	})
	require.NoError(t, err)
	require.True(t, decision.Allowed)
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "egress.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
  "rules": [],
  "credential_environment": {},
  "max_credential_ttl": "1m",
  "audit_path": "egress.jsonl",
  "secret": "must-not-be-accepted"
}`), 0o600))

	_, err := LoadConfig(path)
	require.ErrorIs(t, err, ErrInvalidConfig)
}

func TestEnvironmentSourceResolvesOnlyMappedReferences(t *testing.T) {
	t.Setenv("SECOPS_GITHUB_TOKEN", "transient-secret")

	source, err := NewEnvironmentSource(map[string]string{
		"github/actions": "SECOPS_GITHUB_TOKEN",
	})
	require.NoError(t, err)

	value, err := source.Resolve(context.Background(), "github/actions")
	require.NoError(t, err)
	require.Equal(t, []byte("transient-secret"), value)

	_, err = source.Resolve(context.Background(), "production/root")
	require.ErrorIs(t, err, ErrCredentialUnavailable)
}

func TestEnvironmentSourceRejectsMissingEnvironmentValue(t *testing.T) {
	t.Parallel()

	source, err := NewEnvironmentSource(map[string]string{
		"github/actions": "SECOPS_MISSING_TOKEN",
	})
	require.NoError(t, err)

	_, err = source.Resolve(context.Background(), "github/actions")
	require.ErrorIs(t, err, ErrCredentialUnavailable)
}

func TestEnvironmentSourceHonorsCancellation(t *testing.T) {
	t.Parallel()

	source, err := NewEnvironmentSource(map[string]string{"github/actions": "SECOPS_TOKEN"})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = source.Resolve(ctx, "github/actions")
	require.True(t, errors.Is(err, context.Canceled))
}
