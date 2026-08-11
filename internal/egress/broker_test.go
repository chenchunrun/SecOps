package egress

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type memorySource struct {
	values map[string][]byte
}

func (s memorySource) Resolve(_ context.Context, reference string) ([]byte, error) {
	value, ok := s.values[reference]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return append([]byte(nil), value...), nil
}

func TestBrokerIssuesExpiringRevocableLease(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 11, 1, 2, 3, 0, time.UTC)
	broker, err := NewBroker(
		memorySource{values: map[string][]byte{
			"github/actions": []byte("ghp_abcdefghijklmnopqrstuvwxyz1234567890"),
		}},
		5*time.Minute,
		WithClock(func() time.Time { return now }),
	)
	require.NoError(t, err)

	lease, err := broker.Issue(context.Background(), []Binding{
		{Reference: "github/actions", Environment: "GITHUB_TOKEN"},
	}, 2*time.Minute)
	require.NoError(t, err)
	require.Equal(t, now.Add(2*time.Minute), lease.ExpiresAt())

	environment, err := lease.Environment()
	require.NoError(t, err)
	require.Equal(t, "ghp_abcdefghijklmnopqrstuvwxyz1234567890", environment["GITHUB_TOKEN"])
	environment["GITHUB_TOKEN"] = "modified"
	secondCopy, err := lease.Environment()
	require.NoError(t, err)
	require.Equal(t, "ghp_abcdefghijklmnopqrstuvwxyz1234567890", secondCopy["GITHUB_TOKEN"])

	now = now.Add(3 * time.Minute)
	_, err = lease.Environment()
	require.ErrorIs(t, err, ErrLeaseExpired)

	now = now.Add(-3 * time.Minute)
	lease.Revoke()
	_, err = lease.Environment()
	require.ErrorIs(t, err, ErrLeaseRevoked)
}

func TestBrokerFailsClosed(t *testing.T) {
	t.Parallel()

	source := memorySource{values: map[string][]byte{"known": []byte("secret-value")}}
	broker, err := NewBroker(source, time.Minute)
	require.NoError(t, err)

	tests := []struct {
		name      string
		bindings  []Binding
		ttl       time.Duration
		wantError error
	}{
		{
			name:      "empty bindings",
			ttl:       time.Second,
			wantError: ErrInvalidBinding,
		},
		{
			name:      "invalid environment name",
			bindings:  []Binding{{Reference: "known", Environment: "bad-name"}},
			ttl:       time.Second,
			wantError: ErrInvalidBinding,
		},
		{
			name:      "duplicate environment",
			bindings:  []Binding{{Reference: "known", Environment: "TOKEN"}, {Reference: "known", Environment: "TOKEN"}},
			ttl:       time.Second,
			wantError: ErrInvalidBinding,
		},
		{
			name:      "ttl exceeds maximum",
			bindings:  []Binding{{Reference: "known", Environment: "TOKEN"}},
			ttl:       2 * time.Minute,
			wantError: ErrInvalidLeaseTTL,
		},
		{
			name:      "unknown reference",
			bindings:  []Binding{{Reference: "missing", Environment: "TOKEN"}},
			ttl:       time.Second,
			wantError: ErrCredentialUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lease, issueErr := broker.Issue(context.Background(), tt.bindings, tt.ttl)
			require.ErrorIs(t, issueErr, tt.wantError)
			require.Nil(t, lease)
		})
	}
}
