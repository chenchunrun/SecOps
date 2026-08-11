package egress

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyDefaultsToDenyAndMatchesTrustedRules(t *testing.T) {
	t.Parallel()

	policy, err := NewPolicy([]Rule{
		{
			ID:             "github-api",
			Protocol:       ProtocolHTTPS,
			Host:           "api.github.com",
			Ports:          []int{443},
			CredentialRefs: []string{"github/actions"},
		},
		{
			ID:       "internal-services",
			Protocol: ProtocolHTTPS,
			Host:     "*.services.example.com",
			Ports:    []int{443, 8443},
		},
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		request     Request
		wantAllowed bool
		wantRuleID  string
	}{
		{
			name: "exact host and credential",
			request: Request{
				Protocol:       ProtocolHTTPS,
				Host:           "API.GITHUB.COM.",
				Port:           443,
				CredentialRefs: []string{"github/actions"},
			},
			wantAllowed: true,
			wantRuleID:  "github-api",
		},
		{
			name: "wildcard subdomain",
			request: Request{
				Protocol: ProtocolHTTPS,
				Host:     "build.services.example.com",
				Port:     8443,
			},
			wantAllowed: true,
			wantRuleID:  "internal-services",
		},
		{
			name: "wildcard excludes apex",
			request: Request{
				Protocol: ProtocolHTTPS,
				Host:     "services.example.com",
				Port:     443,
			},
		},
		{
			name: "protocol denied",
			request: Request{
				Protocol: ProtocolHTTP,
				Host:     "api.github.com",
				Port:     443,
			},
		},
		{
			name: "port denied",
			request: Request{
				Protocol: ProtocolHTTPS,
				Host:     "api.github.com",
				Port:     22,
			},
		},
		{
			name: "credential denied",
			request: Request{
				Protocol:       ProtocolHTTPS,
				Host:           "api.github.com",
				Port:           443,
				CredentialRefs: []string{"production/root"},
			},
		},
		{
			name: "unlisted host denied",
			request: Request{
				Protocol: ProtocolHTTPS,
				Host:     "example.org",
				Port:     443,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decision, authorizeErr := policy.Authorize(tt.request)
			if tt.wantAllowed {
				require.NoError(t, authorizeErr)
				require.True(t, decision.Allowed)
				require.Equal(t, tt.wantRuleID, decision.RuleID)
				require.NotEmpty(t, decision.Reason)
				return
			}
			require.ErrorIs(t, authorizeErr, ErrEgressDenied)
			require.False(t, decision.Allowed)
			require.Empty(t, decision.RuleID)
			require.NotEmpty(t, decision.Reason)
		})
	}
}

func TestPolicyRejectsInvalidRulesAndRequests(t *testing.T) {
	t.Parallel()

	_, err := NewPolicy([]Rule{{ID: "bad", Protocol: ProtocolHTTPS, Host: "", Ports: []int{443}}})
	require.ErrorIs(t, err, ErrInvalidPolicy)

	policy, err := NewPolicy(nil)
	require.NoError(t, err)
	decision, err := policy.Authorize(Request{Protocol: ProtocolHTTPS, Host: "api.github.com", Port: 0})
	require.ErrorIs(t, err, ErrInvalidDestination)
	require.False(t, decision.Allowed)
}
