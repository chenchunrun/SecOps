package connectors

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFirstPartyConnectorManifests(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"microsoft-sentinel", "splunk", "elastic", "defender-xdr", "crowdstrike-falcon", "jira"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			manifest, err := LoadManifest(filepath.Join("..", "..", "connectors", name+".yaml"))
			require.NoError(t, err)
			require.Equal(t, name, manifest.Name)
			require.True(t, manifest.Credential.ShortLived)
		})
	}
}

func TestConnectorCredentialsAreInjectedOnlyAtTransportAndRedacted(t *testing.T) {
	t.Parallel()
	transport := &fakeTransport{responses: []TransportResponse{{StatusCode: 200, Body: []byte("result secret-token")}}}
	client := newTestClient(t, transport, &fakeAuditor{})
	result, err := client.Execute(context.Background(), ExecuteRequest{Operation: "query", Payload: []byte("query")})
	require.NoError(t, err)
	require.NotContains(t, string(result.Body), "secret-token")
	require.Equal(t, "Bearer secret-token", transport.requests[0].Headers["Authorization"])
}

func TestConnectorRetriesRateLimitAndDoesNotFabricateFailure(t *testing.T) {
	t.Parallel()
	transport := &fakeTransport{responses: []TransportResponse{{StatusCode: 429}, {StatusCode: 200, Body: []byte("ok")}}}
	client := newTestClient(t, transport, &fakeAuditor{})
	client.sleep = func(context.Context, time.Duration) error { return nil }
	result, err := client.Execute(context.Background(), ExecuteRequest{Operation: "query"})
	require.NoError(t, err)
	require.Equal(t, []byte("ok"), result.Body)
	require.Len(t, transport.requests, 2)

	transport = &fakeTransport{err: errors.New("offline")}
	client = newTestClient(t, transport, &fakeAuditor{})
	client.sleep = func(context.Context, time.Duration) error { return nil }
	result, err = client.Execute(context.Background(), ExecuteRequest{Operation: "query"})
	require.ErrorContains(t, err, "offline")
	require.Empty(t, result.Body)
}

func TestConnectorWritesRequireApprovalAndAudit(t *testing.T) {
	t.Parallel()
	auditor := &fakeAuditor{}
	transport := &fakeTransport{responses: []TransportResponse{{StatusCode: 200}}}
	client := newTestClient(t, transport, auditor)
	_, err := client.Execute(context.Background(), ExecuteRequest{Operation: "write"})
	require.ErrorContains(t, err, "requires approval")
	require.Empty(t, transport.requests)

	_, err = client.Execute(context.Background(), ExecuteRequest{Operation: "write", ApprovalID: "approval-1"})
	require.NoError(t, err)
	require.Equal(t, 1, auditor.calls)
	require.Equal(t, "approval-1", auditor.last.ApprovalID)
}

func newTestClient(t *testing.T, transport Transport, auditor Auditor) *Client {
	t.Helper()
	manifest := Manifest{
		APIVersion: "secops/connectors/v1", Name: "test", Version: "1.0.0", Provider: "test", DataScopes: []string{"alerts:read"},
		Credential: CredentialRequirement{Type: "oauth2", Scopes: []string{"read"}, ShortLived: true}, ProviderAPI: "v1",
		RateLimit: RateLimitPolicy{MaxRetries: 1, BackoffRaw: "1ms", Backoff: time.Millisecond}, HealthPath: "/health", EventSchema: "secops-event-v1",
		Operations: []OperationDescriptor{{Name: "query", Method: "POST", Path: "/query", Risk: "low"}, {Name: "write", Method: "POST", Path: "/write", SideEffect: true, Risk: "high"}},
	}
	client, err := NewClient(manifest, &fakeCredentials{}, transport, auditor)
	require.NoError(t, err)
	return client
}

type fakeCredentials struct{}

func (*fakeCredentials) Credential(context.Context, Manifest) (Credential, error) {
	return Credential{Token: "secret-token", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

type fakeTransport struct {
	responses []TransportResponse
	err       error
	requests  []TransportRequest
}

func (f *fakeTransport) Do(_ context.Context, request TransportRequest) (TransportResponse, error) {
	f.requests = append(f.requests, request)
	if f.err != nil {
		return TransportResponse{}, f.err
	}
	if len(f.responses) == 0 {
		return TransportResponse{StatusCode: 200}, nil
	}
	response := f.responses[0]
	if len(f.responses) > 1 {
		f.responses = f.responses[1:]
	}
	return response, nil
}

type fakeAuditor struct {
	calls int
	last  AuditEvent
}

func (f *fakeAuditor) Record(_ context.Context, event AuditEvent) error {
	f.calls++
	f.last = event
	return nil
}
