package connectors

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type apiKeyCredentials struct{}

func TestPrivateCATransport(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	transport, err := NewHTTPTransport(server.URL)
	require.NoError(t, err)
	_, err = transport.Do(t.Context(), TransportRequest{Method: "GET", Path: "/"})
	require.Error(t, err)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	transport, err = NewHTTPTransportWithCA(server.URL, ca)
	require.NoError(t, err)
	response, err := transport.Do(t.Context(), TransportRequest{Method: "GET", Path: "/"})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	for _, invalid := range [][]byte{{}, []byte("invalid")} {
		_, err := NewHTTPTransportWithCA(server.URL, invalid)
		require.ErrorContains(t, err, "no valid certificates")
	}
}

func (apiKeyCredentials) Credential(context.Context, Manifest) (Credential, error) {
	return Credential{Token: "test-key", ExpiresAt: time.Now().Add(time.Minute), Scheme: "ApiKey"}, nil
}

func TestElasticReadOnlyHTTPContract(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/alerts-test/_search", r.URL.Path)
		require.Equal(t, "ApiKey test-key", r.Header.Get("Authorization"))
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		fmt.Fprint(w, `{"timed_out":false,"_shards":{"failed":0},"hits":{"total":{"value":3,"relation":"eq"}}}`)
	}))
	defer server.Close()
	transport, err := NewHTTPTransport(server.URL)
	require.NoError(t, err)
	transport.client.Transport = server.Client().Transport
	client, err := NewElasticReadClient("alerts-test", apiKeyCredentials{}, transport, &fakeAuditor{})
	require.NoError(t, err)
	result, err := CheckElastic(t.Context(), client)
	require.NoError(t, err)
	require.EqualValues(t, 3, result.Documents)
	_, err = client.Execute(t.Context(), ExecuteRequest{Operation: "update_case"})
	require.ErrorContains(t, err, "not declared")
}

func TestTransportRejectsRedirectsAndLargeResponses(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://example.invalid/", http.StatusTemporaryRedirect)
			return
		}
		fmt.Fprint(w, strings.Repeat("x", maximumResponseBytes+1))
	}))
	defer server.Close()
	transport, err := NewHTTPTransport(server.URL)
	require.NoError(t, err)
	transport.client.Transport = server.Client().Transport
	result, err := transport.Do(t.Context(), TransportRequest{Method: "GET", Path: "/redirect"})
	require.NoError(t, err)
	require.Equal(t, http.StatusTemporaryRedirect, result.StatusCode)
	_, err = transport.Do(t.Context(), TransportRequest{Method: "GET", Path: "/large"})
	require.ErrorContains(t, err, "size limit")
	_, err = transport.Do(t.Context(), TransportRequest{Method: "GET", Path: "https://other.invalid/"})
	require.Error(t, err)
	for _, endpoint := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/path"} {
		_, err := NewHTTPTransport(endpoint)
		require.Error(t, err)
	}
}

func TestElasticRejectsIncompleteResponses(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{}`, `not-json`, `{"timed_out":true,"_shards":{"failed":0},"hits":{"total":{"value":1,"relation":"eq"}}}`, `{"timed_out":false,"_shards":{"failed":1},"hits":{"total":{"value":1,"relation":"eq"}}}`} {
		client, err := NewElasticReadClient("alerts-test", apiKeyCredentials{}, &fakeTransport{responses: []TransportResponse{{StatusCode: 200, Body: []byte(body)}}}, &fakeAuditor{})
		require.NoError(t, err)
		_, err = CheckElastic(t.Context(), client)
		require.Error(t, err)
	}
}

type approvalStoreFunc func(context.Context, string) (ApprovalRecord, error)

func (f approvalStoreFunc) GetApproval(ctx context.Context, id string) (ApprovalRecord, error) {
	return f(ctx, id)
}

func TestStoredApprovalScopeExpiryAndRevocation(t *testing.T) {
	t.Parallel()
	scope := ApprovalRequest{ApprovalID: "a", SessionID: "s", Connector: "c", Operation: "write", Path: "/target", PayloadHash: "digest"}
	record := ApprovalRecord{Scope: scope, ApprovedBy: "operator", NotBefore: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Minute)}
	verifier := StoredApprovalVerifier{Store: approvalStoreFunc(func(context.Context, string) (ApprovalRecord, error) { return record, nil })}
	require.NoError(t, verifier.VerifyApproval(t.Context(), scope))
	changed := scope
	changed.PayloadHash = "other"
	require.Error(t, verifier.VerifyApproval(t.Context(), changed))
	changed = scope
	changed.SessionID = "other"
	require.Error(t, verifier.VerifyApproval(t.Context(), changed))
	record.Revoked = true
	require.Error(t, verifier.VerifyApproval(t.Context(), scope))
	record.Revoked = false
	record.ExpiresAt = time.Now().Add(-time.Second)
	require.Error(t, verifier.VerifyApproval(t.Context(), scope))
}
