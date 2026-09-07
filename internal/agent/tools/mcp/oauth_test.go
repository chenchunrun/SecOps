package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/env"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestOAuthConfiguration(t *testing.T) {
	t.Parallel()
	valid := config.MCPConfig{Type: config.MCPHttp, URL: "https://resource.example/mcp", OAuth: &config.MCPOAuthConfig{Issuer: "https://issuer.example", ClientID: "public"}}
	for _, mutate := range []func(*config.MCPConfig){
		func(m *config.MCPConfig) { m.Type = config.MCPSSE },
		func(m *config.MCPConfig) { m.URL = "http://resource.example/mcp" },
		func(m *config.MCPConfig) { m.URL = "https://user:pass@resource.example/mcp" },
		func(m *config.MCPConfig) { m.URL += "?token=secret" },
		func(m *config.MCPConfig) { m.Headers = map[string]string{"authorization": "secret"} },
		func(m *config.MCPConfig) { m.OAuth = &config.MCPOAuthConfig{Issuer: "https://issuer.example"} },
	} {
		m := valid
		mutate(&m)
		_, err := newBrowserOAuth(m)
		require.Error(t, err)
	}
	resolver := config.NewEnvironmentVariableResolver(env.NewFromMap(nil))
	transport, err := createTransport(t.Context(), valid, resolver)
	require.NoError(t, err)
	httpTransport := transport.(*mcp.StreamableClientTransport)
	require.NotNil(t, httpTransport.OAuthHandler)
	require.Error(t, httpTransport.HTTPClient.CheckRedirect(nil, nil))
	require.Equal(t, 5*time.Minute, mcpTimeout(valid))
	valid.OAuth = nil
	transport, err = createTransport(t.Context(), valid, resolver)
	require.NoError(t, err)
	require.Nil(t, transport.(*mcp.StreamableClientTransport).OAuthHandler)
}

func TestOAuthFlow(t *testing.T) {
	t.Parallel()
	for _, scenario := range []string{"success", "missing_pkce", "wrong_resource", "wrong_issuer", "foreign_endpoint", "token_error"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			var endpoint, challenge string
			mux := http.NewServeMux()
			mcpServer := mcp.NewServer(&mcp.Implementation{Name: "oauth-test", Version: "1"}, nil)
			mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, &mcp.StreamableHTTPOptions{Stateless: true})
			mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer access" {
					w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+endpoint+`/.well-known/oauth-protected-resource/mcp"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				mcpHandler.ServeHTTP(w, r)
			})
			mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				require.Empty(t, r.Header.Get("Authorization"))
				resource, issuer := endpoint+"/mcp", endpoint
				if scenario == "wrong_resource" {
					resource += "/other"
				}
				if scenario == "wrong_issuer" {
					issuer = "https://untrusted.example"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"resource": resource, "authorization_servers": []string{issuer}})
			})
			mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				pkce := []string{"S256"}
				if scenario == "missing_pkce" {
					pkce = nil
				}
				tokenURL := endpoint + "/token"
				if scenario == "foreign_endpoint" {
					tokenURL = "https://untrusted.example/token"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"issuer": endpoint, "authorization_endpoint": endpoint + "/authorize", "token_endpoint": tokenURL, "code_challenge_methods_supported": pkce, "authorization_response_iss_parameter_supported": true})
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				require.Equal(t, "authorization_code", r.Form.Get("grant_type"))
				require.Equal(t, "test-code", r.Form.Get("code"))
				require.Equal(t, "public", r.Form.Get("client_id"))
				require.Equal(t, endpoint+"/mcp", r.Form.Get("resource"))
				require.Equal(t, challenge, oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")))
				w.Header().Set("Content-Type", "application/json")
				if scenario == "token_error" {
					w.WriteHeader(400)
					fmt.Fprint(w, `{"error":"secret-server-detail"}`)
					return
				}
				fmt.Fprint(w, `{"access_token":"access","token_type":"Bearer","expires_in":3600,"refresh_token":"discard"}`)
			})
			server := httptest.NewTLSServer(mux)
			defer server.Close()
			endpoint = server.URL
			h, err := newBrowserOAuth(config.MCPConfig{Type: config.MCPHttp, URL: endpoint + "/mcp", OAuth: &config.MCPOAuthConfig{Issuer: endpoint, ClientID: "public", Scopes: []string{"read"}}})
			require.NoError(t, err)
			h.client.Transport = oauthOriginTransport{origins: []string{endpoint}, base: server.Client().Transport}
			opened := false
			h.open = func(raw string) error {
				opened = true
				u, err := url.Parse(raw)
				require.NoError(t, err)
				q := u.Query()
				require.Equal(t, "S256", q.Get("code_challenge_method"))
				require.Equal(t, endpoint+"/mcp", q.Get("resource"))
				require.Equal(t, "read", q.Get("scope"))
				challenge = q.Get("code_challenge")
				callback := q.Get("redirect_uri")
				for _, query := range []url.Values{
					{"code": {"bad"}, "state": {"wrong"}, "iss": {endpoint}},
					{"code": {"bad"}, "state": {q.Get("state")}, "iss": {"https://wrong.example"}},
					{"code": {"test-code"}, "state": {q.Get("state")}, "iss": {endpoint}},
				} {
					request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, callback+"?"+query.Encode(), nil)
					require.NoError(t, err)
					resp, err := http.DefaultClient.Do(request)
					require.NoError(t, err)
					resp.Body.Close()
					if query.Get("code") == "bad" {
						require.Equal(t, 400, resp.StatusCode)
					} else {
						require.Equal(t, 200, resp.StatusCode)
					}
				}
				return nil
			}
			req, err := http.NewRequestWithContext(t.Context(), "POST", h.resource, nil)
			require.NoError(t, err)
			resp := &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}
			if scenario == "success" {
				client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
				session, connectErr := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: h.resource, HTTPClient: h.client, OAuthHandler: h, DisableStandaloneSSE: true}, nil)
				require.NoError(t, connectErr)
				defer session.Close()
				_, err = session.ListTools(t.Context(), nil)
			} else {
				err = h.Authorize(t.Context(), req, resp)
			}
			if scenario != "success" {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "secret-server-detail")
				require.Equal(t, scenario == "token_error", opened)
				return
			}
			require.NoError(t, err)
			source, err := h.TokenSource(t.Context())
			require.NoError(t, err)
			token, err := source.Token()
			require.NoError(t, err)
			require.Equal(t, "access", token.AccessToken)
			require.Empty(t, token.RefreshToken)
			require.Nil(t, token.Extra("refresh_token"))
			h.token.Expiry = time.Now().Add(-time.Minute)
			source, err = h.TokenSource(t.Context())
			require.NoError(t, err)
			require.Nil(t, source)
		})
	}
}

func TestOAuthCallbackCancellation(t *testing.T) {
	t.Parallel()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	_, err = receiveOAuthCode(ctx, listener, "state", "https://issuer.example", true, func() error { cancel(); return nil })
	require.ErrorIs(t, err, context.Canceled)
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp4", listener.Addr().String())
	if conn != nil {
		conn.Close()
	}
	require.Error(t, err)
}

func TestOAuthOriginIsolation(t *testing.T) {
	t.Parallel()
	transport := oauthOriginTransport{origins: []string{"https://trusted.example"}, base: http.DefaultTransport}
	for _, target := range []string{"https://untrusted.example/token", "http://trusted.example/token", "https://user:secret@trusted.example/token"} {
		req, err := http.NewRequestWithContext(t.Context(), "GET", target, nil)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		if resp != nil {
			resp.Body.Close()
		}
		require.ErrorContains(t, err, "outside configured origins")
	}
}

func TestOAuthWaitingAuthorizationCancels(t *testing.T) {
	t.Parallel()
	h, err := newBrowserOAuth(config.MCPConfig{Type: config.MCPHttp, URL: "https://resource.example/mcp", OAuth: &config.MCPOAuthConfig{Issuer: "https://issuer.example", ClientID: "public"}})
	require.NoError(t, err)
	h.gate <- struct{}{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.resource, nil)
	require.NoError(t, err)
	resp := &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader(""))}
	require.ErrorIs(t, h.Authorize(ctx, req, resp), context.Canceled)
}

func TestOAuthCallbackDenialAndBrowserFailure(t *testing.T) {
	t.Parallel()
	for _, deny := range []bool{false, true} {
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		_, err = receiveOAuthCode(t.Context(), listener, "state", "https://issuer.example", true, func() error {
			if !deny {
				return fmt.Errorf("sensitive browser detail")
			}
			q := url.Values{"state": {"state"}, "iss": {"https://issuer.example"}, "error": {"access_denied"}}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+listener.Addr().String()+"/callback?"+q.Encode(), nil)
			require.NoError(t, err)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			return nil
		})
		require.Error(t, err)
		require.NotContains(t, err.Error(), "sensitive")
		if deny {
			require.ErrorContains(t, err, "denied")
		} else {
			require.ErrorContains(t, err, "browser")
		}
	}
}
