package config

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"charm.land/catwalk/pkg/catwalk"
	"github.com/chenchunrun/SecOps/internal/csync"
	"github.com/chenchunrun/SecOps/internal/env"
	"github.com/stretchr/testify/require"
)

func discoveryProvider(endpoint string) ProviderConfig {
	return ProviderConfig{ID: "private", Type: catwalk.TypeOpenAICompat, BaseURL: endpoint + "/v1/", ModelDiscovery: &ModelDiscoveryConfig{ContextWindow: 8192, DefaultMaxTokens: 1024}}
}

func TestDiscoverModels(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/models", r.URL.Path)
		require.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
		require.Equal(t, "tenant", r.Header.Get("X-Tenant"))
		fmt.Fprint(w, `{"data":[{"id":"z"},{"id":"manual"},{"id":"a"},{"id":"a"}]}`)
	}))
	defer server.Close()
	p := discoveryProvider(server.URL)
	p.APIKey = "$PRIVATE_KEY"
	p.ExtraHeaders = map[string]string{"X-Tenant": "$TENANT"}
	p.Models = []catwalk.Model{{ID: "manual", Name: "My model", ContextWindow: 32000, CanReason: true}}
	resolver := NewEnvironmentVariableResolver(env.NewFromMap(map[string]string{"PRIVATE_KEY": "secret", "TENANT": "tenant"}))
	models, err := discoverModels(t.Context(), p, resolver)
	require.NoError(t, err)
	require.Len(t, models, 3)
	require.Equal(t, p.Models[0], models[0])
	require.Equal(t, "a", models[1].ID)
	require.Equal(t, int64(8192), models[1].ContextWindow)
	require.False(t, models[1].CanReason)
	require.False(t, models[1].SupportsImages)
	require.Len(t, p.Models, 1)
}

func TestDiscoveryRejectsUnsafeResponses(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{}`, `{"data":null}`, `{"data":[]}`, `{"data":[{"id":""}]}`, `{"data":[{"id":"bad\u001b[31m"}]}`, `{"data":[{"id":"x y"}]}`, `{"data":[]} {}`, strings.Repeat("x", modelDiscoveryLimit+1), `{"data":[` + strings.Repeat(`{"id":"x"},`, 4096) + `{"id":"last"}]}`} {
		t.Run(fmt.Sprint(len(body), body[:min(15, len(body))]), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer server.Close()
			_, err := discoverModels(t.Context(), discoveryProvider(server.URL), NewEnvironmentVariableResolver(env.NewFromMap(nil)))
			require.Error(t, err)
		})
	}
}

func TestDiscoveryRedirectAndErrors(t *testing.T) {
	t.Parallel()
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer target.Close()
	for _, status := range []int{302, 401, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", target.URL)
			w.WriteHeader(status)
			fmt.Fprint(w, "secret-server-detail")
		}))
		_, err := discoverModels(t.Context(), discoveryProvider(server.URL), NewEnvironmentVariableResolver(env.NewFromMap(nil)))
		server.Close()
		require.Error(t, err)
		require.NotContains(t, err.Error(), "secret-server-detail")
	}
	require.False(t, reached.Load())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := discoverModels(ctx, discoveryProvider(target.URL), NewEnvironmentVariableResolver(env.NewFromMap(nil)))
	require.ErrorIs(t, err, context.Canceled)
	for _, endpoint := range []string{"http://private.example", "https://user:secret@private.example", "https://private.example?key=secret"} {
		p := discoveryProvider(endpoint)
		_, err := discoverModels(t.Context(), p, NewEnvironmentVariableResolver(env.NewFromMap(nil)))
		require.Error(t, err)
	}
}

func TestDiscoveryRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{\"data\":[{\"id\":\"bad\xff\"}]}")
	}))
	defer server.Close()
	_, err := discoverModels(t.Context(), discoveryProvider(server.URL), NewEnvironmentVariableResolver(env.NewFromMap(nil)))
	require.ErrorContains(t, err, "not valid UTF-8")
}

func TestDiscoveryStartupCatalogAndFallback(t *testing.T) {
	t.Parallel()
	var failing atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(503)
			return
		}
		fmt.Fprint(w, `{"data":[{"id":"private-model"}]}`)
	}))
	defer server.Close()
	environment := env.NewFromMap(nil)
	resolver := NewEnvironmentVariableResolver(environment)
	for _, fallback := range []bool{false, true} {
		p := discoveryProvider(server.URL)
		if fallback {
			failing.Store(true)
			p.Models = []catwalk.Model{{ID: "manual", ContextWindow: 8192, DefaultMaxTokens: 1024}}
		}
		cfg := &Config{Options: &Options{}, Providers: csync.NewMap[string, ProviderConfig]()}
		cfg.Providers.Set("private", p)
		require.NoError(t, cfg.configureProviders(testStore(cfg), environment, resolver, nil))
		got, ok := cfg.Providers.Get("private")
		require.True(t, ok)
		require.Len(t, got.Models, 1)
		large, _, err := cfg.defaultModelSelection(nil)
		require.NoError(t, err)
		require.Equal(t, got.Models[0].ID, large.Model)
	}
	cfg := &Config{Options: &Options{}, Providers: csync.NewMap[string, ProviderConfig]()}
	cfg.Providers.Set("private", discoveryProvider(server.URL))
	require.ErrorContains(t, cfg.configureProviders(testStore(cfg), environment, resolver, nil), "HTTP 503")
}

func TestDiscoveryOptOutAndInvalidLimits(t *testing.T) {
	t.Parallel()
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	environment := env.NewFromMap(nil)
	resolver := NewEnvironmentVariableResolver(environment)
	p := discoveryProvider(server.URL)
	p.ModelDiscovery.DefaultMaxTokens = p.ModelDiscovery.ContextWindow
	_, err := discoverModels(t.Context(), p, resolver)
	require.Error(t, err)
	p.ModelDiscovery = nil
	p.Models = []catwalk.Model{{ID: "manual"}}
	cfg := &Config{Options: &Options{}, Providers: csync.NewMap[string, ProviderConfig]()}
	cfg.Providers.Set("private", p)
	require.NoError(t, cfg.configureProviders(testStore(cfg), environment, resolver, nil))
	require.Zero(t, requests.Load())
}
