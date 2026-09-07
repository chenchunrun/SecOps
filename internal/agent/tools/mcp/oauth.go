package mcp

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

// browserOAuth deliberately keeps credentials in memory and never registers
// clients or silently expands scopes. A new connection requires a fresh login.
type browserOAuth struct {
	resource string
	config   config.MCPOAuthConfig
	client   *http.Client
	open     func(string) error
	mu       sync.Mutex
	token    *oauth2.Token
	gate     chan struct{}
}

func optionalOAuthHandler(h *browserOAuth) auth.OAuthHandler {
	if h == nil {
		return nil
	}
	return h
}

func oauthURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return nil, fmt.Errorf("OAuth requires an HTTPS URL without credentials, query or fragment")
	}
	return u, nil
}

func newBrowserOAuth(m config.MCPConfig) (*browserOAuth, error) {
	if m.Type != config.MCPHttp || m.OAuth == nil || strings.TrimSpace(m.OAuth.ClientID) == "" {
		return nil, fmt.Errorf("OAuth requires HTTP MCP and a preregistered public client ID")
	}
	resource, err := oauthURL(m.URL)
	if err != nil {
		return nil, err
	}
	issuer, err := oauthURL(m.OAuth.Issuer)
	if err != nil {
		return nil, err
	}
	for k := range m.Headers {
		if strings.EqualFold(k, "Authorization") {
			return nil, fmt.Errorf("OAuth cannot be combined with an Authorization header")
		}
	}
	client := &http.Client{
		Timeout:       30 * time.Second,
		Transport:     oauthOriginTransport{origins: []string{resource.Scheme + "://" + resource.Host, issuer.Scheme + "://" + issuer.Host}, base: http.DefaultTransport},
		CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("OAuth HTTP redirects are disabled") },
	}
	return &browserOAuth{resource: m.URL, config: *m.OAuth, client: client, open: browser.OpenURL, gate: make(chan struct{}, 1)}, nil
}

// oauthOriginTransport prevents discovered URLs from reaching unconfigured
// origins. It never inherits MCP custom headers for discovery/token requests.
type oauthOriginTransport struct {
	origins []string
	base    http.RoundTripper
}

func (t oauthOriginTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.User != nil || r.URL.Scheme != "https" || !slices.Contains(t.origins, r.URL.Scheme+"://"+r.URL.Host) {
		return nil, fmt.Errorf("OAuth endpoint is outside configured origins")
	}
	return t.base.RoundTrip(r)
}

func (h *browserOAuth) TokenSource(context.Context) (oauth2.TokenSource, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.token.Valid() {
		return nil, nil
	}
	return oauth2.StaticTokenSource(h.token), nil
}

func (h *browserOAuth) Authorize(ctx context.Context, req *http.Request, resp *http.Response) error {
	defer resp.Body.Close()
	select {
	case h.gate <- struct{}{}:
		defer func() { <-h.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if req.URL.String() != h.resource || resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("MCP OAuth requires a 401 from the configured resource; scope escalation is not automatic")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	challenges, err := oauthex.ParseWWWAuthenticate(resp.Header.Values("WWW-Authenticate"))
	if err != nil {
		return fmt.Errorf("invalid OAuth challenge")
	}
	u, _ := url.Parse(h.resource)
	u.Path = "/.well-known/oauth-protected-resource" + u.Path
	u.RawPath = ""
	metadataURL := u.String()
	for _, c := range challenges {
		if c.Scheme == "bearer" && c.Params["resource_metadata"] != "" {
			metadataURL = c.Params["resource_metadata"]
			break
		}
	}
	prm, err := oauthex.GetProtectedResourceMetadata(ctx, metadataURL, h.resource, h.client)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || prm == nil || !slices.Contains(prm.AuthorizationServers, h.config.Issuer) {
		return fmt.Errorf("MCP resource metadata does not validate the configured issuer")
	}
	asm, err := auth.GetAuthServerMetadata(ctx, h.config.Issuer, h.client)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || asm == nil || asm.Issuer != h.config.Issuer || !slices.Contains(asm.CodeChallengeMethodsSupported, "S256") {
		return fmt.Errorf("OAuth issuer metadata must validate and advertise S256 PKCE")
	}
	issuer, _ := url.Parse(h.config.Issuer)
	for _, endpoint := range []string{asm.AuthorizationEndpoint, asm.TokenEndpoint} {
		u, err := oauthURL(endpoint)
		if err != nil || u.Host != issuer.Host {
			return fmt.Errorf("OAuth endpoints must belong to the configured issuer origin")
		}
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for OAuth callback: %w", err)
	}
	defer listener.Close()
	cfg := &oauth2.Config{ClientID: h.config.ClientID, RedirectURL: "http://" + listener.Addr().String() + "/callback", Scopes: slices.Clone(h.config.Scopes), Endpoint: oauth2.Endpoint{AuthURL: asm.AuthorizationEndpoint, TokenURL: asm.TokenEndpoint, AuthStyle: oauth2.AuthStyleInParams}}
	state, verifier := rand.Text(), oauth2.GenerateVerifier()
	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("resource", h.resource))
	code, err := receiveOAuthCode(ctx, listener, state, h.config.Issuer, asm.AuthorizationResponseIssParameterSupported, func() error { return h.open(authURL) })
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, h.client)
	token, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier), oauth2.SetAuthURLParam("resource", h.resource))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("OAuth token exchange failed; credentials were not saved")
	}
	if !strings.EqualFold(token.TokenType, "Bearer") || !token.Valid() {
		return fmt.Errorf("OAuth server returned an invalid bearer token")
	}
	h.mu.Lock()
	// Do not retain the OAuth library's raw response extras: they may contain
	// refresh tokens or other credentials even after clearing RefreshToken.
	h.token = &oauth2.Token{AccessToken: token.AccessToken, TokenType: token.TokenType, Expiry: token.Expiry}
	h.mu.Unlock()
	return nil
}

func receiveOAuthCode(ctx context.Context, listener net.Listener, state, issuer string, requireIssuer bool, open func() error) (string, error) {
	result := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || r.Method != http.MethodGet || r.Host != listener.Addr().String() || len(q["state"]) != 1 || q.Get("state") != state {
			http.Error(w, "Invalid callback", http.StatusBadRequest)
			return
		}
		if len(q["iss"]) > 1 || (requireIssuer && q.Get("iss") == "") || (q.Get("iss") != "" && q.Get("iss") != issuer) {
			http.Error(w, "Invalid issuer", http.StatusBadRequest)
			return
		}
		code := q.Get("code")
		if q.Get("error") != "" {
			code = ""
		} else if len(q["code"]) != 1 || code == "" {
			http.Error(w, "Missing code", http.StatusBadRequest)
			return
		}
		select {
		case result <- code:
		default:
		}
		fmt.Fprintln(w, "Authorization response received. You may close this window.")
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 16 * 1024}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	defer func() { _ = server.Close(); <-done }()
	if err := open(); err != nil {
		return "", fmt.Errorf("could not open OAuth browser")
	}
	select {
	case code := <-result:
		if code == "" {
			return "", fmt.Errorf("OAuth authorization denied")
		}
		return code, nil
	case <-ctx.Done():
		return "", ctx.Err()
	case <-done:
		return "", fmt.Errorf("OAuth callback listener stopped")
	}
}
