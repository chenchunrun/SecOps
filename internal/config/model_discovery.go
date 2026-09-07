package config

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"charm.land/catwalk/pkg/catwalk"
)

const modelDiscoveryLimit = 1 << 20

// discoverModels returns a new catalog, preserving every manually configured
// model. It performs no writes and never follows redirects with credentials.
func discoverModels(ctx context.Context, p ProviderConfig, resolver VariableResolver) ([]catwalk.Model, error) {
	d := p.ModelDiscovery
	if d == nil || (p.Type != catwalk.TypeOpenAICompat && p.Type != catwalk.TypeOpenAI) || d.ContextWindow <= 0 || d.DefaultMaxTokens <= 0 || d.DefaultMaxTokens >= d.ContextWindow {
		return nil, fmt.Errorf("model discovery requires an OpenAI-compatible provider and valid explicit token limits")
	}
	base, err := resolver.ResolveValue(p.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("could not resolve model discovery endpoint")
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid model discovery endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	localHTTP := u.Scheme == "http" && ip != nil && ip.IsLoopback()
	if u.Scheme != "https" && !localHTTP {
		return nil, fmt.Errorf("model discovery requires HTTPS, or HTTP on a literal loopback address")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/models"
	u.RawPath = ""
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not create model discovery request")
	}
	for key, value := range p.ExtraHeaders {
		resolved, err := resolver.ResolveValue(value)
		if err != nil {
			return nil, fmt.Errorf("could not resolve model discovery header")
		}
		req.Header.Set(key, resolved)
	}
	key, err := resolver.ResolveValue(p.APIKey)
	if err != nil {
		return nil, fmt.Errorf("could not resolve model discovery API key")
	}
	if key != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("model discovery redirects are disabled")
	}}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("model discovery request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("model discovery returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, modelDiscoveryLimit+1))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("could not read model discovery response")
	}
	if len(body) > modelDiscoveryLimit {
		return nil, fmt.Errorf("model discovery response exceeds 1 MiB")
	}
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("model discovery response is not valid UTF-8")
	}
	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.Data == nil || len(result.Data) > 4096 {
		return nil, fmt.Errorf("invalid model discovery response")
	}
	models := slices.Clone(p.Models)
	seen := make(map[string]bool, len(models))
	for _, m := range models {
		seen[m.ID] = true
	}
	var added []catwalk.Model
	for _, entry := range result.Data {
		id := entry.ID
		if id == "" || len(id) > 256 || !utf8.ValidString(id) || strings.ContainsFunc(id, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
			return nil, fmt.Errorf("invalid model ID in discovery response")
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		added = append(added, catwalk.Model{ID: id, Name: id, ContextWindow: d.ContextWindow, DefaultMaxTokens: d.DefaultMaxTokens})
	}
	slices.SortFunc(added, func(a, b catwalk.Model) int { return strings.Compare(a.ID, b.ID) })
	if len(models)+len(added) == 0 {
		return nil, fmt.Errorf("model discovery returned no models")
	}
	return append(models, added...), nil
}
