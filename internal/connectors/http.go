package connectors

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maximumResponseBytes = 4 << 20

// HTTPTransport keeps credentials on one HTTPS origin and bounds responses.
type HTTPTransport struct {
	base   *url.URL
	client *http.Client
}

func NewHTTPTransport(endpoint string) (*HTTPTransport, error) {
	base, err := url.Parse(endpoint)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return nil, errors.New("connector endpoint must be an HTTPS origin without credentials, path or query")
	}
	return &HTTPTransport{base: base, client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (t *HTTPTransport) Do(ctx context.Context, input TransportRequest) (TransportResponse, error) {
	path, err := url.Parse(input.Path)
	if err != nil || path.IsAbs() || path.Host != "" || !strings.HasPrefix(path.Path, "/") || path.Fragment != "" {
		return TransportResponse{}, errors.New("invalid connector operation path")
	}
	target := *t.base
	target.Path, target.RawPath, target.RawQuery = path.Path, path.RawPath, path.RawQuery
	request, err := http.NewRequestWithContext(ctx, input.Method, target.String(), bytes.NewReader(input.Body))
	if err != nil {
		return TransportResponse{}, errors.New("invalid connector HTTP request")
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range input.Headers {
		request.Header.Set(key, value)
	}
	response, err := t.client.Do(request)
	if err != nil {
		return TransportResponse{}, fmt.Errorf("connector HTTP request failed: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil {
		return TransportResponse{}, fmt.Errorf("read connector response: %w", err)
	}
	if len(body) > maximumResponseBytes {
		return TransportResponse{}, errors.New("connector response exceeds size limit")
	}
	return TransportResponse{StatusCode: response.StatusCode, Body: body}, nil
}
