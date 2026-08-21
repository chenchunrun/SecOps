package connectors

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Credential struct {
	Token     string
	ExpiresAt time.Time
}

type CredentialProvider interface {
	Credential(context.Context, Manifest) (Credential, error)
}

type TransportRequest struct {
	Method  string
	Path    string
	Headers map[string]string
	Body    []byte
}

type TransportResponse struct {
	StatusCode int
	Body       []byte
}

type Transport interface {
	Do(context.Context, TransportRequest) (TransportResponse, error)
}

type AuditEvent struct {
	Connector  string
	Operation  string
	Risk       string
	ApprovalID string
}

type Auditor interface {
	Record(context.Context, AuditEvent) error
}

type ExecuteRequest struct {
	Operation  string
	Payload    []byte
	ApprovalID string
}

type Result struct {
	Connector string `json:"connector"`
	Operation string `json:"operation"`
	Body      []byte `json:"body"`
}

type Client struct {
	manifest    Manifest
	credentials CredentialProvider
	transport   Transport
	auditor     Auditor
	sleep       func(context.Context, time.Duration) error
}

func NewClient(manifest Manifest, credentials CredentialProvider, transport Transport, auditor Auditor) (*Client, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	if credentials == nil || transport == nil || auditor == nil {
		return nil, errors.New("initialize connector client: credentials, transport, and auditor are required")
	}
	return &Client{
		manifest: manifest, credentials: credentials, transport: transport, auditor: auditor,
		sleep: func(ctx context.Context, duration time.Duration) error {
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}, nil
}

func (c *Client) Execute(ctx context.Context, request ExecuteRequest) (Result, error) {
	operation, ok := c.manifest.Operation(request.Operation)
	if !ok {
		return Result{}, fmt.Errorf("connector operation %q is not declared", request.Operation)
	}
	if operation.SideEffect {
		if request.ApprovalID == "" {
			return Result{}, errors.New("connector side-effect operation requires approval")
		}
		if err := c.auditor.Record(ctx, AuditEvent{Connector: c.manifest.Name, Operation: operation.Name, Risk: operation.Risk, ApprovalID: request.ApprovalID}); err != nil {
			return Result{}, fmt.Errorf("audit connector operation: %w", err)
		}
	}
	credential, err := c.credentials.Credential(ctx, c.manifest)
	if err != nil {
		return Result{}, fmt.Errorf("obtain connector credential: %w", err)
	}
	if credential.Token == "" || !credential.ExpiresAt.After(time.Now()) {
		return Result{}, errors.New("connector credential is empty or expired")
	}
	transportRequest := TransportRequest{
		Method: operation.Method, Path: operation.Path, Body: append([]byte(nil), request.Payload...),
		Headers: map[string]string{"Authorization": "Bearer " + credential.Token, "X-API-Version": c.manifest.ProviderAPI},
	}
	var response TransportResponse
	for attempt := 0; attempt <= c.manifest.RateLimit.MaxRetries; attempt++ {
		response, err = c.transport.Do(ctx, transportRequest)
		if err == nil && response.StatusCode >= 200 && response.StatusCode < 300 {
			body := []byte(strings.ReplaceAll(string(response.Body), credential.Token, "[REDACTED]"))
			return Result{Connector: c.manifest.Name, Operation: operation.Name, Body: body}, nil
		}
		if attempt == c.manifest.RateLimit.MaxRetries || (err == nil && response.StatusCode != 429 && response.StatusCode < 500) {
			break
		}
		if sleepErr := c.sleep(ctx, c.manifest.RateLimit.Backoff*time.Duration(1<<attempt)); sleepErr != nil {
			return Result{}, sleepErr
		}
	}
	if err != nil {
		return Result{}, fmt.Errorf("connector transport failed: %w", err)
	}
	return Result{}, fmt.Errorf("connector returned status %d", response.StatusCode)
}

func (c *Client) Health(ctx context.Context) error {
	credential, err := c.credentials.Credential(ctx, c.manifest)
	if err != nil {
		return err
	}
	response, err := c.transport.Do(ctx, TransportRequest{
		Method: "GET", Path: c.manifest.HealthPath,
		Headers: map[string]string{"Authorization": "Bearer " + credential.Token, "X-API-Version": c.manifest.ProviderAPI},
	})
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("connector health returned status %d", response.StatusCode)
	}
	return nil
}
