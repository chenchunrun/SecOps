package connectors

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Credential struct {
	Token     string
	ExpiresAt time.Time
	Scheme    string
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
	SessionID  string
}

// ApprovalRequest binds approval to the exact operation and payload.
type ApprovalRequest struct {
	ApprovalID  string
	SessionID   string
	Connector   string
	Operation   string
	Path        string
	PayloadHash string
}

// ApprovalVerifier validates approval identity, scope, expiry and revocation.
type ApprovalVerifier interface {
	VerifyApproval(context.Context, ApprovalRequest) error
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
	approvals   ApprovalVerifier
	sleep       func(context.Context, time.Duration) error
}

func NewClient(manifest Manifest, credentials CredentialProvider, transport Transport, auditor Auditor, approvals ...ApprovalVerifier) (*Client, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	if credentials == nil || transport == nil || auditor == nil {
		return nil, errors.New("initialize connector client: credentials, transport, and auditor are required")
	}
	var verifier ApprovalVerifier
	if len(approvals) > 0 {
		verifier = approvals[0]
	}
	return &Client{
		approvals: verifier,
		manifest:  manifest, credentials: credentials, transport: transport, auditor: auditor,
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
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	request.Payload = append([]byte(nil), request.Payload...)
	operation, ok := c.manifest.Operation(request.Operation)
	if !ok {
		return Result{}, fmt.Errorf("connector operation %q is not declared", request.Operation)
	}
	if operation.SideEffect {
		if request.ApprovalID == "" {
			return Result{}, errors.New("connector side-effect operation requires approval")
		}
		if c.approvals == nil || request.SessionID == "" {
			return Result{}, errors.New("connector write requires an approval verifier and session")
		}
		if err := c.approvals.VerifyApproval(ctx, ApprovalRequest{
			ApprovalID: request.ApprovalID, SessionID: request.SessionID,
			Connector: c.manifest.Name, Operation: operation.Name, Path: operation.Path,
			PayloadHash: fmt.Sprintf("%x", sha256.Sum256(request.Payload)),
		}); err != nil {
			return Result{}, fmt.Errorf("verify connector approval: %w", err)
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
	scheme := credential.Scheme
	if scheme == "" {
		scheme = "Bearer"
	}
	if scheme != "Bearer" && scheme != "ApiKey" {
		return Result{}, errors.New("unsupported credential scheme")
	}
	transportRequest := TransportRequest{
		Method: operation.Method, Path: operation.Path, Body: append([]byte(nil), request.Payload...),
		Headers: map[string]string{"Authorization": scheme + " " + credential.Token, "X-API-Version": c.manifest.ProviderAPI},
	}
	var response TransportResponse
	maxRetries := c.manifest.RateLimit.MaxRetries
	// A transport failure may occur after a write committed. Never replay it.
	if operation.SideEffect {
		maxRetries = 0
	}
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		// Credentials and auditing may take time. Revalidate immediately before a write.
		if operation.SideEffect {
			if err := c.approvals.VerifyApproval(ctx, ApprovalRequest{
				ApprovalID: request.ApprovalID, SessionID: request.SessionID,
				Connector: c.manifest.Name, Operation: operation.Name, Path: operation.Path,
				PayloadHash: fmt.Sprintf("%x", sha256.Sum256(request.Payload)),
			}); err != nil {
				return Result{}, fmt.Errorf("revalidate connector approval: %w", err)
			}
		}
		response, err = c.transport.Do(ctx, transportRequest)
		if err == nil && response.StatusCode >= 200 && response.StatusCode < 300 {
			body := []byte(strings.ReplaceAll(string(response.Body), credential.Token, "[REDACTED]"))
			return Result{Connector: c.manifest.Name, Operation: operation.Name, Body: body}, nil
		}
		if attempt == maxRetries || (err == nil && response.StatusCode != 429 && response.StatusCode < 500) {
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
