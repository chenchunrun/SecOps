package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chenchunrun/SecOps/internal/security/redact"
)

// redactionRegexes holds the credential patterns used to redact sensitive data
// before exporting audit events to SIEM systems. Covers 13 credential types:
//  1. Bearer token          (Authorization: Bearer xxx)
//  2. Stripe live key       (sk_live_)
//  3. Stripe test key        (sk_test_)
//  4. AWS access key ID      (AKIA*, ASIA*, ABIA*, ACCA*)
//  5. AWS secret access key  (aws_secret_access_key=)
//  6. URL password           (?password=)
//  7. Private key header     (-----BEGIN ... PRIVATE KEY-----)
//  8. GitHub PAT             (ghp_*, github_pat_*)
//  9. GCP service account    (gcp_*, GOOGLE_*, _GOOGLE)
//
// 10. Slack token            (xox[baprs]-*)
// 11. Generic API key        (api_key=, apikey=, api-key=)
// 12. Database DSN           (mysql://, postgres://, mongodb://, redis://)
// 13. JWT token              (eyJ... - JSON Web Token header)
//
// The patterns themselves live in internal/security/redact and are shared with
// the shell command logger; this comment documents the historical coverage for
// SIEM export callers.

// siemHTTPTimeout bounds each SIEM HTTP attempt so a hung receiver cannot block
// the exporter indefinitely.
const siemHTTPTimeout = 30 * time.Second

// maxSIEMResponseBytes caps how much of a SIEM error response is read. The body
// is only used to build error messages, so a small bound is sufficient and
// prevents a hostile or misbehaving endpoint from streaming an unbounded body.
const maxSIEMResponseBytes = 64 * 1024

// redactValue recursively scans and redacts credential patterns from a value.
// Strings are scanned for all known credential patterns; maps and slices are
// traversed recursively; all other values are returned unchanged.
func redactValue(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		return redact.String(val)
	case map[string]interface{}:
		cp := make(map[string]interface{}, len(val))
		for k, v := range val {
			cp[k] = redactValue(v)
		}
		return cp
	case []interface{}:
		cp := make([]interface{}, len(val))
		for i, item := range val {
			cp[i] = redactValue(item)
		}
		return cp
	default:
		return v
	}
}

// redactEvent creates a deep copy of the given event with all credential fields
// redacted before export. The original event is not modified.
// ErrorMsg, ResourcePath, and Reason are also passed through the redaction
// engine because error messages and paths often contain DSNs, tokens, and
// file paths that embed credentials (HIGH-03).
func redactEvent(event *AuditEvent) *AuditEvent {
	if event == nil {
		return nil
	}
	cp := &AuditEvent{
		ID:           event.ID,
		EventType:    event.EventType,
		Timestamp:    event.Timestamp,
		SessionID:    event.SessionID,
		UserID:       event.UserID,
		Username:     event.Username,
		SourceIP:     event.SourceIP,
		Action:       event.Action,
		ResourceType: event.ResourceType,
		ResourceName: event.ResourceName,
		ResourcePath: redact.String(event.ResourcePath),
		Transport:    event.Transport,
		TargetHost:   event.TargetHost,
		TargetEnv:    event.TargetEnv,
		TargetID:     event.TargetID,
		Result:       event.Result,
		ErrorMsg:     redact.String(event.ErrorMsg),
		RiskScore:    event.RiskScore,
		RiskLevel:    event.RiskLevel,
		Severity:     event.Severity,
		Details:      make(map[string]interface{}),
		ApprovalID:   event.ApprovalID,
		ApprovedBy:   event.ApprovedBy,
		ApprovedAt:   event.ApprovedAt,
		Reason:       redact.String(event.Reason),
		Signature:    event.Signature,
	}
	for k, v := range event.Details {
		cp.Details[k] = redactValue(v)
	}
	if event.ChangeData != nil {
		cp.ChangeData = &ChangeData{
			FieldName: event.ChangeData.FieldName,
			OldValue:  redactValue(event.ChangeData.OldValue),
			NewValue:  redactValue(event.ChangeData.NewValue),
		}
	}
	return cp
}

// SIEMExporter defines the interface for SIEM integrations.
type SIEMExporter interface {
	Export(ctx context.Context, events []*AuditEvent) error
}

// SyslogExporter exports redacted audit events to a syslog receiver.
// Messages use a compact RFC5424-style header with the audit event JSON in
// the MSG field. Supported networks are "udp", "tcp", "unix", and "unixgram".
// Network syslog is restricted to loopback destinations; use a local syslog
// daemon or Unix socket for forwarding to remote infrastructure over TLS.
type SyslogExporter struct {
	Network  string // "udp", "tcp", "unix", or "unixgram"
	Address  string // e.g. "127.0.0.1:514"
	AppName  string // defaults to "secops-agent"
	Hostname string // defaults to os.Hostname()
	Facility int    // defaults to 16 (local0)
	Severity int    // defaults to 6 (informational)
}

// Export sends audit events to the configured syslog receiver.
func (e *SyslogExporter) Export(ctx context.Context, events []*AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	network := e.Network
	if network == "" {
		network = "udp"
	}
	if network != "udp" && network != "tcp" && network != "unix" && network != "unixgram" {
		return fmt.Errorf("SyslogExporter: unsupported network %q", network)
	}
	if e.Address == "" {
		return errors.New("SyslogExporter: address is required")
	}
	if err := validateSyslogAddress(network, e.Address); err != nil {
		return err
	}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, e.Address)
	if err != nil {
		return fmt.Errorf("SyslogExporter: failed to connect to %s %s: %w", network, e.Address, err)
	}
	defer conn.Close()

	appName := e.AppName
	if appName == "" {
		appName = "secops-agent"
	}
	appName = sanitizeSyslogHeaderField(appName, 48)

	hostname := e.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
		if hostname == "" {
			hostname = "-"
		}
	}
	hostname = sanitizeSyslogHeaderField(hostname, 255)

	facility := e.Facility
	if facility == 0 {
		facility = 16
	}
	severity := e.Severity
	if severity == 0 {
		severity = 6
	}

	for _, event := range events {
		payload, err := json.Marshal(redactEvent(event))
		if err != nil {
			return fmt.Errorf("SyslogExporter: failed to marshal audit event: %w", err)
		}

		msg := formatSyslogMessage(facility, severity, event.Timestamp, hostname, appName, event.ID, payload)
		if _, err := io.WriteString(conn, msg); err != nil {
			return fmt.Errorf("SyslogExporter: failed to write event %s: %w", event.ID, err)
		}
	}

	return nil
}

func formatSyslogMessage(
	facility int,
	severity int,
	timestamp time.Time,
	hostname string,
	appName string,
	msgID string,
	payload []byte,
) string {
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	msgID = sanitizeSyslogHeaderField(msgID, 32)
	priority := facility*8 + severity
	return fmt.Sprintf(
		"<%d>1 %s %s %s - %s - %s\n",
		priority,
		timestamp.UTC().Format(time.RFC3339),
		hostname,
		appName,
		msgID,
		payload,
	)
}

func validateSyslogAddress(network string, address string) error {
	switch network {
	case "unix", "unixgram":
		if strings.TrimSpace(address) == "" {
			return errors.New("SyslogExporter: unix socket path is required")
		}
		return nil
	case "udp", "tcp":
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("SyslogExporter: invalid address %q: %w", address, err)
		}
		if host == "" || strings.EqualFold(host, "localhost") {
			return nil
		}
		ip := net.ParseIP(host)
		if ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("SyslogExporter: remote %s syslog targets are not allowed without a local forwarder: %s", network, address)
	default:
		return fmt.Errorf("SyslogExporter: unsupported network %q", network)
	}
}

func sanitizeSyslogHeaderField(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}

	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if r < 33 || r > 126 || r == ' ' {
			b.WriteByte('-')
			continue
		}
		b.WriteRune(r)
	}
	sanitized := b.String()
	if sanitized == "" {
		return "-"
	}
	if maxLen > 0 && len(sanitized) > maxLen {
		sanitized = sanitized[:maxLen]
	}
	return sanitized
}

// ELKExporter exports to Elasticsearch/Logstash/Kibana.
// TLSEnabled defaults to true; plaintext HTTP exports are rejected to prevent
// credential exposure. Pass a custom TLSConfig for cert pinning or other options.
type ELKExporter struct {
	Endpoint   string // e.g. "https://localhost:9200"
	Index      string // e.g. "secops-audit"
	Username   string
	Password   string
	TLSEnabled bool        // defaults to true; rejected if false
	TLSConfig  *tls.Config // optional; uses the default TLS settings when nil
}

// Export exports audit events to ELK via HTTP bulk API.
func (e *ELKExporter) Export(ctx context.Context, events []*AuditEvent) error {
	if !e.TLSEnabled {
		return errors.New("ELKExporter: TLS must be enabled to prevent credential exposure over plaintext HTTP")
	}
	if err := validateHTTPSURL("ELKExporter", e.Endpoint); err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}

	var body bytes.Buffer
	for _, event := range events {
		// Action line
		action := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": e.Index,
			},
		}
		actionBytes, err := json.Marshal(action)
		if err != nil {
			return fmt.Errorf("failed to marshal bulk action: %w", err)
		}
		body.Write(actionBytes)
		body.WriteByte('\n')

		// Document line — redact credentials before serialising
		docBytes, err := json.Marshal(redactEvent(event))
		if err != nil {
			return fmt.Errorf("failed to marshal audit event: %w", err)
		}
		body.Write(docBytes)
		body.WriteByte('\n')
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint+"/_bulk", &body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if e.Username != "" && e.Password != "" {
		req.SetBasicAuth(e.Username, e.Password)
	}

	return e.doRequestWithRetry(req)
}

func (e *ELKExporter) doRequestWithRetry(req *http.Request) error {
	const maxRetries = 3

	// Snapshot the body before the retry loop so we can reset it on each
	// attempt — http.Request.Body is consumed on the first Do() call (HIGH-04).
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to buffer request body: %w", err)
		}
	}

	client := &http.Client{Timeout: siemHTTPTimeout}
	if e.TLSConfig != nil {
		if e.TLSConfig.InsecureSkipVerify {
			return fmt.Errorf("ELKExporter: InsecureSkipVerify is prohibited for audit transport")
		}
		client.Transport = &http.Transport{TLSClientConfig: e.TLSConfig}
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			if err := sleepWithContext(req.Context(), backoffDuration(attempt)); err != nil {
				return fmt.Errorf("ELK export aborted: %w", err)
			}
		}

		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}

		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxSIEMResponseBytes))
		resp.Body.Close() // close eagerly, not via defer

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		lastErr = fmt.Errorf("ELK bulk request failed with status %d: %s", resp.StatusCode, string(respBody))
		if resp.StatusCode < 500 {
			return lastErr
		}
	}

	return fmt.Errorf("ELK export failed after %d retries: %w", maxRetries, lastErr)
}

// SplunkExporter exports to Splunk HTTP Event Collector.
// TLSEnabled defaults to true; plaintext HTTP exports are rejected to prevent
// credential exposure. Pass a custom TLSConfig for cert pinning or other options.
type SplunkExporter struct {
	Endpoint   string // e.g. "https://localhost:8088/services/collector"
	Token      string
	Index      string
	TLSEnabled bool        // defaults to true; rejected if false
	TLSConfig  *tls.Config // optional; uses the default TLS settings when nil
}

// SplunkHECEvent represents a Splunk HEC event payload.
type SplunkHECEvent struct {
	Time       float64                `json:"time,omitempty"`
	Host       string                 `json:"host,omitempty"`
	Source     string                 `json:"source,omitempty"`
	Sourcetype string                 `json:"sourcetype,omitempty"`
	Index      string                 `json:"index,omitempty"`
	Event      map[string]interface{} `json:"event"`
}

// Export sends events to Splunk HTTP Event Collector.
func (e *SplunkExporter) Export(ctx context.Context, events []*AuditEvent) error {
	if !e.TLSEnabled {
		return errors.New("SplunkExporter: TLS must be enabled to prevent credential exposure over plaintext HTTP")
	}
	if err := validateHTTPSURL("SplunkExporter", e.Endpoint); err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}

	payload := make([]SplunkHECEvent, 0, len(events))
	for _, ev := range events {
		// Marshal the fully-redacted event so Details, ChangeData, and Params
		// are all included and credential-free.
		eventBytes, err := json.Marshal(redactEvent(ev))
		if err != nil {
			return fmt.Errorf("failed to marshal redacted audit event: %w", err)
		}
		var event map[string]interface{}
		if err := json.Unmarshal(eventBytes, &event); err != nil {
			return fmt.Errorf("failed to unmarshal redacted audit event: %w", err)
		}
		hecEvent := SplunkHECEvent{
			Time:       float64(ev.Timestamp.UnixNano()) / 1e9,
			Index:      e.Index,
			Sourcetype: "secops:audit",
			Event:      event,
		}
		payload = append(payload, hecEvent)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal HEC payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+e.Token)

	return e.doRequestWithRetry(req)
}

func (e *SplunkExporter) doRequestWithRetry(req *http.Request) error {
	const maxRetries = 3

	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to buffer request body: %w", err)
		}
	}

	client := &http.Client{Timeout: siemHTTPTimeout}
	if e.TLSConfig != nil {
		if e.TLSConfig.InsecureSkipVerify {
			return fmt.Errorf("SplunkExporter: InsecureSkipVerify is prohibited for audit transport")
		}
		client.Transport = &http.Transport{TLSClientConfig: e.TLSConfig}
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			if err := sleepWithContext(req.Context(), backoffDuration(attempt)); err != nil {
				return fmt.Errorf("splunk export aborted: %w", err)
			}
		}

		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}

		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxSIEMResponseBytes))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		lastErr = fmt.Errorf("splunk HEC request failed with status %d: %s", resp.StatusCode, string(respBody))
		if resp.StatusCode < 500 {
			return lastErr
		}
	}

	return fmt.Errorf("splunk export failed after %d retries: %w", maxRetries, lastErr)
}

// backoffDuration returns the exponential backoff delay for the given attempt
// (attempt is 1-based for the first retry).
func backoffDuration(attempt int) time.Duration {
	return time.Duration(1<<uint(attempt-1)) * time.Second
}

// sleepWithContext waits for d or until ctx is done, whichever comes first.
// It returns the context error if the wait was cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	if ctx == nil {
		time.Sleep(d)
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ExportToAll exports to all configured SIEM systems.
func ExportToAll(ctx context.Context, events []*AuditEvent, exporters ...SIEMExporter) error {
	for _, exp := range exporters {
		if err := exp.Export(ctx, events); err != nil {
			return fmt.Errorf("SIEM export failed: %w", err)
		}
	}
	return nil
}

func validateHTTPSURL(exporterName string, endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return fmt.Errorf("%s: endpoint is required", exporterName)
	}

	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("%s: invalid endpoint: %w", exporterName, err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("%s: endpoint must use https", exporterName)
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("%s: endpoint host is required", exporterName)
	}

	return nil
}
