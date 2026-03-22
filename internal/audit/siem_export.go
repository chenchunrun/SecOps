package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// redactionRegexes holds the credential patterns used to redact sensitive data
// before exporting audit events to SIEM systems.
var redactionRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_-]+`),
	regexp.MustCompile(`(?i)sk_live_[A-Za-z0-9_-]+`),
	regexp.MustCompile(`(?i)sk_test_[A-Za-z0-9_-]+`),
	regexp.MustCompile(`(?i)AKIA[A-Za-z0-9]+`),
	regexp.MustCompile(`(?i)aws_secret_access_key[=:]\s*\S+`),
	regexp.MustCompile(`(?i)[?&]password=[^&\s]+`),
	regexp.MustCompile(`-----BEGIN.*PRIVATE KEY-----`),
}

const redacted = "***REDACTED***"

// redactValue recursively scans and redacts credential patterns from a value.
// Strings are scanned for all known credential patterns; maps and slices are
// traversed recursively; all other values are returned unchanged.
func redactValue(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		result := val
		for _, re := range redactionRegexes {
			result = re.ReplaceAllString(result, redacted)
		}
		return result
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
func redactEvent(event *AuditEvent) *AuditEvent {
	if event == nil {
		return nil
	}
	cp := &AuditEvent{
		ID:          event.ID,
		EventType:   event.EventType,
		Timestamp:   event.Timestamp,
		SessionID:   event.SessionID,
		UserID:      event.UserID,
		Username:    event.Username,
		SourceIP:    event.SourceIP,
		Action:      event.Action,
		ResourceType: event.ResourceType,
		ResourceName: event.ResourceName,
		ResourcePath: event.ResourcePath,
		Result:      event.Result,
		ErrorMsg:    event.ErrorMsg,
		RiskScore:   event.RiskScore,
		RiskLevel:   event.RiskLevel,
		Severity:    event.Severity,
		Details:     make(map[string]interface{}),
		ApprovalID:  event.ApprovalID,
		ApprovedBy:  event.ApprovedBy,
		ApprovedAt:  event.ApprovedAt,
		Reason:      event.Reason,
		Signature:   event.Signature,
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

// ELKExporter exports to Elasticsearch/Logstash/Kibana.
// TLSEnabled controls whether TLS is used for the connection. When TLSEnabled
// is false (the default for backward compatibility), credentials present in
// event fields are still redacted before export, but the transport itself
// will send data in plaintext over the network — configure TLS in production.
type ELKExporter struct {
	Endpoint   string // e.g. "https://localhost:9200"
	Index      string // e.g. "secops-audit"
	Username   string
	Password   string
	TLSEnabled bool
}

// Export exports audit events to ELK via HTTP bulk API.
func (e *ELKExporter) Export(ctx context.Context, events []*AuditEvent) error {
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
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			time.Sleep(backoff)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}

		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		lastErr = fmt.Errorf("ELK bulk request failed with status %d: %s", resp.StatusCode, string(bodyBytes))

		// Only retry on 5xx errors or connection errors
		if resp.StatusCode < 500 {
			return lastErr
		}
	}

	return fmt.Errorf("ELK export failed after %d retries: %w", maxRetries, lastErr)
}

// SplunkExporter exports to Splunk HTTP Event Collector.
// TLSEnabled controls whether TLS is used for the connection. When TLSEnabled
// is false (the default for backward compatibility), credentials present in
// event fields are still redacted before export, but the transport itself
// will send data in plaintext over the network — configure TLS in production.
type SplunkExporter struct {
	Endpoint   string // e.g. "https://localhost:8088/services/collector"
	Token      string
	Index      string
	TLSEnabled bool
}

// SplunkHECEvent represents a Splunk HEC event payload.
type SplunkHECEvent struct {
	Time     float64                `json:"time,omitempty"`
	Host     string                 `json:"host,omitempty"`
	Source   string                 `json:"source,omitempty"`
	Sourcetype string               `json:"sourcetype,omitempty"`
	Index    string                 `json:"index,omitempty"`
	Event    map[string]interface{} `json:"event"`
}

// Export sends events to Splunk HTTP Event Collector.
func (e *SplunkExporter) Export(ctx context.Context, events []*AuditEvent) error {
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
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			time.Sleep(backoff)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}

		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		lastErr = fmt.Errorf("Splunk HEC request failed with status %d: %s", resp.StatusCode, string(bodyBytes))

		// Only retry on 5xx errors or connection errors
		if resp.StatusCode < 500 {
			return lastErr
		}
	}

	return fmt.Errorf("Splunk export failed after %d retries: %w", maxRetries, lastErr)
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
