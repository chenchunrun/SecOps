package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SIEMExporter defines the interface for SIEM integrations.
type SIEMExporter interface {
	Export(ctx context.Context, events []*AuditEvent) error
}

// ELKExporter exports to Elasticsearch/Logstash/Kibana.
type ELKExporter struct {
	Endpoint   string // e.g. "http://localhost:9200"
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

		// Document line
		docBytes, err := json.Marshal(event)
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
type SplunkExporter struct {
	Endpoint string // e.g. "https://localhost:8088/services/collector"
	Token    string
	Index    string
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
		event := map[string]interface{}{
			"id":          ev.ID,
			"event_type":  ev.EventType,
			"timestamp":   ev.Timestamp,
			"session_id":  ev.SessionID,
			"user_id":     ev.UserID,
			"username":    ev.Username,
			"source_ip":   ev.SourceIP,
			"action":      ev.Action,
			"result":      ev.Result,
			"risk_score":  ev.RiskScore,
			"risk_level":  ev.RiskLevel,
			"severity":    ev.Severity,
			"reason":      ev.Reason,
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
