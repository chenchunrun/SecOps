package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- ELKExporter tests ---

func TestELKExporter_Export_Success(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := &ELKExporter{
		Endpoint:   server.URL,
		Index:      "test-index",
		Username:   "elastic",
		Password:   "secret",
		TLSEnabled: true,
	}

	events := []*AuditEvent{
		DefaultAuditEvent(EventTypePermissionRequest),
		DefaultAuditEvent(EventTypeCommandExecuted),
	}

	err := exporter.Export(context.Background(), events)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if receivedContentType != "application/x-ndjson" {
		t.Errorf("expected Content-Type application/x-ndjson, got %q", receivedContentType)
	}

	expectedAuth := "Basic ZWxhc3RpYzpzZWNyZXQ="
	if receivedAuth != expectedAuth {
		t.Errorf("expected Authorization %q, got %q", expectedAuth, receivedAuth)
	}

	// Verify NDJSON body contains action lines for each event
	lines := bytes.Split(receivedBody, []byte{'\n'})
	var actionLines int
	for _, line := range lines {
		if len(line) > 0 {
			var doc map[string]interface{}
			if err := json.Unmarshal(line, &doc); err == nil {
				if _, hasAction := doc["action"]; hasAction {
					actionLines++
				}
			}
		}
	}
	if actionLines < len(events) {
		t.Errorf("expected at least %d action lines in bulk body, got %d", len(events), actionLines)
	}
}

func TestELKExporter_Export_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	exporter := &ELKExporter{
		Endpoint:   server.URL,
		Index:      "test-index",
		TLSEnabled: true,
	}

	events := []*AuditEvent{DefaultAuditEvent(EventTypePermissionRequest)}

	err := exporter.Export(context.Background(), events)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestELKExporter_Export_RetryOnFailure(t *testing.T) {
	attempt := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := &ELKExporter{
		Endpoint:   server.URL,
		Index:      "test-index",
		TLSEnabled: true,
	}

	events := []*AuditEvent{DefaultAuditEvent(EventTypeCommandExecuted)}

	err := exporter.Export(context.Background(), events)
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if attempt != 3 {
		t.Errorf("expected 3 attempts, got %d", attempt)
	}
}

func TestELKExporter_Export_RetryExhausted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	exporter := &ELKExporter{
		Endpoint:   server.URL,
		Index:      "test-index",
		TLSEnabled: true,
	}

	events := []*AuditEvent{DefaultAuditEvent(EventTypeSecurityAlert)}

	err := exporter.Export(context.Background(), events)
	if err == nil {
		t.Fatal("expected error after retries exhausted, got nil")
	}
}

// --- SplunkExporter tests ---

func TestSplunkExporter_Export_Success(t *testing.T) {
	var receivedBody []byte
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := &SplunkExporter{
		Endpoint:   server.URL,
		Token:      "test-token",
		Index:      "test-index",
		TLSEnabled: true,
	}

	events := []*AuditEvent{
		DefaultAuditEvent(EventTypeLoginSuccess),
		DefaultAuditEvent(EventTypeDataAccess),
	}

	err := exporter.Export(context.Background(), events)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if receivedAuth != "Splunk test-token" {
		t.Errorf("expected Authorization 'Splunk test-token', got %q", receivedAuth)
	}

	// Verify HEC JSON payload
	var payload []map[string]interface{}
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("expected valid JSON payload, got parse error: %v", err)
	}
	if len(payload) != len(events) {
		t.Errorf("expected %d events in payload, got %d", len(events), len(payload))
	}
}

func TestSplunkExporter_Export_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	exporter := &SplunkExporter{
		Endpoint:   server.URL,
		Token:      "bad-token",
		TLSEnabled: true,
	}

	events := []*AuditEvent{DefaultAuditEvent(EventTypeLoginFailure)}

	err := exporter.Export(context.Background(), events)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSplunkExporter_Export_RetryOnFailure(t *testing.T) {
	attempt := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := &SplunkExporter{
		Endpoint:   server.URL,
		Token:      "test-token",
		Index:      "test-index",
		TLSEnabled: true,
	}

	events := []*AuditEvent{DefaultAuditEvent(EventTypeConfigChange)}

	err := exporter.Export(context.Background(), events)
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if attempt != 3 {
		t.Errorf("expected 3 attempts, got %d", attempt)
	}
}

func TestSplunkExporter_Export_RetryExhausted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	exporter := &SplunkExporter{
		Endpoint:   server.URL,
		Token:      "test-token",
		TLSEnabled: true,
	}

	events := []*AuditEvent{DefaultAuditEvent(EventTypeSecurityAlert)}

	err := exporter.Export(context.Background(), events)
	if err == nil {
		t.Fatal("expected error after retries exhausted, got nil")
	}
}

// --- ExportToAll tests ---

func TestExportToAll_Success(t *testing.T) {
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server2.Close()

	elk := &ELKExporter{Endpoint: server1.URL, Index: "test", TLSEnabled: true}
	splunk := &SplunkExporter{Endpoint: server2.URL, Token: "tok", Index: "test", TLSEnabled: true}

	events := []*AuditEvent{DefaultAuditEvent(EventTypeCommandExecuted)}

	err := ExportToAll(context.Background(), events, elk, splunk)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestExportToAll_StopsOnFirstError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	elk := &ELKExporter{Endpoint: server.URL, Index: "test", TLSEnabled: true}

	events := []*AuditEvent{DefaultAuditEvent(EventTypePermissionRequest)}

	err := ExportToAll(context.Background(), events, elk)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestExportToAll_EmptyExporters(t *testing.T) {
	events := []*AuditEvent{DefaultAuditEvent(EventTypeDataAccess)}
	err := ExportToAll(context.Background(), events)
	if err != nil {
		t.Fatalf("expected no error with empty exporters, got %v", err)
	}
}

// --- Integration-style tests ---

func TestELKExporter_Export_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := &ELKExporter{Endpoint: server.URL, Index: "test", TLSEnabled: true}
	events := []*AuditEvent{DefaultAuditEvent(EventTypeSecurityAlert)}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := exporter.Export(ctx, events)
	if err == nil {
		t.Fatal("expected error due to context cancellation, got nil")
	}
}

func TestSplunkExporter_Export_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := &SplunkExporter{Endpoint: server.URL, Token: "tok", TLSEnabled: true}
	events := []*AuditEvent{DefaultAuditEvent(EventTypeSecurityAlert)}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := exporter.Export(ctx, events)
	if err == nil {
		t.Fatal("expected error due to context cancellation, got nil")
	}
}

func TestELKExporter_Export_EmptyEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			t.Errorf("expected empty body, got %d bytes", len(body))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := &ELKExporter{Endpoint: server.URL, Index: "test", TLSEnabled: true}
	err := exporter.Export(context.Background(), []*AuditEvent{})
	if err != nil {
		t.Fatalf("expected no error with empty events, got %v", err)
	}
}

func TestSplunkExporter_Export_EmptyEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload []map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("expected valid JSON, got error: %v", err)
		}
		if len(payload) != 0 {
			t.Errorf("expected empty payload, got %d items", len(payload))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := &SplunkExporter{Endpoint: server.URL, Token: "tok", TLSEnabled: true}
	err := exporter.Export(context.Background(), []*AuditEvent{})
	if err != nil {
		t.Fatalf("expected no error with empty events, got %v", err)
	}
}
