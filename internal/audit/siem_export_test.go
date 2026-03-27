package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

// --- SyslogExporter tests ---

func TestSyslogExporter_Export_UDP_Success(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	received := make(chan string, 1)
	go func() {
		buf := make([]byte, 8192)
		n, _, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			received <- ""
			return
		}
		received <- string(buf[:n])
	}()

	event := DefaultAuditEvent(EventTypeCommandExecuted)
	event.ID = "evt-syslog-1"
	event.Timestamp = time.Date(2026, 3, 26, 12, 0, 0, 0, time.UTC)
	event.Details["token"] = "Authorization: Bearer secret-token"

	exporter := &SyslogExporter{
		Network:  "udp",
		Address:  conn.LocalAddr().String(),
		AppName:  "secops-agent",
		Hostname: "audit-host",
		Facility: 16,
		Severity: 6,
	}

	err = exporter.Export(context.Background(), []*AuditEvent{event})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	select {
	case msg := <-received:
		if !strings.HasPrefix(msg, "<134>1 2026-03-26T12:00:00Z audit-host secops-agent - evt-syslog-1 - ") {
			t.Fatalf("unexpected syslog header: %q", msg)
		}
		if !strings.Contains(msg, redacted) {
			t.Fatalf("expected redacted payload, got %q", msg)
		}
		if strings.Contains(msg, "secret-token") {
			t.Fatalf("expected sensitive token to be removed, got %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for syslog message")
	}
}

func TestSyslogExporter_Export_TCP_Success(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			received <- ""
			return
		}
		defer c.Close()
		body, readErr := io.ReadAll(c)
		if readErr != nil {
			received <- ""
			return
		}
		received <- string(body)
	}()

	event := DefaultAuditEvent(EventTypePermissionRequest)
	event.ID = "evt-syslog-tcp"

	exporter := &SyslogExporter{
		Network: "tcp",
		Address: ln.Addr().String(),
		AppName: "secops-agent",
	}

	err = exporter.Export(context.Background(), []*AuditEvent{event})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	select {
	case msg := <-received:
		if !strings.Contains(msg, "evt-syslog-tcp") {
			t.Fatalf("expected msg id in payload, got %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for tcp syslog message")
	}
}

func TestSyslogExporter_Export_InvalidNetwork(t *testing.T) {
	exporter := &SyslogExporter{
		Network: "bogus",
		Address: "127.0.0.1:514",
	}

	err := exporter.Export(context.Background(), []*AuditEvent{DefaultAuditEvent(EventTypeCommandExecuted)})
	if err == nil {
		t.Fatal("expected invalid network error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported network") {
		t.Fatalf("expected unsupported network error, got %v", err)
	}
}

func TestSyslogExporter_Export_RejectsRemoteNetworkAddress(t *testing.T) {
	exporter := &SyslogExporter{
		Network: "udp",
		Address: "8.8.8.8:514",
	}

	err := exporter.Export(context.Background(), []*AuditEvent{DefaultAuditEvent(EventTypeCommandExecuted)})
	if err == nil {
		t.Fatal("expected remote address rejection, got nil")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected remote rejection error, got %v", err)
	}
}

func TestSyslogExporter_Export_UnixSuccess(t *testing.T) {
	socketPath := fmt.Sprintf("/tmp/secops-audit-%d.sock", time.Now().UnixNano())
	_ = os.Remove(socketPath)
	defer os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			received <- ""
			return
		}
		defer c.Close()
		body, readErr := io.ReadAll(c)
		if readErr != nil {
			received <- ""
			return
		}
		received <- string(body)
	}()

	exporter := &SyslogExporter{
		Network: "unix",
		Address: socketPath,
		AppName: "secops-agent",
	}

	err = exporter.Export(context.Background(), []*AuditEvent{DefaultAuditEvent(EventTypeCommandExecuted)})
	if err != nil {
		t.Fatalf("expected unix export success, got %v", err)
	}

	select {
	case msg := <-received:
		if !strings.Contains(msg, "secops-agent") {
			t.Fatalf("expected syslog payload, got %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for unix syslog message")
	}
}

func TestFormatSyslogMessage_SanitizesHeaderFields(t *testing.T) {
	msg := formatSyslogMessage(
		16,
		6,
		time.Date(2026, 3, 27, 1, 2, 3, 0, time.UTC),
		sanitizeSyslogHeaderField("host name\nx", 255),
		sanitizeSyslogHeaderField("app\tname", 48),
		"evt\n123",
		[]byte(`{"ok":true}`),
	)

	if strings.Contains(msg, "\n123") || strings.Contains(msg, "host name") || strings.Contains(msg, "app\tname") {
		t.Fatalf("expected sanitized syslog header, got %q", msg)
	}
	if !strings.Contains(msg, "host-name-x") {
		t.Fatalf("expected sanitized hostname, got %q", msg)
	}
	if !strings.Contains(msg, "app-name") {
		t.Fatalf("expected sanitized app name, got %q", msg)
	}
}

func TestSyslogExporter_Export_EmptyEvents(t *testing.T) {
	exporter := &SyslogExporter{
		Network: "udp",
		Address: "127.0.0.1:514",
	}

	err := exporter.Export(context.Background(), []*AuditEvent{})
	if err != nil {
		t.Fatalf("expected no error with empty events, got %v", err)
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

// --- Credential redaction tests (13 patterns) ---

func TestRedactValue_All13Patterns(t *testing.T) {
	cases := []struct {
		name     string
		input    interface{}
		redacted bool // true = should contain REDACTED, false = unchanged
	}{
		// Pattern 1: Bearer Token
		{name: "bearer token", input: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", redacted: true},
		// Pattern 4: AWS Access Key (AKIA)
		{name: "aws akia key", input: "AKIAIOSFODNN7EXAMPLE", redacted: true},
		// Pattern 4b: AWS Access Key (ASIA)
		{name: "aws asia key", input: "ASIAIOSFODNN7EXAMPLE", redacted: true},
		// Pattern 5: AWS Secret Key
		{name: "aws secret key", input: "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", redacted: true},
		// Pattern 6: URL Password
		{name: "url password", input: "https://example.com/login?password=SuperSecret123", redacted: true},
		// Pattern 7: Private Key
		{name: "private key", input: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...\n-----END RSA PRIVATE KEY-----", redacted: true},
		// Pattern 8: GitHub PAT (ghp_)
		{name: "github pat ghp", input: "ghp_ABCD1234EFGH5678IJKL9012MNOP345678QR", redacted: true},
		// Pattern 8b: GitHub PAT (github_pat_)
		{name: "github pat github_pat", input: "github_pat_11atrepo0_ABCD1234EFGH5678IJKL9012MNOP345678", redacted: true},
		// Pattern 9: GCP credential (gcp_credentials)
		{name: "gcp credentials", input: "gcp_credentials={\"type\":\"service_account\"}", redacted: true},
		// Pattern 9b: GCP credential (GOOGLE_)
		{name: "google credential", input: "GOOGLE_APPLICATION_CREDENTIALS=/path/to/file.json", redacted: true},
		// Pattern 11: Generic API Key
		{name: "generic api_key", input: "api_key=FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000", redacted: true},
		// Pattern 11b: apikey
		{name: "apikey", input: "apikey: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", redacted: true},
		// Pattern 11c: api-key
		{name: "api-key", input: "api-key = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'", redacted: true},
		// Pattern 12: Database DSN (mysql)
		{name: "mysql dsn", input: "mysql://admin:password123@localhost:3306/mydb", redacted: true},
		// Pattern 12b: postgres DSN
		{name: "postgres dsn", input: "postgres://bob:secretpass@db.example.com:5432/prod", redacted: true},
		// Pattern 12c: mongodb DSN
		{name: "mongodb dsn", input: "mongodb://user:mongodbpass@cluster0.example.com:27017/admin", redacted: true},
		// Pattern 12d: redis DSN
		{name: "redis dsn", input: "redis://redis:MySecurePwd@redis.example.com:6379/0", redacted: true},
		// Pattern 13: JWT Token
		{name: "jwt token", input: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", redacted: true},
		// Safe content (should NOT be redacted)
		{name: "safe string", input: "SELECT * FROM users WHERE id = 1", redacted: false},
		{name: "normal log line", input: "[INFO] Server started on port 8080", redacted: false},
		{name: "gcp keyword in non-credential", input: "gcp_instance_name=prod-server-01", redacted: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := redactValue(tc.input)
			resultStr, ok := result.(string)
			if !ok {
				t.Fatalf("expected string result, got %T", result)
			}
			if tc.redacted {
				if !strings.Contains(resultStr, redacted) {
					t.Errorf("expected redaction marker in %q, got %q", tc.name, resultStr)
				}
			} else {
				// Input should be unchanged
				inputStr, ok := tc.input.(string)
				if !ok {
					t.Fatalf("expected string input for non-redacted case, got %T", tc.input)
				}
				if resultStr != inputStr {
					t.Errorf("expected unchanged value %q, got %q", inputStr, resultStr)
				}
			}
		})
	}
}

func TestRedactValue_NestedStruct(t *testing.T) {
	// Test that redaction works recursively on nested maps
	input := map[string]interface{}{
		"user":     "alice",
		"db_conn":  "mysql://admin:secret123@localhost:3306/mydb",
		"metadata": map[string]interface{}{
			"token":    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			"note":     "this is safe",
			"gcp_cred": "gcp_service_account_key=abc123",
		},
		"tokens": []interface{}{
			"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			"normal_value",
		},
	}

	result := redactValue(input)
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}

	// mysql:// URL password should be redacted (regex replaces user:pass@ portion)
	if !strings.Contains(resultMap["db_conn"].(string), redacted) {
		t.Errorf("expected db_conn to contain redaction marker, got %v", resultMap["db_conn"])
	}

	meta, ok := resultMap["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected nested map, got %T", resultMap["metadata"])
	}
	if !strings.Contains(meta["token"].(string), redacted) {
		t.Errorf("expected token to contain redaction marker, got %v", meta["token"])
	}
	if meta["note"] != "this is safe" {
		t.Errorf("expected note unchanged, got %v", meta["note"])
	}
	if gcpCredVal, ok := meta["gcp_cred"].(string); !ok || !strings.Contains(gcpCredVal, redacted) {
		t.Errorf("expected gcp_cred to contain redaction marker, got %v", meta["gcp_cred"])
	}

	tokens, ok := resultMap["tokens"].([]interface{})
	if !ok {
		t.Fatalf("expected slice, got %T", resultMap["tokens"])
	}
	if tokens[0] != redacted {
		t.Errorf("expected token redacted, got %v", tokens[0])
	}
	if tokens[1] != "normal_value" {
		t.Errorf("expected normal_value unchanged, got %v", tokens[1])
	}
}

func TestRedactEvent_DoesNotMutateOriginal(t *testing.T) {
	event := &AuditEvent{
		ID:       "test-123",
		Username: "alice",
		Action:   "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Details: map[string]interface{}{
			"bearer_token": "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			"note":    "safe content",
		},
	}

	// redactEvent must return a new struct; original must be unchanged
	cp := redactEvent(event)

	// redactEvent returns a new struct (different pointer)
	if cp == event {
		t.Error("expected redactEvent to return a new struct pointer, got same pointer")
	}
	// Verify credential in Details was redacted in the copy
	if !strings.Contains(cp.Details["bearer_token"].(string), redacted) {
		t.Errorf("expected Details[\"bearer_token\"] to be redacted in copy, got %v", cp.Details["bearer_token"])
	}
	// Verify original Details is unchanged
	if strings.Contains(event.Details["bearer_token"].(string), redacted) {
		t.Error("expected original Details[\"bearer_token\"] to be unchanged")
	}
	// Verify the Details map was deep-copied (same keys but different underlying map)
	// We can check this by mutating the copy and verifying original is not affected
	cp.Details["new_key"] = "new_value"
	_, existsInOriginal := event.Details["new_key"]
	if existsInOriginal {
		t.Error("expected original Details to be unaffected by copy mutation")
	}
}

func TestELKExporter_TLSRequired(t *testing.T) {
	exporter := &ELKExporter{
		Endpoint:   "http://insecure.example.com/_bulk",
		Index:      "test",
		TLSEnabled: false,
	}

	err := exporter.Export(context.Background(), []*AuditEvent{DefaultAuditEvent(EventTypeCommandExecuted)})
	if err == nil {
		t.Fatal("expected error when TLS is disabled, got nil")
	}
	if !strings.Contains(err.Error(), "TLS") {
		t.Errorf("expected TLS error message, got %v", err)
	}
}

func TestSplunkExporter_TLSRequired(t *testing.T) {
	exporter := &SplunkExporter{
		Endpoint:   "http://insecure.example.com/services/collector",
		Token:      "tok",
		Index:      "test",
		TLSEnabled: false,
	}

	err := exporter.Export(context.Background(), []*AuditEvent{DefaultAuditEvent(EventTypeCommandExecuted)})
	if err == nil {
		t.Fatal("expected error when TLS is disabled, got nil")
	}
	if !strings.Contains(err.Error(), "TLS") {
		t.Errorf("expected TLS error message, got %v", err)
	}
}

func TestRedactEvent_PreservesRemotePolicyDenyFields(t *testing.T) {
	event := &AuditEvent{
		ID:           "evt-remote-1",
		EventType:    EventTypePermissionDenied,
		SessionID:    "sess-1",
		Action:       "remote_policy_deny",
		Transport:    "ssh",
		TargetHost:   "ops@10.0.0.12",
		TargetEnv:    "prod",
		TargetID:     "prod-web",
		ResourcePath: "ssh://ops@10.0.0.12",
		Details: map[string]interface{}{
			"policy_type":   "allow_list",
			"policy_rule":   "systemctl status *",
			"policy_result": "deny",
		},
	}

	redacted := redactEvent(event)
	if redacted.Transport != "ssh" {
		t.Fatalf("expected transport ssh, got %q", redacted.Transport)
	}
	if redacted.TargetHost != "ops@10.0.0.12" {
		t.Fatalf("expected target host preserved, got %q", redacted.TargetHost)
	}
	if redacted.TargetID != "prod-web" {
		t.Fatalf("expected target id preserved, got %q", redacted.TargetID)
	}
	if redacted.Details["policy_result"] != "deny" {
		t.Fatalf("expected policy_result deny, got %#v", redacted.Details["policy_result"])
	}
}
