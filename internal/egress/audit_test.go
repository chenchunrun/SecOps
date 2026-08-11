package egress

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileObserverPersistsEgressDecisions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit", "egress.jsonl")
	observer, err := NewFileObserver(path)
	require.NoError(t, err)

	events := []Event{
		{
			RequestID: "allowed-request",
			Decision: Decision{
				Allowed: true,
				RuleID:  "github-api",
				Request: Request{Protocol: ProtocolHTTPS, Host: "api.github.com", Port: 443, CredentialRefs: []string{"github/actions"}},
				Reason:  "Destination satisfies trusted egress policy.",
			},
		},
		{
			RequestID: "denied-request",
			Decision: Decision{
				Request: Request{Protocol: ProtocolHTTPS, Host: "evil.example.com", Port: 443},
				Reason:  "No trusted egress rule satisfies the destination and credential references.",
			},
		},
	}
	for _, event := range events {
		require.NoError(t, observer.Record(context.Background(), event))
	}

	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })

	var records []AuditRecord
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var record AuditRecord
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &record))
		records = append(records, record)
	}
	require.NoError(t, scanner.Err())
	require.Len(t, records, 2)
	require.Equal(t, events[0], records[0].Event)
	require.False(t, records[0].RecordedAt.IsZero())
	require.Equal(t, events[1], records[1].Event)

	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(path)
		require.NoError(t, statErr)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestFileObserverRejectsEmptyPath(t *testing.T) {
	t.Parallel()

	observer, err := NewFileObserver("")
	require.ErrorIs(t, err, ErrInvalidAuditPath)
	require.Nil(t, observer)
}
