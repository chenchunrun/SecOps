package connectors

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApprovalRevokedBeforeTransportBlocksWrite(t *testing.T) {
	t.Parallel()
	transport := &fakeTransport{responses: []TransportResponse{{StatusCode: 200}}}
	client := newTestClient(t, transport, &fakeAuditor{})
	calls := 0
	client.approvals = approvalVerifierFunc(func(context.Context, ApprovalRequest) error {
		calls++
		if calls > 1 {
			return errors.New("revoked")
		}
		return nil
	})
	_, err := client.Execute(t.Context(), ExecuteRequest{Operation: "write", ApprovalID: "approval", SessionID: "session"})
	require.ErrorContains(t, err, "revoked")
	require.Equal(t, 2, calls)
	require.Empty(t, transport.requests)
}
