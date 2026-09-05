package agent

import (
	"context"
	"testing"
	"time"

	"charm.land/fantasy"
	"github.com/stretchr/testify/require"
)

type cancelableSecOpsTool struct {
	testSecOpsTool
	started chan struct{}
}

func (*cancelableSecOpsTool) RequiredCapabilities() []string { return nil }
func (*cancelableSecOpsTool) Execute(interface{}) (interface{}, error) {
	panic("adapter lost the session context")
}

func (tool *cancelableSecOpsTool) ExecuteContext(ctx context.Context, _ interface{}) (interface{}, error) {
	close(tool.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestAdapterPropagatesSessionCancellation(t *testing.T) {
	lockSecOpsAuditStoreTest(t)
	tool := &cancelableSecOpsTool{started: make(chan struct{})}
	adapter := &Adapter{tool: tool}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan fantasy.ToolResponse, 1)
	go func() {
		response, _ := adapter.executeAndRespond(ctx, fantasy.ToolCall{ID: "cancel-test"}, nil)
		done <- response
	}()
	<-tool.started
	cancel()
	select {
	case response := <-done:
		require.True(t, response.IsError)
	case <-time.After(time.Second):
		t.Fatal("adapter ignored session cancellation")
	}
}
