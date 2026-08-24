package tools

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"charm.land/fantasy"
	"github.com/stretchr/testify/require"
)

func TestToolCallGateCachesSequentialDuplicate(t *testing.T) {
	t.Parallel()

	gate := newToolCallGate(8)
	var calls atomic.Int32
	invoke := func() (fantasy.ToolResponse, error) {
		calls.Add(1)
		return fantasy.NewTextResponse("first result"), nil
	}

	first, err := gate.Do(context.Background(), "session\x00call", invoke)
	require.NoError(t, err)
	second, err := gate.Do(context.Background(), "session\x00call", invoke)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.EqualValues(t, 1, calls.Load())
}

func TestToolCallGateCoalescesConcurrentDuplicate(t *testing.T) {
	t.Parallel()

	gate := newToolCallGate(8)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	invoke := func() (fantasy.ToolResponse, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return fantasy.NewTextResponse("shared result"), nil
	}

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	responses := make(chan fantasy.ToolResponse, workers)
	for range workers {
		go func() {
			defer wg.Done()
			response, err := gate.Do(context.Background(), "session\x00call", invoke)
			require.NoError(t, err)
			responses <- response
		}()
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("tool invocation did not start")
	}
	close(release)
	wg.Wait()
	close(responses)

	require.EqualValues(t, 1, calls.Load())
	for response := range responses {
		require.Equal(t, fantasy.NewTextResponse("shared result"), response)
	}
}

func TestToolCallKeyIsolatesSessions(t *testing.T) {
	t.Parallel()

	first := context.WithValue(context.Background(), SessionIDContextKey, "session-one")
	second := context.WithValue(context.Background(), SessionIDContextKey, "session-two")
	require.NotEqual(t, toolCallKey(first, "call"), toolCallKey(second, "call"))
	require.Empty(t, toolCallKey(first, ""))
}
