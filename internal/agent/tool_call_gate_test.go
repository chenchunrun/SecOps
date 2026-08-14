package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"charm.land/fantasy"
)

func TestToolCallGateCoalescesConcurrentDuplicates(t *testing.T) {
	t.Parallel()

	gate := newToolCallGate(128)
	var executions atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = gate.Do(context.Background(), "same-call", func() (fantasy.ToolResponse, error) {
				executions.Add(1)
				time.Sleep(10 * time.Millisecond)
				return fantasy.NewTextResponse("ok"), nil
			})
		}()
	}
	close(start)
	wg.Wait()

	if got := executions.Load(); got != 1 {
		t.Fatalf("duplicate call executed %d times", got)
	}
}

func TestToolCallGateCachesSequentialDuplicate(t *testing.T) {
	t.Parallel()

	gate := newToolCallGate(128)
	var executions atomic.Int32
	invoke := func() (fantasy.ToolResponse, error) {
		executions.Add(1)
		return fantasy.NewTextResponse("ok"), nil
	}
	_, _ = gate.Do(context.Background(), "same-call", invoke)
	_, _ = gate.Do(context.Background(), "same-call", invoke)

	if got := executions.Load(); got != 1 {
		t.Fatalf("sequential duplicate executed %d times", got)
	}
}

func TestToolCallGateAllowsConcurrentDistinctCalls(t *testing.T) {
	t.Parallel()

	gate := newToolCallGate(128)
	var executions atomic.Int32
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, _ = gate.Do(context.Background(), string(rune('a'+id)), func() (fantasy.ToolResponse, error) {
				executions.Add(1)
				return fantasy.NewTextResponse("ok"), nil
			})
		}(i)
	}
	wg.Wait()
	if got := executions.Load(); got != 20 {
		t.Fatalf("distinct calls executed %d times", got)
	}
}
