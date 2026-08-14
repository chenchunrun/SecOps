package agent

import (
	"context"
	"sync"

	"charm.land/fantasy"
)

type toolCallGate struct {
	mu      sync.Mutex
	entries map[string]*toolCallEntry
	limit   int
}

type toolCallEntry struct {
	done     chan struct{}
	response fantasy.ToolResponse
	err      error
}

func newToolCallGate(limit int) *toolCallGate {
	if limit <= 0 {
		limit = 1024
	}
	return &toolCallGate{entries: make(map[string]*toolCallEntry), limit: limit}
}

func (g *toolCallGate) Do(
	ctx context.Context,
	id string,
	invoke func() (fantasy.ToolResponse, error),
) (fantasy.ToolResponse, error) {
	if id == "" {
		return invoke()
	}

	g.mu.Lock()
	if entry, ok := g.entries[id]; ok {
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return fantasy.ToolResponse{}, ctx.Err()
		case <-entry.done:
			return entry.response, entry.err
		}
	}
	if len(g.entries) >= g.limit {
		for key, entry := range g.entries {
			select {
			case <-entry.done:
				delete(g.entries, key)
			default:
			}
			if len(g.entries) < g.limit {
				break
			}
		}
	}
	entry := &toolCallEntry{done: make(chan struct{})}
	g.entries[id] = entry
	g.mu.Unlock()

	entry.response, entry.err = invoke()
	close(entry.done)
	return entry.response, entry.err
}
