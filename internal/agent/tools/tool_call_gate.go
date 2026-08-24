package tools

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
	return &toolCallGate{
		entries: make(map[string]*toolCallEntry),
		limit:   limit,
	}
}

func (g *toolCallGate) Do(
	ctx context.Context,
	key string,
	invoke func() (fantasy.ToolResponse, error),
) (fantasy.ToolResponse, error) {
	if key == "" {
		return invoke()
	}

	g.mu.Lock()
	if entry, ok := g.entries[key]; ok {
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return fantasy.ToolResponse{}, ctx.Err()
		case <-entry.done:
			return entry.response, entry.err
		}
	}
	if len(g.entries) >= g.limit {
		for existingKey, entry := range g.entries {
			select {
			case <-entry.done:
				delete(g.entries, existingKey)
			default:
			}
			if len(g.entries) < g.limit {
				break
			}
		}
	}
	entry := &toolCallEntry{done: make(chan struct{})}
	g.entries[key] = entry
	g.mu.Unlock()

	entry.response, entry.err = invoke()
	close(entry.done)
	return entry.response, entry.err
}

func toolCallKey(ctx context.Context, callID string) string {
	if callID == "" {
		return ""
	}
	if sessionID := GetSessionFromContext(ctx); sessionID != "" {
		return sessionID + "\x00" + callID
	}
	return callID
}
