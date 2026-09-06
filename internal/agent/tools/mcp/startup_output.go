package mcp

import (
	"fmt"
	"strings"
	"sync"

	"github.com/chenchunrun/SecOps/internal/security/redact"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const startupOutputLimit = 4096

// startupOutput retains only a bounded prefix of the original process stderr.
// A failing command must never be run again just to obtain diagnostics.
type startupOutput struct {
	mu   sync.Mutex
	data []byte
}

func (b *startupOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := min(len(p), startupOutputLimit-len(b.data))
	b.data = append(b.data, p[:n]...)
	return len(p), nil
}

func startupError(err error, transport mcp.Transport) error {
	ct, ok := transport.(*mcp.CommandTransport)
	if !ok {
		return err
	}
	b, ok := ct.Command.Stderr.(*startupOutput)
	if !ok {
		return err
	}
	b.mu.Lock()
	output := string(b.data)
	b.mu.Unlock()
	// Remove known environment values as well as recognizable credentials.
	for _, entry := range ct.Command.Env {
		_, value, found := strings.Cut(entry, "=")
		if found && len(value) >= 4 {
			output = strings.ReplaceAll(output, value, redact.Redacted)
		}
	}
	output = strings.TrimSpace(redact.String(output))
	if output == "" {
		return err
	}
	// Quote untrusted terminal output so control sequences cannot execute.
	return fmt.Errorf("%w; startup stderr (first %d bytes, redacted): %q", err, startupOutputLimit, output)
}
