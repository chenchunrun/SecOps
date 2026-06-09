package execution

import (
	"context"
	"sync"
)

// SandboxRunner executes a command inside an isolated environment (e.g. a
// Docker container or a remote SSH host) and returns the combined output. It is
// implemented outside this package (bootstrap wires a concrete adapter) so the
// execution layer stays decoupled from any specific sandbox backend.
type SandboxRunner interface {
	RunSandboxed(ctx context.Context, command, workingDir string) (output string, err error)
}

var (
	mandatorySandboxMu sync.RWMutex
	mandatorySandbox   SandboxRunner
)

// SetMandatorySandbox installs (or clears, when nil) a process-wide mandatory
// sandbox. When set, local command execution is forced through the sandbox so
// strict-governance deployments cannot run commands directly on the host. The
// policy and audit middlewares still apply around the sandboxed execution.
func SetMandatorySandbox(runner SandboxRunner) {
	mandatorySandboxMu.Lock()
	defer mandatorySandboxMu.Unlock()
	mandatorySandbox = runner
}

func currentMandatorySandbox() SandboxRunner {
	mandatorySandboxMu.RLock()
	defer mandatorySandboxMu.RUnlock()
	return mandatorySandbox
}
