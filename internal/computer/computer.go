// Package computer defines stable execution identities independently from the
// runtime backend that performs each command.
package computer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/chenchunrun/SecOps/internal/sandbox"
)

// ID is the stable logical identity of a Computer.
type ID string

// Backend identifies an execution backend without exposing backend SDK types.
type Backend string

const (
	BackendLocal  Backend = "local"
	BackendDocker Backend = "docker"
	BackendSSH    Backend = "ssh"
)

// State describes the lifecycle of a Computer.
type State string

const (
	StateProvisioning State = "provisioning"
	StateActive       State = "active"
	StateSuspended    State = "suspended"
	StateFailed       State = "failed"
	StateCompleted    State = "completed"
	StateDestroyed    State = "destroyed"
)

var (
	ErrInvalidID          = errors.New("computer ID is required")
	ErrInvalidBackend     = errors.New("invalid computer backend")
	ErrBackendUnavailable = errors.New("computer backend is unavailable")
	ErrNotActive          = errors.New("computer is not active")
	ErrDestroyed          = errors.New("computer is destroyed")
	ErrInvalidResult      = errors.New("computer backend returned no result")
)

// ExecRequest describes one backend-independent execution request.
type ExecRequest struct {
	Command        string
	Config         sandbox.SandboxConfig
	MaxOutputBytes int
}

// ExecutionResult is the normalized result returned by every backend.
type ExecutionResult struct {
	Output    string
	ExitCode  int
	Duration  time.Duration
	RiskScore int
	Truncated bool
}

// Computer is a stable logical execution identity with a managed lifecycle.
type Computer interface {
	ID() ID
	Backend() Backend
	State() State
	Exec(ctx context.Context, req ExecRequest) (*ExecutionResult, error)
	Suspend(ctx context.Context) error
	Resume(ctx context.Context) error
	Destroy(ctx context.Context) error
}

type executorComputer struct {
	id       ID
	backend  Backend
	executor sandbox.SandboxExecutor

	operationMu sync.Mutex
	stateMu     sync.RWMutex
	state       State
}

var _ Computer = (*executorComputer)(nil)

func newExecutorComputer(id ID, backend Backend, executor sandbox.SandboxExecutor) (*executorComputer, error) {
	if strings.TrimSpace(string(id)) == "" {
		return nil, ErrInvalidID
	}
	if !backend.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidBackend, backend)
	}
	if executor == nil {
		return nil, ErrBackendUnavailable
	}

	computer := &executorComputer{
		id:       id,
		backend:  backend,
		executor: executor,
		state:    StateProvisioning,
	}
	computer.setState(StateActive)
	return computer, nil
}

// Valid reports whether the backend is supported by the core runtime.
func (b Backend) Valid() bool {
	switch b {
	case BackendLocal, BackendDocker, BackendSSH:
		return true
	default:
		return false
	}
}

func (c *executorComputer) ID() ID {
	return c.id
}

func (c *executorComputer) Backend() Backend {
	return c.backend
}

func (c *executorComputer) State() State {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}

func (c *executorComputer) Exec(ctx context.Context, req ExecRequest) (*ExecutionResult, error) {
	if err := ctx.Err(); err != nil {
		c.setState(StateFailed)
		return nil, err
	}

	c.operationMu.Lock()
	defer c.operationMu.Unlock()

	state := c.State()
	switch state {
	case StateDestroyed:
		return nil, ErrDestroyed
	case StateSuspended, StateProvisioning:
		return nil, fmt.Errorf("%w: state is %s", ErrNotActive, state)
	case StateActive, StateCompleted, StateFailed:
		c.setState(StateActive)
	default:
		return nil, fmt.Errorf("%w: state is %s", ErrNotActive, state)
	}

	req.Config.Mode = string(c.backend)
	backendResult, execErr := c.executor.Execute(ctx, req.Command, req.Config)
	if backendResult == nil {
		c.setState(StateFailed)
		if execErr != nil {
			return nil, execErr
		}
		return nil, ErrInvalidResult
	}
	if execErr == nil && backendResult.Error != nil {
		execErr = backendResult.Error
	}

	output, truncated := limitOutput(backendResult.Output, req.MaxOutputBytes)
	result := &ExecutionResult{
		Output:    output,
		ExitCode:  backendResult.ExitCode,
		Duration:  backendResult.Duration,
		RiskScore: backendResult.RiskScore,
		Truncated: truncated,
	}
	if execErr != nil || backendResult.ExitCode != 0 {
		c.setState(StateFailed)
		if execErr == nil {
			execErr = fmt.Errorf("backend exited with code %d", backendResult.ExitCode)
		}
		return result, execErr
	}

	c.setState(StateCompleted)
	return result, nil
}

func (c *executorComputer) Suspend(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.operationMu.Lock()
	defer c.operationMu.Unlock()

	switch c.State() {
	case StateDestroyed:
		return ErrDestroyed
	case StateSuspended:
		return nil
	default:
		c.setState(StateSuspended)
		return nil
	}
}

func (c *executorComputer) Resume(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.operationMu.Lock()
	defer c.operationMu.Unlock()

	if c.State() == StateDestroyed {
		return ErrDestroyed
	}
	c.setState(StateActive)
	return nil
}

func (c *executorComputer) Destroy(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.operationMu.Lock()
	defer c.operationMu.Unlock()

	if c.State() == StateDestroyed {
		return nil
	}
	c.setState(StateDestroyed)
	return nil
}

func (c *executorComputer) setState(state State) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.state = state
}

func limitOutput(output string, maxBytes int) (string, bool) {
	if maxBytes <= 0 || len(output) <= maxBytes {
		return output, false
	}
	end := maxBytes
	for end > 0 && !utf8.ValidString(output[:end]) {
		end--
	}
	return output[:end], true
}
