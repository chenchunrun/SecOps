package egress

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/chenchunrun/SecOps/internal/computer"
)

var (
	ErrInvalidCredentialInjection     = errors.New("invalid credential injection")
	ErrCredentialInjectionUnsupported = errors.New("credential injection unsupported for backend")
)

// LeaseComputer decorates one Local or Docker Computer execution with a
// short-lived credential lease. Lifecycle operations remain delegated to the
// stable logical Computer.
type LeaseComputer struct {
	computer computer.Computer
	lease    *Lease
	mu       sync.Mutex
	used     bool
}

// NewLeaseComputer creates a single-use credential-injecting Computer wrapper.
// SSH is rejected until a channel that does not expose values in command
// arguments is available.
func NewLeaseComputer(machine computer.Computer, lease *Lease) (*LeaseComputer, error) {
	if machine == nil || lease == nil {
		return nil, ErrInvalidCredentialInjection
	}
	if machine.Backend() != computer.BackendLocal && machine.Backend() != computer.BackendDocker {
		return nil, fmt.Errorf("%w: %s", ErrCredentialInjectionUnsupported, machine.Backend())
	}
	return &LeaseComputer{computer: machine, lease: lease}, nil
}

func (c *LeaseComputer) ID() computer.ID           { return c.computer.ID() }
func (c *LeaseComputer) Backend() computer.Backend { return c.computer.Backend() }
func (c *LeaseComputer) State() computer.State     { return c.computer.State() }

// Exec injects a lease into a request copy, invokes the backend once, and
// clears both the request copy and lease on every return path.
func (c *LeaseComputer) Exec(
	ctx context.Context,
	request computer.ExecRequest,
) (*computer.ExecutionResult, error) {
	c.mu.Lock()
	if c.used {
		c.mu.Unlock()
		return nil, ErrLeaseRevoked
	}
	c.used = true
	c.mu.Unlock()

	environment, err := c.lease.Environment()
	if err != nil {
		c.lease.Revoke()
		return nil, err
	}
	request.Config.Environment = mergeTransientEnvironment(request.Config.Environment, environment)
	defer func() {
		clearStringValues(request.Config.Environment)
		c.lease.Revoke()
	}()
	return c.computer.Exec(ctx, request)
}

func (c *LeaseComputer) Suspend(ctx context.Context) error { return c.computer.Suspend(ctx) }
func (c *LeaseComputer) Resume(ctx context.Context) error  { return c.computer.Resume(ctx) }
func (c *LeaseComputer) Destroy(ctx context.Context) error { return c.computer.Destroy(ctx) }

func mergeTransientEnvironment(existing, lease map[string]string) map[string]string {
	merged := make(map[string]string, len(existing)+len(lease))
	for name, value := range existing {
		merged[name] = value
	}
	for name, value := range lease {
		merged[name] = value
	}
	return merged
}

func clearStringValues(values map[string]string) {
	for name := range values {
		values[name] = ""
		delete(values, name)
	}
}
