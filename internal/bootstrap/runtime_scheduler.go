package bootstrap

import (
	"errors"
	"fmt"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/scheduler"
)

var ErrComputerRuntimeRequired = errors.New("computer runtime is required")

// NewRuntimeScheduler builds trusted profiles from the Computers registered by
// application bootstrap and stores every decision outside execution backends.
func NewRuntimeScheduler(runtime *ComputerRuntime, auditPath string) (*scheduler.Scheduler, error) {
	if runtime == nil || runtime.Computers == nil {
		return nil, ErrComputerRuntimeRequired
	}
	observer, err := scheduler.NewFileObserver(auditPath)
	if err != nil {
		return nil, fmt.Errorf("initialize scheduler audit observer: %w", err)
	}

	profiles := make([]scheduler.Profile, 0)
	for _, candidate := range runtime.Computers.List() {
		scopes, supported := trustedScopes(candidate.Backend())
		if !supported {
			continue
		}
		profiles = append(profiles, scheduler.Profile{
			ComputerID:   candidate.ID(),
			Capabilities: []string{"*"},
			Scopes:       scopes,
		})
	}
	runtimeScheduler, err := scheduler.New(runtime.Computers, profiles, observer)
	if err != nil {
		return nil, fmt.Errorf("initialize runtime scheduler: %w", err)
	}
	return runtimeScheduler, nil
}

func trustedScopes(backend computer.Backend) ([]scheduler.Scope, bool) {
	switch backend {
	case computer.BackendLocal:
		return []scheduler.Scope{scheduler.ScopeWorkspace, scheduler.ScopeHost}, true
	case computer.BackendDocker:
		return []scheduler.Scope{scheduler.ScopeWorkspace, scheduler.ScopeIsolated}, true
	case computer.BackendSSH:
		return []scheduler.Scope{scheduler.ScopeWorkspace, scheduler.ScopeRemote}, true
	default:
		return nil, false
	}
}
