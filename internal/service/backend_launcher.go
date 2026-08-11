package service

import (
	"context"
	"fmt"

	"github.com/chenchunrun/SecOps/internal/computer"
)

// BackendLauncher dispatches to trusted launchers using the selected
// Computer's backend. Service declarations cannot choose this route.
type BackendLauncher struct {
	launchers map[computer.Backend]Launcher
}

func NewBackendLauncher(launchers map[computer.Backend]Launcher) (*BackendLauncher, error) {
	if len(launchers) == 0 {
		return nil, ErrBackendUnsupported
	}
	registered := make(map[computer.Backend]Launcher, len(launchers))
	for backend, launcher := range launchers {
		if !backend.Valid() || launcher == nil {
			return nil, ErrBackendUnsupported
		}
		registered[backend] = launcher
	}
	return &BackendLauncher{launchers: registered}, nil
}

func (l *BackendLauncher) Start(ctx context.Context, machine computer.Computer, spec Spec) (Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, ErrBackendUnsupported
	}
	launcher, exists := l.launchers[machine.Backend()]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrBackendUnsupported, machine.Backend())
	}
	return launcher.Start(ctx, machine, spec)
}
