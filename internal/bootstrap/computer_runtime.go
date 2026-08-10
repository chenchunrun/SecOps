package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
)

const DefaultLocalComputerID computer.ID = "local-default"

type ComputerRuntime struct {
	Computers *computer.Manager
	Tasks     *taskruntime.Runtime
	Recovered []taskruntime.Task
}

func NewComputerRuntime(ctx context.Context, cfg *config.Config) (*ComputerRuntime, error) {
	dataDirectory := ""
	if cfg != nil && cfg.Options != nil {
		dataDirectory = strings.TrimSpace(cfg.Options.DataDirectory)
	}
	if dataDirectory == "" {
		dataDirectory = filepath.Dir(config.GlobalConfigData())
	}
	return newComputerRuntime(ctx, filepath.Join(dataDirectory, "runtime", "tasks"))
}

func newComputerRuntime(ctx context.Context, stateRoot string) (*ComputerRuntime, error) {
	store, err := taskruntime.NewFileStore(stateRoot)
	if err != nil {
		return nil, fmt.Errorf("initialize durable task store: %w", err)
	}
	tasks, err := taskruntime.New(store)
	if err != nil {
		return nil, fmt.Errorf("initialize durable task runtime: %w", err)
	}
	manager := computer.NewManager()
	local, err := computer.NewLocalComputer(DefaultLocalComputerID)
	if err != nil {
		return nil, fmt.Errorf("initialize default local computer: %w", err)
	}
	if err := manager.Register(local); err != nil {
		return nil, fmt.Errorf("register default local computer: %w", err)
	}

	recovered, err := tasks.Recover(ctx)
	if err != nil {
		return nil, fmt.Errorf("recover durable tasks: %w", err)
	}
	if len(recovered) > 0 {
		slog.Warn("Recovered interrupted durable tasks", "count", len(recovered))
	}
	return &ComputerRuntime{
		Computers: manager,
		Tasks:     tasks,
		Recovered: recovered,
	}, nil
}
