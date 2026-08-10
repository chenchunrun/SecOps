package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
	"github.com/chenchunrun/SecOps/internal/workspace"
)

const (
	DefaultLocalComputerID computer.ID  = "local-default"
	DefaultWorkspaceID     workspace.ID = "default"
)

type ComputerRuntime struct {
	Computers  *computer.Manager
	Tasks      *taskruntime.Runtime
	Workspaces *workspace.Manager
	Recovered  []taskruntime.Task
}

func NewComputerRuntime(ctx context.Context, cfg *config.Config) (*ComputerRuntime, error) {
	dataDirectory := ""
	if cfg != nil && cfg.Options != nil {
		dataDirectory = strings.TrimSpace(cfg.Options.DataDirectory)
	}
	if dataDirectory == "" {
		dataDirectory = filepath.Dir(config.GlobalConfigData())
	}
	return newComputerRuntime(ctx, filepath.Join(dataDirectory, "runtime"))
}

func newComputerRuntime(ctx context.Context, runtimeRoot string) (*ComputerRuntime, error) {
	store, err := taskruntime.NewFileStore(filepath.Join(runtimeRoot, "tasks"))
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
	workspaces, err := workspace.NewManager(
		filepath.Join(runtimeRoot, "workspaces"),
		filepath.Join(runtimeRoot, "snapshots"),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize workspace runtime: %w", err)
	}
	if _, err := workspaces.Get(ctx, DefaultWorkspaceID); errors.Is(err, workspace.ErrNotFound) {
		if _, err := workspaces.Create(ctx, DefaultWorkspaceID); err != nil {
			return nil, fmt.Errorf("create default workspace: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("load default workspace: %w", err)
	}

	recovered, err := tasks.Recover(ctx)
	if err != nil {
		return nil, fmt.Errorf("recover durable tasks: %w", err)
	}
	if len(recovered) > 0 {
		slog.Warn("Recovered interrupted durable tasks", "count", len(recovered))
	}
	return &ComputerRuntime{
		Computers:  manager,
		Tasks:      tasks,
		Workspaces: workspaces,
		Recovered:  recovered,
	}, nil
}
