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
	"github.com/chenchunrun/SecOps/internal/service"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
	"github.com/chenchunrun/SecOps/internal/workspace"
)

const (
	DefaultLocalComputerID  computer.ID  = "local-default"
	DefaultDockerComputerID computer.ID  = "docker-default"
	DefaultSSHComputerID    computer.ID  = "ssh-default"
	DefaultWorkspaceID      workspace.ID = "default"
)

type ComputerRuntime struct {
	Computers         *computer.Manager
	Tasks             *taskruntime.Runtime
	Workspaces        *workspace.Manager
	Recovered         []taskruntime.Task
	Services          *service.Manager
	RecoveredServices []service.Service
}

func NewComputerRuntime(ctx context.Context, cfg *config.Config) (*ComputerRuntime, error) {
	dataDirectory := ""
	if cfg != nil && cfg.Options != nil {
		dataDirectory = strings.TrimSpace(cfg.Options.DataDirectory)
	}
	if dataDirectory == "" {
		dataDirectory = filepath.Dir(config.GlobalConfigData())
	}
	return newComputerRuntimeWithConfig(ctx, filepath.Join(dataDirectory, "runtime"), cfg)
}

func newComputerRuntime(ctx context.Context, runtimeRoot string) (*ComputerRuntime, error) {
	return newComputerRuntimeWithConfig(ctx, runtimeRoot, nil)
}

func newComputerRuntimeWithConfig(ctx context.Context, runtimeRoot string, cfg *config.Config) (*ComputerRuntime, error) {
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
	dockerProfiles := make(map[computer.ID]service.DockerProfile)
	sshProfiles := make(map[computer.ID]service.SSHProfile)
	if cfg != nil && cfg.Sandbox != nil && strings.EqualFold(strings.TrimSpace(cfg.Sandbox.Mode), "docker") &&
		strings.TrimSpace(cfg.Sandbox.Image) != "" {
		dockerComputer, err := computer.NewDockerComputer(DefaultDockerComputerID)
		if err != nil {
			return nil, fmt.Errorf("initialize default Docker computer: %w", err)
		}
		if err := manager.Register(dockerComputer); err != nil {
			return nil, fmt.Errorf("register default Docker computer: %w", err)
		}
		dockerProfiles[DefaultDockerComputerID] = service.DockerProfile{
			Image:   cfg.Sandbox.Image,
			Network: cfg.Sandbox.Network,
		}
	}
	if cfg != nil && cfg.Sandbox != nil && strings.EqualFold(strings.TrimSpace(cfg.Sandbox.Mode), "ssh") &&
		strings.TrimSpace(cfg.Sandbox.Host) != "" {
		sshComputer, err := computer.NewSSHComputer(
			DefaultSSHComputerID,
			strings.TrimSpace(cfg.Sandbox.User),
			strings.TrimSpace(cfg.Sandbox.KeyPath),
		)
		if err != nil {
			return nil, fmt.Errorf("initialize default SSH computer: %w", err)
		}
		if err := manager.Register(sshComputer); err != nil {
			return nil, fmt.Errorf("register default SSH computer: %w", err)
		}
		sshProfiles[DefaultSSHComputerID] = service.SSHProfile{
			Target:  sshTarget(cfg.Sandbox.User, cfg.Sandbox.Host),
			KeyPath: strings.TrimSpace(cfg.Sandbox.KeyPath),
		}
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
	serviceStore, err := service.NewFileStore(filepath.Join(runtimeRoot, "services"))
	if err != nil {
		return nil, fmt.Errorf("initialize durable service store: %w", err)
	}
	serviceLogRoot := filepath.Join(runtimeRoot, "service-logs")
	localServiceLauncher, err := service.NewLocalLauncher(serviceLogRoot)
	if err != nil {
		return nil, fmt.Errorf("initialize local service launcher: %w", err)
	}
	serviceLaunchers := map[computer.Backend]service.Launcher{
		computer.BackendLocal: localServiceLauncher,
	}
	if len(dockerProfiles) > 0 {
		dockerServiceLauncher, err := service.NewDockerLauncher(serviceLogRoot, dockerProfiles)
		if err != nil {
			return nil, fmt.Errorf("initialize Docker service launcher: %w", err)
		}
		serviceLaunchers[computer.BackendDocker] = dockerServiceLauncher
	}
	if len(sshProfiles) > 0 {
		sshServiceLauncher, err := service.NewSSHLauncher(serviceLogRoot, sshProfiles)
		if err != nil {
			return nil, fmt.Errorf("initialize SSH service launcher: %w", err)
		}
		serviceLaunchers[computer.BackendSSH] = sshServiceLauncher
	}
	serviceLauncher, err := service.NewBackendLauncher(serviceLaunchers)
	if err != nil {
		return nil, fmt.Errorf("initialize service backend launcher: %w", err)
	}
	services, err := service.NewManager(serviceStore, manager, serviceLauncher)
	if err != nil {
		return nil, fmt.Errorf("initialize durable service manager: %w", err)
	}
	recoveredServices, err := services.Recover(ctx)
	if err != nil {
		return nil, fmt.Errorf("recover durable services: %w", err)
	}
	if len(recoveredServices) > 0 {
		slog.Warn("Recovered interrupted durable services", "count", len(recoveredServices))
	}
	return &ComputerRuntime{
		Computers:         manager,
		Tasks:             tasks,
		Workspaces:        workspaces,
		Recovered:         recovered,
		Services:          services,
		RecoveredServices: recoveredServices,
	}, nil
}
