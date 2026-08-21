package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/chenchunrun/SecOps/internal/admission"
	"github.com/chenchunrun/SecOps/internal/collaboration"
	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/evidence"
	"github.com/chenchunrun/SecOps/internal/service"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
	"github.com/chenchunrun/SecOps/internal/verification"
	"github.com/chenchunrun/SecOps/internal/workspace"
)

const (
	DefaultLocalComputerID  computer.ID  = "local-default"
	DefaultDockerComputerID computer.ID  = "docker-default"
	DefaultSSHComputerID    computer.ID  = "ssh-default"
	DefaultWorkspaceID      workspace.ID = "default"
)

type ComputerRuntime struct {
	Computers           *computer.Manager
	Tasks               *taskruntime.Runtime
	Workspaces          *workspace.Manager
	Recovered           []taskruntime.Task
	VerificationStore   *verification.FileStore
	VerificationMaker   *verification.Maker
	VerificationChecker *verification.Checker
	EvidenceStore       *evidence.FileStore
	HandoffStore        *collaboration.FileStore
	AdmissionStore      admission.Store
	Admission           *admission.Manager
	Services            *service.Manager
	RecoveredServices   []service.Service
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
	verificationStore, err := verification.NewFileStore(filepath.Join(runtimeRoot, "verifications"))
	if err != nil {
		return nil, fmt.Errorf("initialize verification store: %w", err)
	}
	verificationMaker, err := verification.NewMaker(verificationStore)
	if err != nil {
		return nil, fmt.Errorf("initialize verification maker: %w", err)
	}
	verificationChecker, err := verification.NewChecker(verificationStore)
	if err != nil {
		return nil, fmt.Errorf("initialize verification checker: %w", err)
	}
	evidenceStore, err := evidence.NewFileStore(filepath.Join(runtimeRoot, "evidence"))
	if err != nil {
		return nil, fmt.Errorf("initialize evidence store: %w", err)
	}
	handoffStore, err := collaboration.NewFileStore(filepath.Join(runtimeRoot, "handoffs"))
	if err != nil {
		return nil, fmt.Errorf("initialize handoff store: %w", err)
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
	admissionBackend := ""
	if cfg != nil && cfg.Sandbox != nil {
		admissionBackend = cfg.Sandbox.AdmissionStore
	}
	admissionStore, err := initializeAdmissionStore(ctx, runtimeRoot, admissionBackend)
	if err != nil {
		return nil, fmt.Errorf("initialize admission store: %w", err)
	}
	admissionProfiles := make([]admission.Profile, 0)
	for _, machine := range manager.List() {
		admissionProfiles = append(admissionProfiles, admission.Profile{
			ComputerID: machine.ID(),
			Capacity:   admissionCapacityFor(cfg, machine.Backend()),
		})
	}
	admissionManager, err := admission.NewManager(admissionStore, admissionProfiles)
	if err != nil {
		return nil, fmt.Errorf("initialize admission manager: %w", err)
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
	releasedLeases, err := admissionManager.Reconcile(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("reconcile orphaned admission leases: %w", err)
	}
	if len(releasedLeases) > 0 {
		slog.Warn("Released orphaned admission leases", "count", len(releasedLeases))
	}
	for _, lease := range releasedLeases {
		_, err := tasks.MarkAdmissionReleased(
			ctx,
			taskruntime.ID(lease.TaskID),
			lease.ID,
			lease.ReleasedAt,
		)
		if errors.Is(err, taskruntime.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reconcile task admission lease %s: %w", lease.ID, err)
		}
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
		Computers:           manager,
		Tasks:               tasks,
		Workspaces:          workspaces,
		Recovered:           recovered,
		VerificationStore:   verificationStore,
		VerificationMaker:   verificationMaker,
		VerificationChecker: verificationChecker,
		EvidenceStore:       evidenceStore,
		HandoffStore:        handoffStore,
		AdmissionStore:      admissionStore,
		Admission:           admissionManager,
		Services:            services,
		RecoveredServices:   recoveredServices,
	}, nil
}

func admissionStorePath(runtimeRoot string) string {
	return filepath.Join(runtimeRoot, "admission")
}

func initializeAdmissionStore(ctx context.Context, runtimeRoot, backend string) (admission.Store, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(backend)); normalized {
	case "", "file":
		return admission.NewFileStore(admissionStorePath(runtimeRoot))
	case "sqlite":
		fileStore, err := admission.NewFileStore(admissionStorePath(runtimeRoot))
		if err != nil {
			return nil, fmt.Errorf("initialize migration source: %w", err)
		}
		sqliteStore, err := admission.OpenSQLiteStore(ctx, filepath.Join(runtimeRoot, "admission.db"))
		if err != nil {
			return nil, err
		}
		if _, err := admission.MigrateFileStoreToSQLite(ctx, fileStore, sqliteStore); err != nil {
			_ = sqliteStore.Close()
			return nil, fmt.Errorf("migrate admission store to sqlite: %w", err)
		}
		return sqliteStore, nil
	default:
		return nil, fmt.Errorf("unsupported admission store %q", backend)
	}
}
