package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
)

// LocalLauncher starts host processes while keeping logs in a host-owned root.
type LocalLauncher struct {
	logRoot string
	nextID  atomic.Uint64
}

func NewLocalLauncher(logRoot string) (*LocalLauncher, error) {
	logRoot = strings.TrimSpace(logRoot)
	if logRoot == "" {
		return nil, ErrInvalidService
	}
	if err := os.MkdirAll(logRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create local service log directory: %w", err)
	}
	return &LocalLauncher{logRoot: logRoot}, nil
}

func (l *LocalLauncher) Start(ctx context.Context, machine computer.Computer, spec Spec) (Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if machine == nil || machine.Backend() != computer.BackendLocal {
		return nil, ErrBackendUnsupported
	}
	if state := machine.State(); state == computer.StateDestroyed || state == computer.StateSuspended || state == computer.StateProvisioning {
		return nil, fmt.Errorf("%w: computer state is %s", ErrBackendUnsupported, state)
	}
	if err := validateSpec(spec); err != nil {
		return nil, err
	}
	id := fmt.Sprintf("%d-%06d", time.Now().UTC().UnixNano(), l.nextID.Add(1))
	logs := LogPaths{
		Stdout: filepath.Join(l.logRoot, id+".stdout.log"),
		Stderr: filepath.Join(l.logRoot, id+".stderr.log"),
	}
	stdout, err := os.OpenFile(logs.Stdout, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create local service stdout log: %w", err)
	}
	stderr, err := os.OpenFile(logs.Stderr, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = stdout.Close()
		_ = os.Remove(logs.Stdout)
		return nil, fmt.Errorf("create local service stderr log: %w", err)
	}
	command := localServiceCommand(ctx, spec.Command)
	command.Dir = spec.WorkingDirectory
	command.Stdout = stdout
	command.Stderr = stderr
	configureServiceProcess(command)
	if err := command.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, fmt.Errorf("start local service process: %w", err)
	}
	process := &localProcess{
		command: command,
		logs:    logs,
		done:    make(chan struct{}),
	}
	go func() {
		waitErr := command.Wait()
		_ = stdout.Close()
		_ = stderr.Close()
		process.mu.Lock()
		process.err = waitErr
		process.mu.Unlock()
		close(process.done)
	}()
	return process, nil
}

func localServiceCommand(ctx context.Context, command string) *exec.Cmd {
	serviceContext := context.WithoutCancel(ctx)
	if runtime.GOOS == "windows" {
		return exec.CommandContext(serviceContext, "cmd.exe", "/C", command)
	}
	return exec.CommandContext(serviceContext, "/bin/sh", "-c", command)
}

type localProcess struct {
	command *exec.Cmd
	logs    LogPaths
	done    chan struct{}
	mu      sync.Mutex
	err     error
}

func (p *localProcess) PID() int       { return p.command.Process.Pid }
func (p *localProcess) Logs() LogPaths { return p.logs }
func (p *localProcess) Wait() error {
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *localProcess) Stop(ctx context.Context) error {
	return stopServiceProcess(ctx, p.command.Process, p.done)
}
