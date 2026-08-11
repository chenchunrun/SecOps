package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
)

var (
	ErrInvalidSSHProfile   = errors.New("invalid SSH service profile")
	ErrInvalidSSHProcessID = errors.New("invalid SSH service process ID")
)

var sshTargetPattern = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_.-]*@)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`)

type SSHProfile struct {
	Target          string
	Port            int
	KeyPath         string
	ProxyJump       string
	RemoteDirectory string
	ConnectTimeout  time.Duration
	PollInterval    time.Duration
}

type sshCLI interface {
	Run(ctx context.Context, args []string) ([]byte, error)
}

type sshLauncherOption func(*SSHLauncher)

func withSSHCLI(cli sshCLI) sshLauncherOption {
	return func(launcher *SSHLauncher) {
		launcher.cli = cli
	}
}

type SSHLauncher struct {
	logRoot  string
	profiles map[computer.ID]SSHProfile
	cli      sshCLI
	sequence atomic.Uint64
}

func NewSSHLauncher(logRoot string, profiles map[computer.ID]SSHProfile, options ...sshLauncherOption) (*SSHLauncher, error) {
	normalized := make(map[computer.ID]SSHProfile, len(profiles))
	for id, profile := range profiles {
		profile = normalizeSSHProfile(profile)
		if err := validateSSHProfile(profile); err != nil {
			return nil, fmt.Errorf("%w for computer %q: %v", ErrInvalidSSHProfile, id, err)
		}
		normalized[id] = profile
	}
	launcher := &SSHLauncher{logRoot: logRoot, profiles: normalized, cli: operatingSystemSSHCLI{}}
	for _, option := range options {
		option(launcher)
	}
	if launcher.cli == nil {
		return nil, fmt.Errorf("%w: SSH CLI is nil", ErrInvalidSSHProfile)
	}
	return launcher, nil
}

func (l *SSHLauncher) Start(ctx context.Context, machine computer.Computer, spec Spec) (Process, error) {
	profile, ok := l.profiles[machine.ID()]
	if !ok || machine.Backend() != computer.BackendSSH {
		return nil, fmt.Errorf("%w: no trusted SSH profile for computer %q", ErrBackendUnsupported, machine.ID())
	}
	if strings.TrimSpace(spec.Command) == "" {
		return nil, fmt.Errorf("%w: command is empty", ErrInvalidSSHProfile)
	}

	name := fmt.Sprintf("secops-%s-%d", safeServiceName(string(machine.ID())), l.sequence.Add(1))
	remoteStdout := profile.RemoteDirectory + "/" + name + ".stdout.log"
	remoteStderr := profile.RemoteDirectory + "/" + name + ".stderr.log"
	logs, err := createSSHLogPaths(l.logRoot, name)
	if err != nil {
		return nil, err
	}
	args := sshBaseArgs(profile)
	args = append(args, profile.Target, sshLaunchCommand(profile, spec, remoteStdout, remoteStderr))
	output, err := l.cli.Run(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("start SSH service: %w", err)
	}
	pid, err := parseSSHProcessID(output)
	if err != nil {
		return nil, err
	}

	monitorContext, cancel := context.WithCancel(context.Background())
	process := &sshServiceProcess{
		pid:          pid,
		logs:         logs,
		remoteStdout: remoteStdout,
		remoteStderr: remoteStderr,
		profile:      profile,
		cli:          l.cli,
		monitorCtx:   monitorContext,
		cancel:       cancel,
		done:         make(chan struct{}),
	}
	go process.monitor()
	return process, nil
}

func normalizeSSHProfile(profile SSHProfile) SSHProfile {
	profile.Target = strings.TrimSpace(profile.Target)
	profile.KeyPath = strings.TrimSpace(profile.KeyPath)
	profile.ProxyJump = strings.TrimSpace(profile.ProxyJump)
	profile.RemoteDirectory = strings.TrimSpace(profile.RemoteDirectory)
	if profile.Port == 0 {
		profile.Port = 22
	}
	if profile.RemoteDirectory == "" {
		profile.RemoteDirectory = "/tmp/secops-services"
	}
	if profile.ConnectTimeout == 0 {
		profile.ConnectTimeout = 10 * time.Second
	}
	if profile.PollInterval == 0 {
		profile.PollInterval = 2 * time.Second
	}
	return profile
}

func validateSSHProfile(profile SSHProfile) error {
	if !sshTargetPattern.MatchString(profile.Target) {
		return fmt.Errorf("invalid target")
	}
	if profile.Port < 1 || profile.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if strings.ContainsAny(profile.KeyPath, "\r\n\x00") {
		return fmt.Errorf("key path contains control characters")
	}
	if profile.ProxyJump != "" && !sshTargetPattern.MatchString(profile.ProxyJump) {
		return fmt.Errorf("invalid proxy jump")
	}
	if !strings.HasPrefix(profile.RemoteDirectory, "/") || strings.ContainsAny(profile.RemoteDirectory, "\r\n\x00") {
		return fmt.Errorf("remote directory must be an absolute POSIX path")
	}
	if profile.ConnectTimeout <= 0 || profile.ConnectTimeout > 5*time.Minute {
		return fmt.Errorf("connect timeout must be between zero and five minutes")
	}
	if profile.PollInterval <= 0 {
		return fmt.Errorf("poll interval must be positive")
	}
	return nil
}

func sshBaseArgs(profile SSHProfile) []string {
	args := []string{
		"-T",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "LogLevel=ERROR",
		"-o", "ClearAllForwardings=yes",
		"-o", "ConnectTimeout=" + strconv.Itoa(max(1, int(profile.ConnectTimeout/time.Second))),
		"-p", strconv.Itoa(profile.Port),
	}
	if profile.KeyPath != "" {
		args = append(args, "-i", profile.KeyPath)
	}
	if profile.ProxyJump != "" {
		args = append(args, "-J", profile.ProxyJump)
	}
	return args
}

func sshLaunchCommand(profile SSHProfile, spec Spec, stdout, stderr string) string {
	workingDirectory := strings.TrimSpace(spec.WorkingDirectory)
	if workingDirectory == "" {
		workingDirectory = profile.RemoteDirectory
	}
	return "umask 077; mkdir -p -- " + shellQuote(profile.RemoteDirectory) +
		"; cd -- " + shellQuote(workingDirectory) +
		"; nohup setsid /bin/sh -c " + shellQuote(spec.Command) +
		" >" + shellQuote(stdout) + " 2>" + shellQuote(stderr) +
		" </dev/null & printf '%s\\n' \"$!\""
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func parseSSHProcessID(output []byte) (int, error) {
	pid, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("%w: %q", ErrInvalidSSHProcessID, strings.TrimSpace(string(output)))
	}
	return pid, nil
}

func safeServiceName(value string) string {
	var builder strings.Builder
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z', character >= '0' && character <= '9', character == '-', character == '_':
			builder.WriteRune(character)
		default:
			builder.WriteByte('-')
		}
	}
	if builder.Len() == 0 {
		return "service"
	}
	return builder.String()
}

func createSSHLogPaths(root, name string) (LogPaths, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return LogPaths{}, fmt.Errorf("create SSH service log directory: %w", err)
	}
	logs := LogPaths{
		Stdout: filepath.Join(root, name+".stdout.log"),
		Stderr: filepath.Join(root, name+".stderr.log"),
	}
	for _, path := range []string{logs.Stdout, logs.Stderr} {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return LogPaths{}, fmt.Errorf("create SSH service log: %w", err)
		}
		if err := file.Close(); err != nil {
			return LogPaths{}, fmt.Errorf("close SSH service log: %w", err)
		}
	}
	return logs, nil
}

type sshServiceProcess struct {
	pid          int
	logs         LogPaths
	remoteStdout string
	remoteStderr string
	profile      SSHProfile
	cli          sshCLI
	monitorCtx   context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	completeOnce sync.Once
	stopOnce     sync.Once
	mu           sync.Mutex
	waitErr      error
	stopErr      error
}

func (p *sshServiceProcess) PID() int       { return p.pid }
func (p *sshServiceProcess) Logs() LogPaths { return p.logs }

func (p *sshServiceProcess) Wait() error {
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.waitErr
}

func (p *sshServiceProcess) Stop(ctx context.Context) error {
	p.stopOnce.Do(func() {
		p.cancel()
		args := p.commandArgs(fmt.Sprintf("kill -TERM -- -%d", p.pid))
		if _, err := p.cli.Run(ctx, args); err != nil {
			if _, killErr := p.cli.Run(ctx, p.commandArgs(fmt.Sprintf("kill -KILL -- -%d", p.pid))); killErr != nil {
				p.stopErr = fmt.Errorf("stop SSH service: TERM failed: %v; KILL failed: %w", err, killErr)
			}
		}
		p.syncLogs(ctx)
		p.complete(nil)
	})
	return p.stopErr
}

func (p *sshServiceProcess) monitor() {
	ticker := time.NewTicker(p.profile.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.monitorCtx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(p.monitorCtx, p.profile.ConnectTimeout)
			_, err := p.cli.Run(ctx, p.commandArgs(fmt.Sprintf("kill -0 -- -%d", p.pid)))
			cancel()
			if err != nil {
				syncContext, syncCancel := context.WithTimeout(context.Background(), p.profile.ConnectTimeout)
				p.syncLogs(syncContext)
				syncCancel()
				p.complete(nil)
				return
			}
		}
	}
}

func (p *sshServiceProcess) syncLogs(ctx context.Context) {
	for remote, local := range map[string]string{
		p.remoteStdout: p.logs.Stdout,
		p.remoteStderr: p.logs.Stderr,
	} {
		output, err := p.cli.Run(ctx, p.commandArgs("cat -- "+shellQuote(remote)))
		if err != nil {
			continue
		}
		if err := os.WriteFile(local, output, 0o600); err != nil {
			continue
		}
	}
}

func (p *sshServiceProcess) commandArgs(command string) []string {
	args := sshBaseArgs(p.profile)
	return append(args, p.profile.Target, command)
}

func (p *sshServiceProcess) complete(err error) {
	p.completeOnce.Do(func() {
		p.mu.Lock()
		p.waitErr = err
		p.mu.Unlock()
		close(p.done)
	})
}

type operatingSystemSSHCLI struct{}

func (operatingSystemSSHCLI) Run(ctx context.Context, args []string) ([]byte, error) {
	path, err := exec.LookPath("ssh")
	if err != nil {
		return nil, fmt.Errorf("find SSH executable: %w", err)
	}
	command := exec.CommandContext(ctx, path, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("run SSH command: %w", err)
	}
	return output, nil
}
