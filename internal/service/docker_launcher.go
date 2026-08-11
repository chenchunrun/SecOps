package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
)

const (
	defaultDockerStopTimeout = 5 * time.Second
	maximumDockerStopTimeout = 5 * time.Minute
)

var dockerNetworkPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// DockerProfile is trusted backend configuration selected by Computer ID.
// Service declarations cannot override these isolation settings.
type DockerProfile struct {
	Image          string
	Network        string
	PublishAddress string
	Shell          []string
	User           string
	WritableRoot   bool
	StopTimeout    time.Duration
}

type dockerCLI interface {
	Start(ctx context.Context, args []string, logs LogPaths) (Process, error)
	Run(ctx context.Context, args []string) ([]byte, error)
}

type dockerLauncherOption func(*DockerLauncher)

func withDockerCLI(cli dockerCLI) dockerLauncherOption {
	return func(launcher *DockerLauncher) {
		if cli != nil {
			launcher.cli = cli
		}
	}
}

// DockerLauncher starts foreground Docker containers with host-owned logs.
type DockerLauncher struct {
	logRoot  string
	profiles map[computer.ID]DockerProfile
	cli      dockerCLI
	nextID   atomic.Uint64
}

func NewDockerLauncher(logRoot string, profiles map[computer.ID]DockerProfile, options ...dockerLauncherOption) (*DockerLauncher, error) {
	logRoot = strings.TrimSpace(logRoot)
	if logRoot == "" {
		return nil, ErrInvalidDockerProfile
	}
	if err := os.MkdirAll(logRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create Docker service log directory: %w", err)
	}
	normalized := make(map[computer.ID]DockerProfile, len(profiles))
	for id, profile := range profiles {
		validated, err := normalizeDockerProfile(id, profile)
		if err != nil {
			return nil, err
		}
		normalized[id] = validated
	}
	launcher := &DockerLauncher{logRoot: logRoot, profiles: normalized, cli: execDockerCLI{}}
	for _, option := range options {
		if option != nil {
			option(launcher)
		}
	}
	return launcher, nil
}

func (l *DockerLauncher) Start(ctx context.Context, machine computer.Computer, spec Spec) (Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if machine == nil || machine.Backend() != computer.BackendDocker {
		return nil, ErrBackendUnsupported
	}
	profile, exists := l.profiles[machine.ID()]
	if !exists {
		return nil, ErrBackendUnsupported
	}
	if err := validateSpec(spec); err != nil {
		return nil, err
	}
	if len(spec.Ports) > 0 && profile.Network == "none" {
		return nil, ErrPortPublishingDisabled
	}
	containerName := l.containerName(machine.ID())
	logs := LogPaths{
		Stdout: filepath.Join(l.logRoot, containerName+".stdout.log"),
		Stderr: filepath.Join(l.logRoot, containerName+".stderr.log"),
	}
	process, err := l.cli.Start(ctx, buildDockerServiceArgs(containerName, profile, spec), logs)
	if err != nil {
		return nil, fmt.Errorf("start Docker service container: %w", err)
	}
	return &dockerProcess{Process: process, cli: l.cli, containerName: containerName, stopTimeout: profile.StopTimeout}, nil
}

func (l *DockerLauncher) containerName(id computer.ID) string {
	name := strings.ToLower(string(id))
	name = strings.NewReplacer("_", "-", ".", "-").Replace(name)
	return fmt.Sprintf("secops-%s-%d-%06d", name, time.Now().UTC().UnixNano(), l.nextID.Add(1))
}

func normalizeDockerProfile(id computer.ID, profile DockerProfile) (DockerProfile, error) {
	if strings.TrimSpace(string(id)) == "" {
		return DockerProfile{}, ErrInvalidDockerProfile
	}
	profile.Image = strings.TrimSpace(profile.Image)
	profile.Network = strings.TrimSpace(profile.Network)
	profile.PublishAddress = strings.TrimSpace(profile.PublishAddress)
	profile.User = strings.TrimSpace(profile.User)
	if profile.Image == "" || strings.ContainsAny(profile.Image, " \t\r\n") {
		return DockerProfile{}, fmt.Errorf("%w: image is required", ErrInvalidDockerProfile)
	}
	if profile.Network == "" {
		profile.Network = "none"
	}
	if !dockerNetworkPattern.MatchString(profile.Network) {
		return DockerProfile{}, fmt.Errorf("%w: invalid network", ErrInvalidDockerProfile)
	}
	if profile.PublishAddress == "" {
		profile.PublishAddress = "127.0.0.1"
	}
	publishIP := net.ParseIP(profile.PublishAddress)
	if publishIP == nil || !publishIP.IsLoopback() {
		return DockerProfile{}, fmt.Errorf("%w: publish address must be loopback", ErrInvalidDockerProfile)
	}
	if len(profile.Shell) == 0 {
		profile.Shell = []string{"/bin/sh", "-c"}
	}
	for _, argument := range profile.Shell {
		if strings.TrimSpace(argument) == "" {
			return DockerProfile{}, fmt.Errorf("%w: shell contains an empty argument", ErrInvalidDockerProfile)
		}
	}
	profile.Shell = append([]string(nil), profile.Shell...)
	if profile.User == "" {
		profile.User = "65534:65534"
	}
	if profile.StopTimeout == 0 {
		profile.StopTimeout = defaultDockerStopTimeout
	}
	if profile.StopTimeout < time.Second || profile.StopTimeout > maximumDockerStopTimeout {
		return DockerProfile{}, fmt.Errorf("%w: invalid stop timeout", ErrInvalidDockerProfile)
	}
	return profile, nil
}

func buildDockerServiceArgs(containerName string, profile DockerProfile, spec Spec) []string {
	args := []string{
		"run", "--rm", "--name", containerName,
		"--network=" + profile.Network,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--user", profile.User,
	}
	if !profile.WritableRoot {
		args = append(args, "--read-only", "--tmpfs=/tmp:rw,noexec,nosuid,size=64m")
	}
	if spec.WorkingDirectory != "" {
		args = append(args, "--workdir", spec.WorkingDirectory)
	}
	ports := append([]Port(nil), spec.Ports...)
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Number != ports[j].Number {
			return ports[i].Number < ports[j].Number
		}
		return ports[i].Protocol < ports[j].Protocol
	})
	for _, port := range ports {
		published := net.JoinHostPort(profile.PublishAddress, strconv.Itoa(port.Number)) +
			":" + strconv.Itoa(port.Number) + "/" + string(port.Protocol)
		args = append(args, "--publish", published)
	}
	args = append(args, profile.Image)
	args = append(args, profile.Shell...)
	args = append(args, spec.Command)
	return args
}

type dockerProcess struct {
	Process
	cli           dockerCLI
	containerName string
	stopTimeout   time.Duration
	stopOnce      sync.Once
	stopErr       error
}

func (p *dockerProcess) Stop(ctx context.Context) error {
	p.stopOnce.Do(func() {
		seconds := int(p.stopTimeout / time.Second)
		output, stopErr := p.cli.Run(ctx, []string{"stop", "--time", strconv.Itoa(seconds), p.containerName})
		if stopErr == nil {
			return
		}
		removeOutput, removeErr := p.cli.Run(ctx, []string{"rm", "--force", p.containerName})
		if removeErr != nil {
			p.stopErr = fmt.Errorf("stop Docker service container: %w", errors.Join(
				fmt.Errorf("docker stop: %w: %s", stopErr, strings.TrimSpace(string(output))),
				fmt.Errorf("docker rm: %w: %s", removeErr, strings.TrimSpace(string(removeOutput))),
			))
		}
	})
	return p.stopErr
}

type execDockerCLI struct{}

func (execDockerCLI) Start(ctx context.Context, args []string, logs LogPaths) (Process, error) {
	stdout, err := os.OpenFile(logs.Stdout, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create Docker service stdout log: %w", err)
	}
	stderr, err := os.OpenFile(logs.Stderr, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = stdout.Close()
		_ = os.Remove(logs.Stdout)
		return nil, fmt.Errorf("create Docker service stderr log: %w", err)
	}
	command := exec.CommandContext(context.WithoutCancel(ctx), "docker", args...)
	command.Stdout = stdout
	command.Stderr = stderr
	configureServiceProcess(command)
	if err := command.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, err
	}
	process := &localProcess{command: command, logs: logs, done: make(chan struct{})}
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

func (execDockerCLI) Run(ctx context.Context, args []string) ([]byte, error) {
	return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
}
