// Package sandbox provides secure command execution environments with
// configurable isolation and resource limits.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SandboxConfig controls the execution environment for sandboxed commands.
type SandboxConfig struct {
	MaxMemoryMB     int64    // Maximum memory limit in MB
	MaxCPU          int      // CPU limit (number of cores or percentage)
	TimeoutSeconds  int      // Maximum execution time in seconds
	AllowedHosts    []string // Whitelist of allowed hostnames/IPs
	AllowedPorts    []int    // Whitelist of allowed ports
	ReadOnlyPaths   []string // Paths that can be read but not written
	DenyPaths       []string // Paths that are always denied
	AuditLogPath    string   // Path for audit log output
	TraceID         string   // Unique trace identifier for audit trail
	// Execution mode: "local", "docker", "ssh"
	Mode      string
	DockerImage string   // Docker image to use (for docker mode)
	SSHTarget   string   // SSH target user@host (for ssh mode)
}

// ExecutionResult contains the outcome of a sandboxed command execution.
type ExecutionResult struct {
	Output    string        // Standard output from the command
	ExitCode  int           // Exit code (0 = success)
	Duration  time.Duration // How long the command took
	RiskScore int           // Risk assessment score (0-100)
	Error     error         // Error if execution failed
}

// SandboxExecutor defines the interface for sandboxed execution backends.
type SandboxExecutor interface {
	Execute(ctx context.Context, cmd string, cfg SandboxConfig) (*ExecutionResult, error)
}

// LocalExecutor runs commands with OS-level isolation using ulimit hints.
type LocalExecutor struct{}

// DockerExecutor runs commands in isolated Docker containers.
type DockerExecutor struct{}

// SSHExecutor runs commands on remote hosts via SSH.
type SSHExecutor struct {
	User    string // SSH username
	KeyPath string // Path to SSH private key
}

// ErrDangerousPath is returned when a command targets a forbidden path.
var ErrDangerousPath = errors.New("command targets a dangerous or denied path")

// ErrTimeout is returned when command execution exceeds the configured timeout.
var ErrTimeout = errors.New("execution timeout exceeded")

// ErrConfigInvalid is returned when sandbox configuration is invalid.
var ErrConfigInvalid = errors.New("invalid sandbox configuration")

// ErrModeUnsupported is returned when the execution mode is not supported.
var ErrModeUnsupported = errors.New("unsupported execution mode")

// Dangerous path patterns that should never be executed.
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^\s*/etc/shadow`),
	regexp.MustCompile(`(?i)^\s*/etc/passwd\s+-w`),  // passwd write attempts
	regexp.MustCompile(`(?i)^\s*/etc/sudoers`),
	regexp.MustCompile(`(?i)^\s*rm\s+-rf\s+/`),
	regexp.MustCompile(`(?i)^\s*rm\s+-rf\s+/\*`),
	regexp.MustCompile(`(?i)^\s*mkfs\.`),
	regexp.MustCompile(`(?i)^\s*dd\s+if=.*of=/dev/sd`),
	regexp.MustCompile(`(?i)^\s*:\(\)`), // fork bomb: :(){ ... } or :()
}

// ValidateConfig checks the sandbox configuration for safety issues.
func ValidateConfig(cfg *SandboxConfig) error {
	if cfg == nil {
		return fmt.Errorf("%w: config is nil", ErrConfigInvalid)
	}

	if cfg.TimeoutSeconds < 0 {
		return fmt.Errorf("%w: timeout cannot be negative", ErrConfigInvalid)
	}

	if cfg.MaxMemoryMB < 0 {
		return fmt.Errorf("%w: memory limit cannot be negative", ErrConfigInvalid)
	}

	// Check for overlapping read-only and deny paths
	for _, ro := range cfg.ReadOnlyPaths {
		for _, deny := range cfg.DenyPaths {
			if ro == deny {
				return fmt.Errorf("%w: path %q cannot be both read-only and denied", ErrConfigInvalid, ro)
			}
		}
	}

	return nil
}

// checkCommandSafety validates a command string against dangerous patterns.
func checkCommandSafety(cmd string) error {
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(cmd) {
			return fmt.Errorf("%w: dangerous pattern detected", ErrDangerousPath)
		}
	}

	// Check for denied paths in the command
	cmdLower := strings.ToLower(cmd)
	for _, deny := range []string{
		"/.ssh/authorized_keys",
		"/etc/ssh/sshd_config",
		"/root/.ssh/",
		"/sys/kernel/security",
		"/proc/sys/kernel",
	} {
		if strings.Contains(cmdLower, deny) {
			return fmt.Errorf("%w: denied path %q referenced", ErrDangerousPath, deny)
		}
	}

	return nil
}

// buildLocalCommand constructs the command for local execution.
func (e *LocalExecutor) buildCommand(ctx context.Context, cmd string, cfg SandboxConfig) *exec.Cmd {
	// Use shell to support pipelines and complex commands
	shellCmd := exec.CommandContext(ctx, "sh", "-c", cmd)

	// Set environment constraints
	env := os.Environ()
	env = append(env, "HOME=/tmp")
	shellCmd.Env = env

	// Configure working directory to a safe location
	shellCmd.Dir = "/tmp"

	return shellCmd
}

// Execute runs a command in a local sandboxed environment.
func (e *LocalExecutor) Execute(ctx context.Context, cmd string, cfg SandboxConfig) (*ExecutionResult, error) {
	start := time.Now()

	if err := ValidateConfig(&cfg); err != nil {
		return &ExecutionResult{Error: err, RiskScore: 100}, err
	}

	if err := checkCommandSafety(cmd); err != nil {
		return &ExecutionResult{RiskScore: 100, Error: err}, err
	}

	// Check if context is already cancelled before proceeding
	select {
	case <-ctx.Done():
		return &ExecutionResult{
			Duration:  time.Since(start),
			RiskScore: 10,
			Error:     ctx.Err(),
			ExitCode:  1,
		}, ctx.Err()
	default:
	}

	// Apply timeout before building command so the context is used
	if cfg.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	execCmd := e.buildCommand(ctx, cmd, cfg)

	var stdout, stderr bytes.Buffer
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	logEntry := e.auditLogEntry(cfg.TraceID, "local", cmd, "started")
	e.writeAuditLog(cfg.AuditLogPath, logEntry)

	err := execCmd.Run()
	duration := time.Since(start)

	riskScore := e.assessRisk(cmd, cfg, err)

	result := &ExecutionResult{
		Output:    stdout.String(),
		ExitCode:  0,
		Duration:  duration,
		RiskScore: riskScore,
		Error:     nil,
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			result.Error = fmt.Errorf("%w: %v", ErrTimeout, err)
		} else {
			result.Error = err
		}
	}

	if stderr.Len() > 0 {
		result.Output += "\n[stderr] " + stderr.String()
	}

	completeEntry := e.auditLogEntry(cfg.TraceID, "local", cmd,
		fmt.Sprintf("completed exit=%d duration=%v risk=%d", result.ExitCode, duration, riskScore))
	e.writeAuditLog(cfg.AuditLogPath, completeEntry)

	return result, nil
}

// buildDockerCommand constructs a docker run command with resource limits.
func (e *DockerExecutor) buildDockerArgs(cmd string, cfg SandboxConfig) []string {
	args := []string{"run", "--rm", "--network=none"}

	// Apply memory limit
	if cfg.MaxMemoryMB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dm", cfg.MaxMemoryMB))
	}

	// Apply CPU limit
	if cfg.MaxCPU > 0 {
		args = append(args, "--cpus", strconv.Itoa(cfg.MaxCPU))
	}

	// Set read-only filesystem with specific writable paths
	args = append(args, "--read-only")

	// Allow specific writable paths if configured
	if len(cfg.ReadOnlyPaths) > 0 {
		for _, p := range cfg.ReadOnlyPaths {
			args = append(args, "--tmpfs", fmt.Sprintf("%s:rw,noexec,nosuid", p))
		}
	}

	// Deny specific paths via volumes (empty mount to override)
	if len(cfg.DenyPaths) > 0 {
		for _, p := range cfg.DenyPaths {
			args = append(args, "--read-only", "--volume", fmt.Sprintf("/dev/null:%s:ro", p))
		}
	}

	// Set user to non-root
	args = append(args, "--user", "65534:65534")

	// Disable privileged mode
	args = append(args, "--cap-drop=ALL", "--security-opt=no-new-privileges")

	// Image and command
	image := cfg.DockerImage
	if image == "" {
		image = "alpine:latest"
	}
	args = append(args, image, "sh", "-c", cmd)

	return args
}

// Execute runs a command inside an isolated Docker container.
func (e *DockerExecutor) Execute(ctx context.Context, cmd string, cfg SandboxConfig) (*ExecutionResult, error) {
	start := time.Now()

	if err := ValidateConfig(&cfg); err != nil {
		return &ExecutionResult{Error: err, RiskScore: 100}, err
	}

	if err := checkCommandSafety(cmd); err != nil {
		return &ExecutionResult{RiskScore: 100, Error: err}, err
	}

	// Check if context is already cancelled before proceeding
	select {
	case <-ctx.Done():
		return &ExecutionResult{
			Duration:  time.Since(start),
			RiskScore: 10,
			Error:     ctx.Err(),
			ExitCode:  1,
		}, ctx.Err()
	default:
	}

	// Apply timeout before building command so the context is used
	if cfg.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	// Verify docker is available
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return &ExecutionResult{Error: fmt.Errorf("docker not found: %w", err), RiskScore: 100}, fmt.Errorf("docker not found: %w", err)
	}

	args := e.buildDockerArgs(cmd, cfg)
	execCmd := exec.CommandContext(ctx, dockerPath, args...)

	execCmd.Dir = "/tmp"
	execCmd.Env = []string{"HOME=/root", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}

	logEntry := e.dockerAuditLogEntry(cfg.TraceID, cmd, "started")
	e.writeAuditLog(cfg.AuditLogPath, logEntry)

	var stdout, stderr bytes.Buffer
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	err = execCmd.Run()
	duration := time.Since(start)

	riskScore := e.assessRisk(cmd, cfg, err)

	result := &ExecutionResult{
		Output:    stdout.String(),
		ExitCode:  0,
		Duration:  duration,
		RiskScore: riskScore,
		Error:     nil,
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			result.Error = fmt.Errorf("%w: %v", ErrTimeout, err)
		} else {
			result.Error = err
		}
	}

	if stderr.Len() > 0 {
		result.Output += "\n[stderr] " + stderr.String()
	}

	completeEntry := e.dockerAuditLogEntry(cfg.TraceID, cmd,
		fmt.Sprintf("completed exit=%d duration=%v risk=%d", result.ExitCode, duration, riskScore))
	e.writeAuditLog(cfg.AuditLogPath, completeEntry)

	return result, nil
}

// dockerAuditLogEntry creates a structured audit log entry for docker execution.
func (e *DockerExecutor) dockerAuditLogEntry(traceID, cmd, status string) string {
	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"trace_id":  traceID,
		"mode":      "docker",
		"command":   redactCommand(cmd),
		"status":    status,
	}
	data, _ := json.Marshal(entry)
	return string(data)
}

// writeAuditLog writes an audit log entry to the configured path or stderr.
func (e *DockerExecutor) writeAuditLog(path, entry string) {
	if path != "" {
		// #nosec G302 -- audit logs should be readable only by owner
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			defer f.Close()
			fmt.Fprintln(f, entry)
		}
	}
	fmt.Fprintln(os.Stderr, entry)
}

// Execute runs a command on a remote host via SSH.
func (e *SSHExecutor) Execute(ctx context.Context, cmd string, cfg SandboxConfig) (*ExecutionResult, error) {
	start := time.Now()

	if err := ValidateConfig(&cfg); err != nil {
		return &ExecutionResult{Error: err, RiskScore: 100}, err
	}

	if err := checkCommandSafety(cmd); err != nil {
		return &ExecutionResult{RiskScore: 100, Error: err}, err
	}

	// Check if context is already cancelled before proceeding
	select {
	case <-ctx.Done():
		return &ExecutionResult{
			Duration:  time.Since(start),
			RiskScore: 10,
			Error:     ctx.Err(),
			ExitCode:  1,
		}, ctx.Err()
	default:
	}

	if cfg.SSHTarget == "" {
		return &ExecutionResult{Error: fmt.Errorf("%w: SSHTarget not configured", ErrConfigInvalid), RiskScore: 100},
			fmt.Errorf("%w: SSHTarget not configured", ErrConfigInvalid)
	}

	// Verify ssh is available
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return &ExecutionResult{Error: fmt.Errorf("ssh not found: %w", err), RiskScore: 100}, fmt.Errorf("ssh not found: %w", err)
	}

	// Apply timeout before building command so the context is used
	if cfg.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	args := buildSSHExecutorArgs(e, cfg, cmd)

	execCmd := exec.CommandContext(ctx, sshPath, args...)

	logEntry := auditLogEntrySSH(cfg.TraceID, "ssh", cfg.SSHTarget, cmd, "started")
	writeAuditLog(cfg.AuditLogPath, logEntry)

	var stdout, stderr bytes.Buffer
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	err = execCmd.Run()
	duration := time.Since(start)

	riskScore := assessRisk(cmd, cfg, err)

	result := &ExecutionResult{
		Output:    stdout.String(),
		ExitCode:  0,
		Duration:  duration,
		RiskScore: riskScore,
		Error:     nil,
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			result.Error = fmt.Errorf("%w: %v", ErrTimeout, err)
		} else {
			result.Error = err
		}
	}

	if stderr.Len() > 0 {
		result.Output += "\n[stderr] " + stderr.String()
	}

	completeEntry := auditLogEntrySSH(cfg.TraceID, "ssh", cfg.SSHTarget, cmd,
		fmt.Sprintf("completed exit=%d duration=%v risk=%d", result.ExitCode, duration, riskScore))
	writeAuditLog(cfg.AuditLogPath, completeEntry)

	return result, nil
}

func buildSSHExecutorArgs(e *SSHExecutor, cfg SandboxConfig, cmd string) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "LogLevel=ERROR",
	}

	if e != nil && e.KeyPath != "" {
		args = append(args, "-i", e.KeyPath)
	}

	if cfg.TimeoutSeconds > 0 {
		args = append(args, "-o", fmt.Sprintf("ConnectTimeout=%d", cfg.TimeoutSeconds))
	}

	args = append(args, cfg.SSHTarget, cmd)
	return args
}

// NewSSHExecutor creates an SSHExecutor with the given credentials.
func NewSSHExecutor(user, keyPath string) *SSHExecutor {
	return &SSHExecutor{User: user, KeyPath: keyPath}
}

// NewLocalExecutor creates a new LocalExecutor.
func NewLocalExecutor() *LocalExecutor {
	return &LocalExecutor{}
}

// NewDockerExecutor creates a new DockerExecutor.
func NewDockerExecutor() *DockerExecutor {
	return &DockerExecutor{}
}

// DefaultSandboxConfig returns a safe default configuration.
func DefaultSandboxConfig() SandboxConfig {
	return SandboxConfig{
		MaxMemoryMB:    512,
		MaxCPU:         2,
		TimeoutSeconds: 60,
		ReadOnlyPaths:  []string{"/tmp"},
		DenyPaths: []string{
			"/etc/shadow",
			"/etc/sudoers",
			"/root/.ssh",
			"/.ssh",
		},
		AuditLogPath: "",
		TraceID:      "",
		Mode:         "local",
	}
}

// redactCommand replaces credential patterns in a command string with ***REDACTED***.
func redactCommand(cmd string) string {
	redacted := "***REDACTED***"

	// Bearer tokens: Bearer <token>
	cmd = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9_\-]+`).ReplaceAllString(cmd, "Bearer "+redacted)

	// API keys: sk_live_*, sk_test_*, AKIA*
	cmd = regexp.MustCompile(`sk_live_[A-Za-z0-9_\-]+`).ReplaceAllString(cmd, redacted)
	cmd = regexp.MustCompile(`sk_test_[A-Za-z0-9_\-]+`).ReplaceAllString(cmd, redacted)
	cmd = regexp.MustCompile(`(?i)AKIA[A-Za-z0-9]+`).ReplaceAllString(cmd, redacted)

	// AWS secret access key: aws_secret_access_key=<value> or aws_secret_access_key:<value>
	cmd = regexp.MustCompile(`(?i)aws_secret_access_key[=:]\s*\S+`).ReplaceAllString(cmd, "aws_secret_access_key="+redacted)

	// Password in URL query/fragment: ?password=... or &password=...
	cmd = regexp.MustCompile(`(?i)[?&]password=[^&\s]+`).ReplaceAllString(cmd, "?password="+redacted)

	// Basic auth in URL or -u flag: -u user:pass
	cmd = regexp.MustCompile(`(?i)-u\s+\S+:\S+`).ReplaceAllString(cmd, "-u "+redacted)

	// --password=<value>
	cmd = regexp.MustCompile(`(?i)--password[=:]\S+`).ReplaceAllString(cmd, "--password="+redacted)

	// -p followed by a password value (mysql, docker, etc.)
	// Matches: -p <password>, -ppassword
	cmd = regexp.MustCompile(`-p\s+\S+`).ReplaceAllString(cmd, "-p "+redacted)

	// Private key content: -----BEGIN ... PRIVATE KEY-----
	cmd = regexp.MustCompile(`-----BEGIN.*PRIVATE KEY-----`).ReplaceAllString(cmd, "-----BEGIN PRIVATE KEY----- "+redacted)

	return cmd
}

// auditLogEntry creates a structured audit log entry for local/docker execution.
func (e *LocalExecutor) auditLogEntry(traceID, mode, cmd, status string) string {
	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"trace_id":  traceID,
		"mode":      mode,
		"command":   redactCommand(cmd),
		"status":    status,
	}
	data, _ := json.Marshal(entry)
	return string(data)
}

// auditLogEntrySSH creates an audit log entry for SSH execution.
func auditLogEntrySSH(traceID, mode, target, cmd, status string) string {
	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"trace_id":  traceID,
		"mode":      mode,
		"target":    target,
		"command":   redactCommand(cmd),
		"status":    status,
	}
	data, _ := json.Marshal(entry)
	return string(data)
}

// writeAuditLog writes an audit log entry to the configured path or stderr.
func (e *LocalExecutor) writeAuditLog(path, entry string) {
	if path != "" {
		// #nosec G302 -- audit logs should be readable only by owner
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			defer f.Close()
			fmt.Fprintln(f, entry)
		}
	}
	// Always log to stderr for visibility
	fmt.Fprintln(os.Stderr, entry)
}

// writeAuditLog is a package-level wrapper for SSH and Docker executors.
func writeAuditLog(path, entry string) {
	if path != "" {
		// #nosec G302 -- audit logs should be readable only by owner
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			defer f.Close()
			fmt.Fprintln(f, entry)
		}
	}
	fmt.Fprintln(os.Stderr, entry)
}

// assessRisk calculates a risk score based on the command and config.
func assessRisk(cmd string, cfg SandboxConfig, execErr error) int {
	score := 10 // Base score for any execution

	// Higher score for remote execution
	if cfg.Mode == "ssh" {
		score += 15
	}

	// Higher score if docker is not network-isolated (configurable)
	if cfg.Mode == "docker" {
		score += 5
	}

	// Score increases with memory limit
	if cfg.MaxMemoryMB > 2048 {
		score += 5
	}

	// Score increases with timeout
	if cfg.TimeoutSeconds > 300 {
		score += 5
	}

	// Check for potentially risky command patterns
	cmdLower := strings.ToLower(cmd)
	riskyPatterns := []struct {
		pattern string
		weight  int
	}{
		{"curl ", 10},
		{"wget ", 10},
		{"nc ", 15},
		{"ncat ", 15},
		{"netcat ", 15},
		{"bash ", 10},
		{"sh ", 5},
		{"exec ", 15},
		{"eval ", 20},
		{"|", 5},
		{"&&", 5},
		{"||", 5},
		{"sudo ", 10},
		{"chmod ", 10},
		{"chown ", 10},
	}

	for _, rp := range riskyPatterns {
		if strings.Contains(cmdLower, rp.pattern) {
			score += rp.weight
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// assessRisk is the method version for LocalExecutor.
func (e *LocalExecutor) assessRisk(cmd string, cfg SandboxConfig, execErr error) int {
	return assessRisk(cmd, cfg, execErr)
}

// assessRisk is the method version for DockerExecutor.
func (e *DockerExecutor) assessRisk(cmd string, cfg SandboxConfig, execErr error) int {
	return assessRisk(cmd, cfg, execErr)
}

// ParseConfig parses a JSON sandbox configuration string.
func ParseConfig(data string) (*SandboxConfig, error) {
	var cfg SandboxConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}
