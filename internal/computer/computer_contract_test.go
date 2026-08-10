package computer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chenchunrun/SecOps/internal/sandbox"
	"github.com/stretchr/testify/require"
)

type executorFunc func(context.Context, string, sandbox.SandboxConfig) (*sandbox.ExecutionResult, error)

func (f executorFunc) Execute(ctx context.Context, command string, cfg sandbox.SandboxConfig) (*sandbox.ExecutionResult, error) {
	return f(ctx, command, cfg)
}

type recordingExecutor struct {
	mu       sync.Mutex
	calls    int
	commands []string
	modes    []string
	result   *sandbox.ExecutionResult
	err      error
}

func (e *recordingExecutor) Execute(_ context.Context, command string, cfg sandbox.SandboxConfig) (*sandbox.ExecutionResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	e.commands = append(e.commands, command)
	e.modes = append(e.modes, cfg.Mode)
	return e.result, e.err
}

func (e *recordingExecutor) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

func TestComputerContract_AllBackends(t *testing.T) {
	t.Parallel()

	for _, backend := range []Backend{BackendLocal, BackendDocker, BackendSSH} {
		backend := backend
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()

			t.Run("success", func(t *testing.T) {
				executor := &recordingExecutor{result: &sandbox.ExecutionResult{Output: "ok", ExitCode: 0}}
				computer, err := newExecutorComputer(ID("computer-1"), backend, executor)
				require.NoError(t, err)

				result, err := computer.Exec(context.Background(), ExecRequest{Command: "echo ok"})
				require.NoError(t, err)
				require.Equal(t, "ok", result.Output)
				require.Equal(t, 0, result.ExitCode)
				require.Equal(t, StateCompleted, computer.State())
				require.Equal(t, string(backend), executor.modes[0])
			})

			t.Run("failure", func(t *testing.T) {
				execErr := errors.New("exit status 7")
				executor := &recordingExecutor{result: &sandbox.ExecutionResult{ExitCode: 7, Error: execErr}}
				computer, err := newExecutorComputer(ID("computer-2"), backend, executor)
				require.NoError(t, err)

				result, err := computer.Exec(context.Background(), ExecRequest{Command: "exit 7"})
				require.ErrorIs(t, err, execErr)
				require.Equal(t, 7, result.ExitCode)
				require.Equal(t, StateFailed, computer.State())
			})

			t.Run("cancellation", func(t *testing.T) {
				executor := executorFunc(func(ctx context.Context, _ string, _ sandbox.SandboxConfig) (*sandbox.ExecutionResult, error) {
					<-ctx.Done()
					return &sandbox.ExecutionResult{ExitCode: 1, Error: ctx.Err()}, ctx.Err()
				})
				computer, err := newExecutorComputer(ID("computer-3"), backend, executor)
				require.NoError(t, err)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				_, err = computer.Exec(ctx, ExecRequest{Command: "wait"})
				require.ErrorIs(t, err, context.Canceled)
				require.Equal(t, StateFailed, computer.State())
			})

			t.Run("output limit", func(t *testing.T) {
				executor := &recordingExecutor{result: &sandbox.ExecutionResult{Output: "1234567890"}}
				computer, err := newExecutorComputer(ID("computer-4"), backend, executor)
				require.NoError(t, err)

				result, err := computer.Exec(context.Background(), ExecRequest{
					Command:        "print output",
					MaxOutputBytes: 4,
				})
				require.NoError(t, err)
				require.Equal(t, "1234", result.Output)
				require.True(t, result.Truncated)
			})

			t.Run("permission denial", func(t *testing.T) {
				permissionErr := errors.New("permission denied")
				executor := &recordingExecutor{err: permissionErr}
				computer, err := newExecutorComputer(ID("computer-5"), backend, executor)
				require.NoError(t, err)

				_, err = computer.Exec(context.Background(), ExecRequest{Command: "blocked"})
				require.ErrorIs(t, err, permissionErr)
				require.Equal(t, StateFailed, computer.State())
			})
		})
	}
}

func TestComputerLifecycle(t *testing.T) {
	t.Parallel()

	executor := &recordingExecutor{result: &sandbox.ExecutionResult{Output: "ok"}}
	computer, err := newExecutorComputer(ID("stable-id"), BackendLocal, executor)
	require.NoError(t, err)
	require.Equal(t, ID("stable-id"), computer.ID())
	require.Equal(t, BackendLocal, computer.Backend())
	require.Equal(t, StateActive, computer.State())

	require.NoError(t, computer.Suspend(context.Background()))
	require.NoError(t, computer.Suspend(context.Background()))
	require.Equal(t, StateSuspended, computer.State())

	_, err = computer.Exec(context.Background(), ExecRequest{Command: "must not run"})
	require.ErrorIs(t, err, ErrNotActive)
	require.Equal(t, 0, executor.callCount())

	require.NoError(t, computer.Resume(context.Background()))
	require.Equal(t, StateActive, computer.State())
	_, err = computer.Exec(context.Background(), ExecRequest{Command: "run"})
	require.NoError(t, err)
	require.Equal(t, StateCompleted, computer.State())

	require.NoError(t, computer.Destroy(context.Background()))
	require.NoError(t, computer.Destroy(context.Background()))
	require.Equal(t, StateDestroyed, computer.State())

	_, err = computer.Exec(context.Background(), ExecRequest{Command: "must fail closed"})
	require.ErrorIs(t, err, ErrDestroyed)
	require.Equal(t, 1, executor.callCount())
	require.ErrorIs(t, computer.Resume(context.Background()), ErrDestroyed)
}

func TestComputerConstructionValidation(t *testing.T) {
	t.Parallel()

	_, err := newExecutorComputer("", BackendLocal, &recordingExecutor{})
	require.ErrorIs(t, err, ErrInvalidID)
	_, err = newExecutorComputer("valid", "unknown", &recordingExecutor{})
	require.ErrorIs(t, err, ErrInvalidBackend)
	_, err = newExecutorComputer("valid", BackendLocal, nil)
	require.ErrorIs(t, err, ErrBackendUnavailable)
}

func TestLocalComputer_ExecutorBehavior(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Local sandbox contract uses POSIX shell commands")
	}

	t.Run("success and environment isolation", func(t *testing.T) {
		computer, err := NewLocalComputer("local-success")
		require.NoError(t, err)

		result, err := computer.Exec(context.Background(), ExecRequest{
			Command: `printf '%s|%s' "$HOME" "$PWD"`,
			Config:  sandbox.SandboxConfig{TimeoutSeconds: 2},
		})
		require.NoError(t, err)
		resolvedTmp, err := filepath.EvalSymlinks("/tmp")
		require.NoError(t, err)
		require.Equal(t, "/tmp|"+resolvedTmp, result.Output)
	})

	t.Run("non-zero exit", func(t *testing.T) {
		computer, err := NewLocalComputer("local-failure")
		require.NoError(t, err)

		result, err := computer.Exec(context.Background(), ExecRequest{
			Command: "exit 7",
			Config:  sandbox.SandboxConfig{TimeoutSeconds: 2},
		})
		require.Error(t, err)
		require.Equal(t, 7, result.ExitCode)
	})

	t.Run("timeout", func(t *testing.T) {
		computer, err := NewLocalComputer("local-timeout")
		require.NoError(t, err)

		_, err = computer.Exec(context.Background(), ExecRequest{
			Command: "sleep 2",
			Config:  sandbox.SandboxConfig{TimeoutSeconds: 1},
		})
		require.ErrorIs(t, err, sandbox.ErrTimeout)
	})

	t.Run("cancellation", func(t *testing.T) {
		computer, err := NewLocalComputer("local-cancel")
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err = computer.Exec(ctx, ExecRequest{Command: "sleep 2"})
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("output limit", func(t *testing.T) {
		computer, err := NewLocalComputer("local-output")
		require.NoError(t, err)

		result, err := computer.Exec(context.Background(), ExecRequest{
			Command:        "printf 1234567890",
			MaxOutputBytes: 5,
		})
		require.NoError(t, err)
		require.Equal(t, "12345", result.Output)
		require.True(t, result.Truncated)
	})

	t.Run("permission denial", func(t *testing.T) {
		computer, err := NewLocalComputer("local-denied")
		require.NoError(t, err)

		_, err = computer.Exec(context.Background(), ExecRequest{Command: "rm -rf /"})
		require.ErrorIs(t, err, sandbox.ErrDangerousPath)
	})

	t.Run("audit", func(t *testing.T) {
		auditPath := t.TempDir() + "/computer-audit.jsonl"
		computer, err := NewLocalComputer("local-audit")
		require.NoError(t, err)

		_, err = computer.Exec(context.Background(), ExecRequest{
			Command: "printf audited",
			Config: sandbox.SandboxConfig{
				AuditLogPath: auditPath,
				TraceID:      "trace-computer-1",
			},
		})
		require.NoError(t, err)
		contents, err := os.ReadFile(auditPath)
		require.NoError(t, err)
		require.Contains(t, string(contents), "trace-computer-1")
		require.Contains(t, string(contents), "started")
		require.Contains(t, string(contents), "completed")
	})
}

func TestBackendConstructors(t *testing.T) {
	t.Parallel()

	local, err := NewLocalComputer("local")
	require.NoError(t, err)
	require.Equal(t, BackendLocal, local.Backend())

	docker, err := NewDockerComputer("docker")
	require.NoError(t, err)
	require.Equal(t, BackendDocker, docker.Backend())

	ssh, err := NewSSHComputer("ssh", "ops", "/tmp/test-key")
	require.NoError(t, err)
	require.Equal(t, BackendSSH, ssh.Backend())
}

func TestOutputLimitPreservesValidUTF8(t *testing.T) {
	t.Parallel()

	executor := &recordingExecutor{result: &sandbox.ExecutionResult{Output: "安全输出"}}
	computer, err := newExecutorComputer("utf8", BackendLocal, executor)
	require.NoError(t, err)
	result, err := computer.Exec(context.Background(), ExecRequest{
		Command:        "unicode",
		MaxOutputBytes: 5,
	})
	require.NoError(t, err)
	require.True(t, result.Truncated)
	require.True(t, strings.HasPrefix("安全输出", result.Output))
	require.True(t, strings.ToValidUTF8(result.Output, "") == result.Output)
}

func BenchmarkComputerExecLifecycle(b *testing.B) {
	executor := &recordingExecutor{result: &sandbox.ExecutionResult{Output: "ok"}}
	computer, err := newExecutorComputer("benchmark", BackendLocal, executor)
	require.NoError(b, err)

	b.ResetTimer()
	for range b.N {
		_, err := computer.Exec(context.Background(), ExecRequest{Command: "noop"})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestComputerExecWaitsForContextAwareBackend(t *testing.T) {
	t.Parallel()

	executor := executorFunc(func(ctx context.Context, _ string, _ sandbox.SandboxConfig) (*sandbox.ExecutionResult, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
			return &sandbox.ExecutionResult{}, nil
		}
	})
	computer, err := newExecutorComputer("context-aware", BackendLocal, executor)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err = computer.Exec(ctx, ExecRequest{Command: "wait"})
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
