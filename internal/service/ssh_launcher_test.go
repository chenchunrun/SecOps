package service

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
)

type fakeSSHCLI struct {
	mu      sync.Mutex
	calls   [][]string
	start   []byte
	stdout  []byte
	stderr  []byte
	termErr error
}

func (c *fakeSSHCLI) Run(_ context.Context, args []string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, append([]string(nil), args...))
	command := args[len(args)-1]
	if strings.Contains(command, "nohup") {
		return c.start, nil
	}
	if strings.Contains(command, "cat --") && strings.Contains(command, ".stdout.log") {
		return c.stdout, nil
	}
	if strings.Contains(command, "cat --") && strings.Contains(command, ".stderr.log") {
		return c.stderr, nil
	}
	if strings.Contains(command, "kill -TERM") && c.termErr != nil {
		return nil, c.termErr
	}
	return nil, nil
}

func (c *fakeSSHCLI) snapshot() [][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	calls := make([][]string, len(c.calls))
	for i := range c.calls {
		calls[i] = append([]string(nil), c.calls[i]...)
	}
	return calls
}

func TestSSHLauncherBuildsHardenedDeterministicArguments(t *testing.T) {
	t.Parallel()

	cli := &fakeSSHCLI{start: []byte("4242\n")}
	launcher, err := NewSSHLauncher(t.TempDir(), map[computer.ID]SSHProfile{
		"ssh-build": {
			Target:          "ops@build.example.com",
			Port:            2222,
			KeyPath:         "/keys/build_ed25519",
			ProxyJump:       "ops@bastion.example.com",
			RemoteDirectory: "/var/tmp/secops-services",
			ConnectTimeout:  7 * time.Second,
			PollInterval:    time.Hour,
		},
	}, withSSHCLI(cli))
	require.NoError(t, err)
	machine, err := computer.NewSSHComputer("ssh-build", "ops", "/keys/build_ed25519")
	require.NoError(t, err)

	process, err := launcher.Start(context.Background(), machine, Spec{
		Command:          "printf '%s' 'value; not a local command'",
		WorkingDirectory: "/srv/application",
	})
	require.NoError(t, err)
	require.Equal(t, 4242, process.PID())

	calls := cli.snapshot()
	require.Len(t, calls, 1)
	args := calls[0]
	require.Equal(t, []string{"-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "LogLevel=ERROR", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=7", "-p", "2222", "-i", "/keys/build_ed25519", "-J", "ops@bastion.example.com", "ops@build.example.com"}, args[:len(args)-1])
	remoteCommand := args[len(args)-1]
	require.Contains(t, remoteCommand, "umask 077")
	require.Contains(t, remoteCommand, "cd -- '/srv/application'")
	require.Contains(t, remoteCommand, "nohup setsid /bin/sh -c")
	require.Contains(t, remoteCommand, "'printf '\"'\"'%s'\"'\"' '\"'\"'value; not a local command'\"'\"''")
	require.NotContains(t, strings.Join(args[:len(args)-1], " "), "value; not a local command")
}

func TestSSHLauncherRejectsInvalidRemotePID(t *testing.T) {
	t.Parallel()

	cli := &fakeSSHCLI{start: []byte("not-a-pid\n")}
	launcher, err := NewSSHLauncher(t.TempDir(), map[computer.ID]SSHProfile{
		"ssh-invalid-pid": {Target: "ops@example.com", PollInterval: time.Hour},
	}, withSSHCLI(cli))
	require.NoError(t, err)
	machine, err := computer.NewSSHComputer("ssh-invalid-pid", "ops", "")
	require.NoError(t, err)

	process, err := launcher.Start(context.Background(), machine, Spec{Command: "sleep 60"})
	require.ErrorIs(t, err, ErrInvalidSSHProcessID)
	require.Nil(t, process)
}

func TestSSHProcessFallsBackToKill(t *testing.T) {
	t.Parallel()

	cli := &fakeSSHCLI{start: []byte("4242\n"), termErr: errors.New("term unavailable")}
	launcher, err := NewSSHLauncher(t.TempDir(), map[computer.ID]SSHProfile{
		"ssh-stop": {Target: "ops@example.com", PollInterval: time.Hour},
	}, withSSHCLI(cli))
	require.NoError(t, err)
	machine, err := computer.NewSSHComputer("ssh-stop", "ops", "")
	require.NoError(t, err)
	process, err := launcher.Start(context.Background(), machine, Spec{Command: "sleep 60"})
	require.NoError(t, err)

	require.NoError(t, process.Stop(context.Background()))
	calls := cli.snapshot()
	require.Len(t, calls, 5)
	require.Contains(t, calls[1][len(calls[1])-1], "kill -TERM -- -4242")
	require.Contains(t, calls[2][len(calls[2])-1], "kill -KILL -- -4242")
	require.NoError(t, process.Stop(context.Background()))
	require.Len(t, cli.snapshot(), 5)
}

func TestSSHProcessCopiesRemoteLogsOutsideRuntime(t *testing.T) {
	t.Parallel()

	cli := &fakeSSHCLI{
		start:  []byte("4242\n"),
		stdout: []byte("service ready\n"),
		stderr: []byte("diagnostic\n"),
	}
	launcher, err := NewSSHLauncher(t.TempDir(), map[computer.ID]SSHProfile{
		"ssh-evidence": {Target: "ops@example.com", PollInterval: time.Hour},
	}, withSSHCLI(cli))
	require.NoError(t, err)
	machine, err := computer.NewSSHComputer("ssh-evidence", "ops", "")
	require.NoError(t, err)
	process, err := launcher.Start(context.Background(), machine, Spec{Command: "serve"})
	require.NoError(t, err)

	require.NoError(t, process.Stop(context.Background()))
	stdout, err := os.ReadFile(process.Logs().Stdout)
	require.NoError(t, err)
	stderr, err := os.ReadFile(process.Logs().Stderr)
	require.NoError(t, err)
	require.Equal(t, "service ready\n", string(stdout))
	require.Equal(t, "diagnostic\n", string(stderr))
	stdoutInfo, err := os.Stat(process.Logs().Stdout)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o600), stdoutInfo.Mode().Perm())
	}
}

func TestSSHLauncherFailsClosedWithoutTrustedProfile(t *testing.T) {
	t.Parallel()

	launcher, err := NewSSHLauncher(t.TempDir(), nil)
	require.NoError(t, err)
	machine, err := computer.NewSSHComputer("unknown", "ops", "")
	require.NoError(t, err)

	process, err := launcher.Start(context.Background(), machine, Spec{Command: "serve"})
	require.ErrorIs(t, err, ErrBackendUnsupported)
	require.Nil(t, process)
}

func TestSSHLauncherRejectsUntrustedProfileFields(t *testing.T) {
	t.Parallel()

	tests := map[string]SSHProfile{
		"target":           {Target: "-oProxyCommand=bad"},
		"port":             {Target: "ops@example.com", Port: 70000},
		"key":              {Target: "ops@example.com", KeyPath: "/key\ncommand"},
		"proxy jump":       {Target: "ops@example.com", ProxyJump: "bad jump"},
		"remote directory": {Target: "ops@example.com", RemoteDirectory: "relative/path"},
	}
	for name, profile := range tests {
		profile := profile
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			launcher, err := NewSSHLauncher(t.TempDir(), map[computer.ID]SSHProfile{"ssh": profile})
			require.ErrorIs(t, err, ErrInvalidSSHProfile)
			require.Nil(t, launcher)
		})
	}
}
