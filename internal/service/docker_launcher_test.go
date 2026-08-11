package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
)

type fakeDockerCLI struct {
	mu        sync.Mutex
	startArgs [][]string
	runArgs   [][]string
	process   *fakeProcess
	stopErr   error
}

func (c *fakeDockerCLI) Start(_ context.Context, args []string, _ LogPaths) (Process, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.startArgs = append(c.startArgs, append([]string(nil), args...))
	c.process = newFakeProcess(4242)
	return c.process, nil
}

func (c *fakeDockerCLI) Run(_ context.Context, args []string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runArgs = append(c.runArgs, append([]string(nil), args...))
	if len(args) > 0 && args[0] == "stop" && c.stopErr != nil {
		return []byte("stop failed"), c.stopErr
	}
	if c.process != nil {
		c.process.complete(nil)
	}
	return nil, nil
}

func TestDockerLauncherBuildsHardenedDeterministicArguments(t *testing.T) {
	t.Parallel()

	cli := &fakeDockerCLI{}
	launcher, err := NewDockerLauncher(t.TempDir(), map[computer.ID]DockerProfile{
		"docker-build": {
			Image:          "alpine:3.20",
			Network:        "bridge",
			PublishAddress: "127.0.0.1",
			Shell:          []string{"/bin/sh", "-c"},
		},
	}, withDockerCLI(cli))
	require.NoError(t, err)
	machine, err := computer.NewDockerComputer("docker-build")
	require.NoError(t, err)

	process, err := launcher.Start(context.Background(), machine, Spec{
		Command:          "printf '%s' 'value; not a host command'",
		WorkingDirectory: "/workspace",
		Ports: []Port{
			{Name: "dns", Protocol: ProtocolUDP, Number: 5353},
			{Name: "http", Protocol: ProtocolTCP, Number: 8080},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 4242, process.PID())
	require.Len(t, cli.startArgs, 1)
	args := cli.startArgs[0]
	require.Equal(t, "run", args[0])
	require.Contains(t, args, "--rm")
	require.Contains(t, args, "--cap-drop=ALL")
	require.Contains(t, args, "--security-opt=no-new-privileges")
	require.Contains(t, args, "--network=bridge")
	require.Contains(t, args, "127.0.0.1:5353:5353/udp")
	require.Contains(t, args, "127.0.0.1:8080:8080/tcp")
	require.Equal(t, []string{"alpine:3.20", "/bin/sh", "-c", "printf '%s' 'value; not a host command'"}, args[len(args)-4:])
}

func TestDockerLauncherRejectsPublishedPortsWithDisabledNetwork(t *testing.T) {
	t.Parallel()

	cli := &fakeDockerCLI{}
	launcher, err := NewDockerLauncher(t.TempDir(), map[computer.ID]DockerProfile{
		"docker-isolated": {Image: "alpine:3.20", Network: "none"},
	}, withDockerCLI(cli))
	require.NoError(t, err)
	machine, err := computer.NewDockerComputer("docker-isolated")
	require.NoError(t, err)

	process, err := launcher.Start(context.Background(), machine, Spec{
		Command: "serve",
		Ports:   []Port{{Name: "http", Protocol: ProtocolTCP, Number: 8080}},
	})
	require.ErrorIs(t, err, ErrPortPublishingDisabled)
	require.Nil(t, process)
	require.Empty(t, cli.startArgs)
}

func TestDockerProcessFallsBackToForcedRemoval(t *testing.T) {
	t.Parallel()

	cli := &fakeDockerCLI{stopErr: errors.New("docker stop unavailable")}
	launcher, err := NewDockerLauncher(t.TempDir(), map[computer.ID]DockerProfile{
		"docker-stop": {Image: "alpine:3.20", Network: "none", StopTimeout: 3 * time.Second},
	}, withDockerCLI(cli))
	require.NoError(t, err)
	machine, err := computer.NewDockerComputer("docker-stop")
	require.NoError(t, err)
	process, err := launcher.Start(context.Background(), machine, Spec{Command: "sleep 60"})
	require.NoError(t, err)

	require.NoError(t, process.Stop(context.Background()))
	require.Equal(t, []string{"stop", "--time", "3", dockerContainerName(cli.startArgs[0])}, cli.runArgs[0])
	require.Equal(t, []string{"rm", "--force", dockerContainerName(cli.startArgs[0])}, cli.runArgs[1])
}

func TestDockerLauncherFailsClosedWithoutTrustedProfile(t *testing.T) {
	t.Parallel()

	launcher, err := NewDockerLauncher(t.TempDir(), nil, withDockerCLI(&fakeDockerCLI{}))
	require.NoError(t, err)
	machine, err := computer.NewDockerComputer("untrusted-docker")
	require.NoError(t, err)

	process, err := launcher.Start(context.Background(), machine, Spec{Command: "serve"})
	require.ErrorIs(t, err, ErrBackendUnsupported)
	require.Nil(t, process)
}

func dockerContainerName(args []string) string {
	for index, argument := range args {
		if argument == "--name" && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}
