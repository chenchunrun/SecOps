//go:build !windows

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/computer"
)

func TestLocalLauncherStopsEntireUnixProcessGroup(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	launcher, err := NewLocalLauncher(filepath.Join(directory, "logs"))
	require.NoError(t, err)
	machine, err := computer.NewLocalComputer("process-tree-test")
	require.NoError(t, err)
	process, err := launcher.Start(context.Background(), machine, Spec{
		Command:          "trap '' TERM; (trap '' TERM; while :; do sleep 1; done) & echo $! > child.pid; wait",
		WorkingDirectory: directory,
	})
	require.NoError(t, err)

	processGroupID, err := syscall.Getpgid(process.PID())
	require.NoError(t, err)
	require.Equal(t, process.PID(), processGroupID)

	var childPID int
	require.Eventually(t, func() bool {
		data, readErr := os.ReadFile(filepath.Join(directory, "child.pid"))
		if readErr != nil {
			return false
		}
		childPID, readErr = strconv.Atoi(strings.TrimSpace(string(data)))
		return readErr == nil && childPID > 0
	}, time.Second, 10*time.Millisecond)
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, process.Stop(ctx))
	require.Eventually(t, func() bool {
		err := syscall.Kill(childPID, 0)
		return errors.Is(err, syscall.ESRCH)
	}, 2*time.Second, 20*time.Millisecond)
}
