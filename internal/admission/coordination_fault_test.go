package admission

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/require"
)

func TestCoordinateCancelsWhileWaitingForLocalHolder(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- store.Coordinate(context.Background(), func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	timer := time.AfterFunc(250*time.Millisecond, func() { close(release) })
	defer timer.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	actionCalled := false
	err = store.Coordinate(ctx, func() error {
		actionCalled = true
		return nil
	})
	elapsed := time.Since(started)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.False(t, actionCalled)
	require.Less(t, elapsed, 150*time.Millisecond)
	require.NoError(t, <-firstDone)
}

func TestCoordinateRecoversAfterLockHolderIsKilled(t *testing.T) {
	root := t.TempDir()
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestAdmissionLockHolderHelper$")
	command.Env = append(os.Environ(),
		"SECOPS_ADMISSION_LOCK_HELPER=1",
		"SECOPS_ADMISSION_ROOT="+root,
	)
	stdout, err := command.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, command.Start())

	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() && scanner.Text() == "ADMISSION_LOCK_READY" {
			ready <- nil
			return
		}
		ready <- fmt.Errorf("lock helper did not become ready: %s: %w", scanner.Text(), scanner.Err())
	}()
	select {
	case err := <-ready:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		require.FailNow(t, "timed out waiting for lock helper")
	}

	require.NoError(t, command.Process.Kill())
	require.Error(t, command.Wait())

	store, err := NewFileStore(root)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	actionCalled := false
	require.NoError(t, store.Coordinate(ctx, func() error {
		actionCalled = true
		return nil
	}))
	require.True(t, actionCalled)
}

func TestAdmissionLockHolderHelper(t *testing.T) {
	if os.Getenv("SECOPS_ADMISSION_LOCK_HELPER") != "1" {
		t.Skip("subprocess helper")
	}

	lock := flock.New(filepath.Join(os.Getenv("SECOPS_ADMISSION_ROOT"), ".admission.lock"))
	locked, err := lock.TryLockContext(context.Background(), time.Millisecond)
	require.NoError(t, err)
	require.True(t, locked)
	defer func() { require.NoError(t, lock.Unlock()) }()

	fmt.Println("ADMISSION_LOCK_READY")
	for {
		if err := context.Cause(t.Context()); err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("lock helper context: %v", err)
		}
		time.Sleep(time.Second)
	}
}
