package workspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSnapshotRestoreRoundTripAcrossManagerRestart(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workspaceRoot := filepath.Join(root, "workspaces")
	snapshotRoot := filepath.Join(root, "snapshots")
	manager, err := NewManager(workspaceRoot, snapshotRoot)
	require.NoError(t, err)
	ws, err := manager.Create(context.Background(), "workspace-1")
	require.NoError(t, err)

	require.NoError(t, os.MkdirAll(filepath.Join(ws.Root, "nested", "empty"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(ws.Root, "nested", "config.txt"), []byte("version=1\n"), 0o640))
	require.NoError(t, os.WriteFile(filepath.Join(ws.Root, "run.sh"), []byte("#!/bin/sh\necho ok\n"), 0o750))

	snapshot, err := manager.CreateSnapshot(context.Background(), ws.ID)
	require.NoError(t, err)
	require.Equal(t, ws.ID, snapshot.WorkspaceID)
	require.NotEmpty(t, snapshot.ID)
	require.NotEmpty(t, snapshot.Digest)
	require.Equal(t, 2, snapshot.Files)
	require.NotZero(t, snapshot.CreatedAt)

	require.NoError(t, os.WriteFile(filepath.Join(ws.Root, "nested", "config.txt"), []byte("version=2\n"), 0o600))
	require.NoError(t, os.Remove(filepath.Join(ws.Root, "run.sh")))
	require.NoError(t, os.WriteFile(filepath.Join(ws.Root, "untracked.txt"), []byte("remove me"), 0o600))

	reopened, err := NewManager(workspaceRoot, snapshotRoot)
	require.NoError(t, err)
	reopenedWorkspace, err := reopened.Get(context.Background(), ws.ID)
	require.NoError(t, err)
	require.Equal(t, ws.Root, reopenedWorkspace.Root)
	require.NoError(t, reopened.Restore(context.Background(), ws.ID, snapshot.ID))

	config, err := os.ReadFile(filepath.Join(ws.Root, "nested", "config.txt"))
	require.NoError(t, err)
	require.Equal(t, "version=1\n", string(config))
	_, err = os.Stat(filepath.Join(ws.Root, "untracked.txt"))
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(filepath.Join(ws.Root, "nested", "empty"))
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(ws.Root, "run.sh"))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o750), info.Mode().Perm())
	}
}

func TestRestoreCorruptSnapshotFailsWithoutChangingWorkspace(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	snapshotRoot := filepath.Join(root, "snapshots")
	manager, err := NewManager(filepath.Join(root, "workspaces"), snapshotRoot)
	require.NoError(t, err)
	ws, err := manager.Create(context.Background(), "workspace-1")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(ws.Root, "state.txt"), []byte("original"), 0o600))
	snapshot, err := manager.CreateSnapshot(context.Background(), ws.ID)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(snapshotRoot, string(snapshot.ID), "data", "state.txt"), []byte("tampered"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(ws.Root, "state.txt"), []byte("current"), 0o600))
	err = manager.Restore(context.Background(), ws.ID, snapshot.ID)
	require.ErrorIs(t, err, ErrSnapshotCorrupt)

	current, readErr := os.ReadFile(filepath.Join(ws.Root, "state.txt"))
	require.NoError(t, readErr)
	require.Equal(t, "current", string(current))
}

func TestSnapshotRejectsUnsafeIdentityAndSymlink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	manager, err := NewManager(filepath.Join(root, "workspaces"), filepath.Join(root, "snapshots"))
	require.NoError(t, err)
	_, err = manager.Create(context.Background(), "../escape")
	require.ErrorIs(t, err, ErrInvalidID)

	ws, err := manager.Create(context.Background(), "workspace-1")
	require.NoError(t, err)
	target := filepath.Join(root, "outside-secret")
	require.NoError(t, os.WriteFile(target, []byte("secret"), 0o600))
	if err := os.Symlink(target, filepath.Join(ws.Root, "link")); err != nil {
		if runtime.GOOS == "windows" || errors.Is(err, os.ErrPermission) {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		require.NoError(t, err)
	}
	_, err = manager.CreateSnapshot(context.Background(), ws.ID)
	require.ErrorIs(t, err, ErrUnsafeEntry)
}

func TestManagerRejectsOverlappingStateRoots(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	_, err := NewManager(root, filepath.Join(root, "snapshots"))
	require.ErrorIs(t, err, ErrInvalidRoot)
}
