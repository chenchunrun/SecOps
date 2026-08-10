package workspace

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const manifestName = "manifest.json"

var validIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Manager struct {
	mu            sync.Mutex
	workspaceRoot string
	snapshotRoot  string
}

func NewManager(workspaceRoot, snapshotRoot string) (*Manager, error) {
	workspaceRoot, err := normalizeRoot(workspaceRoot)
	if err != nil {
		return nil, err
	}
	snapshotRoot, err = normalizeRoot(snapshotRoot)
	if err != nil {
		return nil, err
	}
	if rootsOverlap(workspaceRoot, snapshotRoot) {
		return nil, fmt.Errorf("%w: workspace and snapshot roots overlap", ErrInvalidRoot)
	}
	if err := os.MkdirAll(workspaceRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create workspace root: %w", err)
	}
	if err := os.MkdirAll(snapshotRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create snapshot root: %w", err)
	}
	return &Manager{workspaceRoot: workspaceRoot, snapshotRoot: snapshotRoot}, nil
}

func (m *Manager) Create(ctx context.Context, id ID) (Workspace, error) {
	if err := ctx.Err(); err != nil {
		return Workspace{}, err
	}
	if err := validateID(id); err != nil {
		return Workspace{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	workspaceDir := filepath.Join(m.workspaceRoot, string(id))
	if err := os.Mkdir(workspaceDir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Workspace{}, fmt.Errorf("%w: %s", ErrAlreadyExists, id)
		}
		return Workspace{}, fmt.Errorf("create workspace %s: %w", id, err)
	}
	dataRoot := filepath.Join(workspaceDir, "data")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		_ = os.RemoveAll(workspaceDir)
		return Workspace{}, fmt.Errorf("create workspace data root %s: %w", id, err)
	}
	return Workspace{ID: id, Root: dataRoot}, nil
}

func (m *Manager) Get(ctx context.Context, id ID) (Workspace, error) {
	if err := ctx.Err(); err != nil {
		return Workspace{}, err
	}
	if err := validateID(id); err != nil {
		return Workspace{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getLocked(id)
}

func (m *Manager) CreateSnapshot(ctx context.Context, id ID) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if err := validateID(id); err != nil {
		return Snapshot{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	ws, err := m.getLocked(id)
	if err != nil {
		return Snapshot{}, err
	}
	snapshotID, err := newSnapshotID()
	if err != nil {
		return Snapshot{}, fmt.Errorf("create snapshot id: %w", err)
	}
	tempRoot, err := os.MkdirTemp(m.snapshotRoot, ".snapshot-")
	if err != nil {
		return Snapshot{}, fmt.Errorf("create temporary snapshot: %w", err)
	}
	defer os.RemoveAll(tempRoot)
	tempData := filepath.Join(tempRoot, "data")
	if err := os.Mkdir(tempData, 0o700); err != nil {
		return Snapshot{}, fmt.Errorf("create snapshot data root: %w", err)
	}

	entries, files, bytes, err := copyTree(ctx, ws.Root, tempData)
	if err != nil {
		return Snapshot{}, err
	}
	entryData, err := json.Marshal(entries)
	if err != nil {
		return Snapshot{}, fmt.Errorf("encode snapshot entries: %w", err)
	}
	snapshot := Snapshot{
		ID:          snapshotID,
		WorkspaceID: id,
		CreatedAt:   time.Now().UTC(),
		Files:       files,
		Bytes:       bytes,
		Digest:      digestBytes(entryData),
		Entries:     entries,
	}
	manifest, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return Snapshot{}, fmt.Errorf("encode snapshot manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tempRoot, manifestName), manifest, 0o600); err != nil {
		return Snapshot{}, fmt.Errorf("write snapshot manifest: %w", err)
	}
	finalRoot := filepath.Join(m.snapshotRoot, string(snapshotID))
	if err := os.Rename(tempRoot, finalRoot); err != nil {
		return Snapshot{}, fmt.Errorf("publish snapshot %s: %w", snapshotID, err)
	}
	return snapshot, nil
}

func (m *Manager) Restore(ctx context.Context, workspaceID ID, snapshotID SnapshotID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateID(workspaceID); err != nil {
		return err
	}
	if err := validateID(ID(snapshotID)); err != nil {
		return fmt.Errorf("%w: %s", ErrSnapshotNotFound, snapshotID)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	ws, err := m.getLocked(workspaceID)
	if err != nil {
		return err
	}
	snapshot, snapshotData, err := m.loadAndVerifySnapshotLocked(ctx, snapshotID)
	if err != nil {
		return err
	}
	if snapshot.WorkspaceID != workspaceID {
		return fmt.Errorf("%w: snapshot %s belongs to workspace %s", ErrSnapshotCorrupt, snapshotID, snapshot.WorkspaceID)
	}

	workspaceDir := filepath.Dir(ws.Root)
	stageRoot, err := os.MkdirTemp(workspaceDir, ".restore-")
	if err != nil {
		return fmt.Errorf("create restore staging directory: %w", err)
	}
	defer os.RemoveAll(stageRoot)
	if _, _, _, err := copyTree(ctx, snapshotData, stageRoot); err != nil {
		return fmt.Errorf("stage snapshot restore: %w", err)
	}
	backupRoot, err := uniquePath(workspaceDir, ".backup-")
	if err != nil {
		return fmt.Errorf("allocate workspace backup path: %w", err)
	}
	if err := os.Rename(ws.Root, backupRoot); err != nil {
		return fmt.Errorf("backup current workspace: %w", err)
	}
	if err := os.Rename(stageRoot, ws.Root); err != nil {
		rollbackErr := os.Rename(backupRoot, ws.Root)
		return errors.Join(fmt.Errorf("activate restored workspace: %w", err), rollbackErr)
	}
	if err := os.RemoveAll(backupRoot); err != nil {
		return fmt.Errorf("remove workspace restore backup: %w", err)
	}
	return nil
}

func (m *Manager) getLocked(id ID) (Workspace, error) {
	dataRoot := filepath.Join(m.workspaceRoot, string(id), "data")
	info, err := os.Stat(dataRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Workspace{}, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return Workspace{}, fmt.Errorf("inspect workspace %s: %w", id, err)
	}
	if !info.IsDir() {
		return Workspace{}, fmt.Errorf("%w: workspace %s data root is not a directory", ErrNotFound, id)
	}
	return Workspace{ID: id, Root: dataRoot}, nil
}

func (m *Manager) loadAndVerifySnapshotLocked(ctx context.Context, id SnapshotID) (Snapshot, string, error) {
	root := filepath.Join(m.snapshotRoot, string(id))
	manifestData, err := os.ReadFile(filepath.Join(root, manifestName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Snapshot{}, "", fmt.Errorf("%w: %s", ErrSnapshotNotFound, id)
		}
		return Snapshot{}, "", fmt.Errorf("read snapshot manifest %s: %w", id, err)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(manifestData, &snapshot); err != nil {
		return Snapshot{}, "", fmt.Errorf("%w: decode manifest: %v", ErrSnapshotCorrupt, err)
	}
	if snapshot.ID != id {
		return Snapshot{}, "", fmt.Errorf("%w: snapshot identity mismatch", ErrSnapshotCorrupt)
	}
	entryData, err := json.Marshal(snapshot.Entries)
	if err != nil || digestBytes(entryData) != snapshot.Digest {
		return Snapshot{}, "", fmt.Errorf("%w: manifest digest mismatch", ErrSnapshotCorrupt)
	}
	dataRoot := filepath.Join(root, "data")
	entries, files, bytes, err := inspectTree(ctx, dataRoot)
	if err != nil {
		return Snapshot{}, "", fmt.Errorf("%w: %v", ErrSnapshotCorrupt, err)
	}
	actualData, err := json.Marshal(entries)
	if err != nil || digestBytes(actualData) != snapshot.Digest || files != snapshot.Files || bytes != snapshot.Bytes {
		return Snapshot{}, "", fmt.Errorf("%w: snapshot contents do not match manifest", ErrSnapshotCorrupt)
	}
	return snapshot, dataRoot, nil
}

func copyTree(ctx context.Context, sourceRoot, destinationRoot string) ([]Entry, int, int64, error) {
	entries := make([]Entry, 0)
	files := 0
	var bytes int64
	err := filepath.WalkDir(sourceRoot, func(path string, directoryEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		info, err := directoryEntry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.Mode().IsRegular() && !info.IsDir()) {
			return fmt.Errorf("%w: %s", ErrUnsafeEntry, relative)
		}
		destination := filepath.Join(destinationRoot, relative)
		entry := Entry{Path: filepath.ToSlash(relative), Mode: uint32(info.Mode().Perm()), Directory: info.IsDir()}
		if info.IsDir() {
			if err := os.Mkdir(destination, info.Mode().Perm()); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
		} else {
			digest, size, err := copyFile(path, destination, info.Mode().Perm())
			if err != nil {
				return err
			}
			entry.Digest = digest
			entry.Size = size
			files++
			bytes += size
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, 0, 0, fmt.Errorf("copy workspace tree: %w", err)
	}
	return entries, files, bytes, nil
}

func inspectTree(ctx context.Context, root string) ([]Entry, int, int64, error) {
	tempRoot, err := os.MkdirTemp(filepath.Dir(root), ".inspect-")
	if err != nil {
		return nil, 0, 0, err
	}
	defer os.RemoveAll(tempRoot)
	return copyTree(ctx, root, tempRoot)
}

func copyFile(source, destination string, mode os.FileMode) (string, int64, error) {
	input, err := os.Open(source)
	if err != nil {
		return "", 0, err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	if copyErr == nil {
		copyErr = output.Sync()
	}
	closeErr := output.Close()
	if copyErr != nil {
		return "", 0, copyErr
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func normalizeRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("%w: root is required", ErrInvalidRoot)
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidRoot, err)
	}
	return filepath.Clean(absolute), nil
}

func rootsOverlap(first, second string) bool {
	return containsPath(first, second) || containsPath(second, first)
}

func containsPath(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateID(id ID) error {
	if !validIDPattern.MatchString(string(id)) {
		return fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	return nil
}

func ValidateID(id ID) error {
	return validateID(id)
}

func newSnapshotID() (SnapshotID, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return SnapshotID(time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(random)), nil
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func uniquePath(parent, prefix string) (string, error) {
	path, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return path, nil
}
