// Package workspace manages persistent workspaces and immutable snapshots
// outside ephemeral Computer backends.
package workspace

import (
	"errors"
	"time"
)

type ID string

type SnapshotID string

var (
	ErrInvalidID        = errors.New("invalid workspace id")
	ErrInvalidRoot      = errors.New("invalid workspace state root")
	ErrAlreadyExists    = errors.New("workspace already exists")
	ErrNotFound         = errors.New("workspace not found")
	ErrSnapshotNotFound = errors.New("workspace snapshot not found")
	ErrSnapshotCorrupt  = errors.New("workspace snapshot is corrupt")
	ErrUnsafeEntry      = errors.New("workspace contains unsafe entry")
)

type Workspace struct {
	ID   ID     `json:"id"`
	Root string `json:"root"`
}

type Entry struct {
	Path      string `json:"path"`
	Mode      uint32 `json:"mode"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest,omitempty"`
	Directory bool   `json:"directory"`
}

type Snapshot struct {
	ID          SnapshotID `json:"id"`
	WorkspaceID ID         `json:"workspace_id"`
	CreatedAt   time.Time  `json:"created_at"`
	Files       int        `json:"files"`
	Bytes       int64      `json:"bytes"`
	Digest      string     `json:"digest"`
	Entries     []Entry    `json:"entries"`
}
