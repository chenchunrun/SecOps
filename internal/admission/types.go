// Package admission provides deterministic resource admission for tasks that
// have already been assigned to stable Computer identities.
package admission

import (
	"errors"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
)

type ID string

type State string

const (
	StateActive   State = "active"
	StateReleased State = "released"
)

var (
	ErrInvalidRequest   = errors.New("invalid admission request")
	ErrUnknownComputer  = errors.New("admission computer is not configured")
	ErrCapacityExceeded = errors.New("computer resource capacity exceeded")
	ErrNotFound         = errors.New("admission lease not found")
	ErrAlreadyExists    = errors.New("admission lease already exists")
	ErrLeaseConflict    = errors.New("admission lease conflicts with existing request")
	ErrLeaseReleased    = errors.New("admission lease was already released")
	ErrVersionConflict  = errors.New("admission lease version conflict")
)

type Resources struct {
	Slots    int   `json:"slots"`
	CPUUnits int   `json:"cpu_units"`
	MemoryMB int64 `json:"memory_mb"`
}

type Profile struct {
	ComputerID computer.ID
	Capacity   Resources
}

type Request struct {
	LeaseID    ID
	TaskID     ID
	ComputerID computer.ID
	Demand     Resources
}

type Lease struct {
	ID         ID          `json:"id"`
	TaskID     ID          `json:"task_id"`
	ComputerID computer.ID `json:"computer_id"`
	Demand     Resources   `json:"demand"`
	State      State       `json:"state"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
	ReleasedAt time.Time   `json:"released_at,omitempty"`
	Version    uint64      `json:"version"`
}
