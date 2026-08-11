// Package taskruntime provides durable orchestration for commands executed by
// stable Computer identities.
package taskruntime

import (
	"errors"
	"time"

	"github.com/chenchunrun/SecOps/internal/admission"
	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/workspace"
)

type ID string

type State string

const (
	StatePending     State = "pending"
	StateRunning     State = "running"
	StateVerifying   State = "verifying"
	StateInterrupted State = "interrupted"
	StateSucceeded   State = "succeeded"
	StateFailed      State = "failed"
	StateCancelled   State = "cancelled"
)

var (
	ErrInvalidTask               = errors.New("invalid durable task")
	ErrNotFound                  = errors.New("durable task not found")
	ErrAlreadyExists             = errors.New("durable task already exists")
	ErrConflict                  = errors.New("durable task version conflict")
	ErrNotRunnable               = errors.New("durable task is not runnable")
	ErrComputerMismatch          = errors.New("durable task computer mismatch")
	ErrInvalidResult             = errors.New("computer returned no execution result")
	ErrNotVerifiable             = errors.New("durable task is not awaiting verification")
	ErrVerificationFailed        = errors.New("durable task verification failed")
	ErrInvalidVerificationResult = errors.New("invalid durable task verification result")
)

type Submission struct {
	ID             ID
	ComputerID     computer.ID
	WorkspaceID    workspace.ID
	Request        computer.ExecRequest
	VerificationID string
	ResourceDemand admission.Resources
}

type Result struct {
	Output    string        `json:"output"`
	ExitCode  int           `json:"exit_code"`
	Duration  time.Duration `json:"duration"`
	RiskScore int           `json:"risk_score"`
}

type Task struct {
	ID                      ID                   `json:"id"`
	ComputerID              computer.ID          `json:"computer_id"`
	WorkspaceID             workspace.ID         `json:"workspace_id,omitempty"`
	State                   State                `json:"state"`
	Request                 computer.ExecRequest `json:"request"`
	ResourceDemand          admission.Resources  `json:"resource_demand,omitempty"`
	Attempt                 int                  `json:"attempt"`
	Result                  *Result              `json:"result,omitempty"`
	Error                   string               `json:"error,omitempty"`
	VerificationID          string               `json:"verification_id,omitempty"`
	VerificationVerdict     string               `json:"verification_verdict,omitempty"`
	VerificationEvidenceIDs []string             `json:"verification_evidence_ids,omitempty"`
	VerificationFindings    []string             `json:"verification_findings,omitempty"`
	CreatedAt               time.Time            `json:"created_at"`
	UpdatedAt               time.Time            `json:"updated_at"`
	StartedAt               time.Time            `json:"started_at,omitempty"`
	FinishedAt              time.Time            `json:"finished_at,omitempty"`
	Version                 uint64               `json:"version"`
}

func (s State) valid() bool {
	switch s {
	case StatePending, StateRunning, StateVerifying, StateInterrupted, StateSucceeded, StateFailed, StateCancelled:
		return true
	default:
		return false
	}
}

func (s State) terminal() bool {
	switch s {
	case StateSucceeded, StateFailed, StateCancelled:
		return true
	default:
		return false
	}
}
