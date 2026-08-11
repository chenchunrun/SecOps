package verification

import (
	"errors"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
)

var (
	ErrNotFound        = errors.New("verification record not found")
	ErrAlreadyExists   = errors.New("verification record already exists")
	ErrInvalidRequest  = errors.New("invalid verification request")
	ErrInvalidEvidence = errors.New("invalid verification evidence")
	ErrIntegrity       = errors.New("verification evidence integrity failure")
)

type Verdict string

const (
	VerdictPassed Verdict = "passed"
	VerdictFailed Verdict = "failed"
)

type FindingCode string

const (
	FindingMissingEvidence  FindingCode = "missing_evidence"
	FindingIntegrityFailure FindingCode = "integrity_failure"
)

type Requirement struct {
	Kind    string `json:"kind"`
	Minimum int    `json:"minimum"`
}

type Request struct {
	ID           string        `json:"id"`
	TaskID       string        `json:"task_id"`
	ComputerID   computer.ID   `json:"computer_id"`
	Requirements []Requirement `json:"requirements"`
	CreatedAt    time.Time     `json:"created_at"`
}

type Artifact struct {
	Kind    string
	Source  string
	Payload []byte
}

type Evidence struct {
	ID        string    `json:"id"`
	RequestID string    `json:"request_id"`
	Kind      string    `json:"kind"`
	Source    string    `json:"source"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Locator   string    `json:"locator"`
	CreatedAt time.Time `json:"created_at"`
}

type Finding struct {
	Code        FindingCode `json:"code"`
	Requirement string      `json:"requirement,omitempty"`
	EvidenceID  string      `json:"evidence_id,omitempty"`
	Message     string      `json:"message"`
}

type Result struct {
	RequestID   string    `json:"request_id"`
	Verdict     Verdict   `json:"verdict"`
	EvidenceIDs []string  `json:"evidence_ids,omitempty"`
	Findings    []Finding `json:"findings,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
}
