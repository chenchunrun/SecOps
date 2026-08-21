// Package evidence provides evidence-first security investigation contracts.
package evidence

import (
	"errors"
	"time"
)

var (
	ErrAlreadyExists      = errors.New("evidence record already exists")
	ErrIntegrity          = errors.New("evidence integrity check failed")
	ErrInvalidRecord      = errors.New("invalid evidence record")
	ErrNotFound           = errors.New("evidence record not found")
	ErrTaskMismatch       = errors.New("cross-task evidence reference")
	ErrIncomplete         = errors.New("incomplete evidence cannot support a fact")
	ErrCheckerNotIsolated = errors.New("maker and checker identities must differ")
)

type TrustLevel string

const (
	TrustUntrusted TrustLevel = "untrusted"
	TrustLow       TrustLevel = "low"
	TrustMedium    TrustLevel = "medium"
	TrustHigh      TrustLevel = "high"
)

type Completeness string

const (
	CompletenessComplete  Completeness = "complete"
	CompletenessTruncated Completeness = "truncated"
	CompletenessFailed    Completeness = "failed"
)

type EvidenceSource struct {
	Type      string `json:"type"`
	Reference string `json:"reference"`
}

type Evidence struct {
	ID           string         `json:"id"`
	TaskID       string         `json:"task_id"`
	Source       EvidenceSource `json:"source"`
	CollectedAt  time.Time      `json:"collected_at"`
	ContentHash  string         `json:"content_hash"`
	Summary      string         `json:"summary"`
	RawReference string         `json:"raw_reference"`
	TrustLevel   TrustLevel     `json:"trust_level"`
	Completeness Completeness   `json:"completeness"`
	Failure      string         `json:"failure,omitempty"`
}

type Fact struct {
	ID          string   `json:"id"`
	TaskID      string   `json:"task_id"`
	Statement   string   `json:"statement"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Inference struct {
	ID           string   `json:"id"`
	TaskID       string   `json:"task_id"`
	Statement    string   `json:"statement"`
	FactIDs      []string `json:"fact_ids"`
	Confidence   float64  `json:"confidence"`
	Alternatives []string `json:"alternatives,omitempty"`
}

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type FindingStatus string

const (
	FindingPreliminary   FindingStatus = "preliminary"
	FindingVerified      FindingStatus = "verified"
	FindingRejected      FindingStatus = "rejected"
	FindingNeedsEvidence FindingStatus = "needs_evidence"
)

type Finding struct {
	ID             string        `json:"id"`
	TaskID         string        `json:"task_id"`
	MakerID        string        `json:"maker_id"`
	Severity       Severity      `json:"severity"`
	FactIDs        []string      `json:"fact_ids"`
	InferenceIDs   []string      `json:"inference_ids,omitempty"`
	Recommendation string        `json:"recommendation"`
	Status         FindingStatus `json:"status"`
}

type Verdict string

const (
	VerdictPassed        Verdict = "passed"
	VerdictRejected      Verdict = "rejected"
	VerdictNeedsEvidence Verdict = "needs_evidence"
)

type Verification struct {
	FindingID   string    `json:"finding_id"`
	TaskID      string    `json:"task_id"`
	CheckerID   string    `json:"checker_id"`
	Verdict     Verdict   `json:"verdict"`
	EvidenceIDs []string  `json:"evidence_ids"`
	Reason      string    `json:"reason"`
	CheckedAt   time.Time `json:"checked_at"`
}
