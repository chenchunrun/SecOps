package attack

import "time"

// EvidenceEvent is a normalized security evidence record.
type EvidenceEvent struct {
	ID         string            `json:"id"`
	Source     string            `json:"source"`
	EventType  string            `json:"event_type"`
	Timestamp  time.Time         `json:"timestamp"`
	Actor      string            `json:"actor,omitempty"`
	Target     string            `json:"target,omitempty"`
	Action     string            `json:"action,omitempty"`
	Severity   string            `json:"severity,omitempty"`
	Confidence float64           `json:"confidence,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	Raw        string            `json:"raw,omitempty"`
}

// Technique describes a reduced MITRE ATT&CK technique entry.
type Technique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	TacticIDs   []string `json:"tactic_ids"`
	Platforms   []string `json:"platforms,omitempty"`
	DataSources []string `json:"data_sources,omitempty"`
	Detections  []string `json:"detections,omitempty"`
	Mitigations []string `json:"mitigations,omitempty"`
}

// TechniqueMatch represents a ranked ATT&CK technique candidate.
type TechniqueMatch struct {
	TechniqueID string   `json:"technique_id"`
	Name        string   `json:"name"`
	Score       float64  `json:"score"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	Reasons     []string `json:"reasons,omitempty"`
	TacticIDs   []string `json:"tactic_ids,omitempty"`
}

// Assessment is the top-level ATT&CK reasoning result.
type Assessment struct {
	Summary     string           `json:"summary"`
	Tactics     []string         `json:"tactics,omitempty"`
	Techniques  []TechniqueMatch `json:"techniques,omitempty"`
	Gaps        []string         `json:"gaps,omitempty"`
	NextActions []string         `json:"next_actions,omitempty"`
}
