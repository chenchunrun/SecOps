package evidence

import (
	"context"
	"errors"
	"fmt"
)

type Report struct {
	TaskID       string        `json:"task_id"`
	Evidence     []Evidence    `json:"evidence"`
	Facts        []Fact        `json:"facts"`
	Inferences   []Inference   `json:"inferences,omitempty"`
	Finding      Finding       `json:"finding"`
	Verification *Verification `json:"verification,omitempty"`
}

type ReplayBundle struct {
	Report      Report            `json:"report"`
	RawEvidence map[string][]byte `json:"raw_evidence"`
}

func (s *FileStore) BuildReport(ctx context.Context, findingID string) (Report, error) {
	finding, err := s.GetFinding(ctx, findingID)
	if err != nil {
		return Report{}, fmt.Errorf("load report finding: %w", err)
	}
	report := Report{TaskID: finding.TaskID, Finding: finding}
	evidenceSeen := make(map[string]struct{})
	for _, factID := range finding.FactIDs {
		fact, err := s.GetFact(ctx, factID)
		if err != nil {
			return Report{}, fmt.Errorf("load report fact %s: %w", factID, err)
		}
		if fact.TaskID != finding.TaskID {
			return Report{}, ErrTaskMismatch
		}
		report.Facts = append(report.Facts, fact)
		for _, evidenceID := range fact.EvidenceIDs {
			if _, exists := evidenceSeen[evidenceID]; exists {
				continue
			}
			item, _, err := s.GetEvidence(ctx, evidenceID)
			if err != nil {
				return Report{}, fmt.Errorf("load report evidence %s: %w", evidenceID, err)
			}
			if item.TaskID != finding.TaskID {
				return Report{}, ErrTaskMismatch
			}
			evidenceSeen[evidenceID] = struct{}{}
			report.Evidence = append(report.Evidence, item)
		}
	}
	for _, inferenceID := range finding.InferenceIDs {
		inference, err := s.GetInference(ctx, inferenceID)
		if err != nil {
			return Report{}, fmt.Errorf("load report inference %s: %w", inferenceID, err)
		}
		if inference.TaskID != finding.TaskID {
			return Report{}, ErrTaskMismatch
		}
		report.Inferences = append(report.Inferences, inference)
	}
	verification, err := s.GetVerification(ctx, finding.ID)
	if err == nil {
		if verification.TaskID != finding.TaskID {
			return Report{}, ErrTaskMismatch
		}
		report.Verification = &verification
	} else if !errors.Is(err, ErrNotFound) {
		return Report{}, fmt.Errorf("load report verification: %w", err)
	}
	if finding.Severity == SeverityHigh || finding.Severity == SeverityCritical {
		if report.Verification == nil || report.Verification.Verdict != VerdictPassed {
			return Report{}, fmt.Errorf("%w: high-risk finding is not independently verified", ErrIncomplete)
		}
	}
	return report, nil
}

func (s *FileStore) ReplayFinding(ctx context.Context, findingID string) (ReplayBundle, error) {
	report, err := s.BuildReport(ctx, findingID)
	if err != nil {
		return ReplayBundle{}, err
	}
	bundle := ReplayBundle{Report: report, RawEvidence: make(map[string][]byte, len(report.Evidence))}
	for _, item := range report.Evidence {
		_, raw, err := s.GetEvidence(ctx, item.ID)
		if err != nil {
			return ReplayBundle{}, fmt.Errorf("replay evidence %s: %w", item.ID, err)
		}
		bundle.RawEvidence[item.ID] = raw
	}
	return bundle, nil
}
