package verification

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type Checker struct {
	store *FileStore
	now   func() time.Time
}

func NewChecker(store *FileStore) (*Checker, error) {
	if store == nil {
		return nil, fmt.Errorf("initialize verification checker: store is nil")
	}
	return &Checker{store: store, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (c *Checker) Check(ctx context.Context, requestID string) (Result, error) {
	if result, err := c.store.GetResult(ctx, requestID); err == nil {
		return result, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Result{}, fmt.Errorf("load verification result: %w", err)
	}
	request, err := c.store.GetRequest(ctx, requestID)
	if err != nil {
		return Result{}, fmt.Errorf("load verification request: %w", err)
	}
	evidence, err := c.store.ListEvidence(ctx, requestID)
	if err != nil {
		return Result{}, fmt.Errorf("list verification evidence: %w", err)
	}

	result := Result{RequestID: requestID, Verdict: VerdictPassed, CheckedAt: c.now()}
	counts := make(map[string]int)
	for _, item := range evidence {
		result.EvidenceIDs = append(result.EvidenceIDs, item.ID)
		counts[item.Kind]++
		if _, err := c.store.LoadPayload(ctx, item); err != nil {
			if errors.Is(err, ErrIntegrity) {
				result.Findings = append(result.Findings, Finding{
					Code:       FindingIntegrityFailure,
					EvidenceID: item.ID,
					Message:    "evidence payload failed digest or size verification",
				})
				continue
			}
			return Result{}, fmt.Errorf("load verification evidence %s: %w", item.ID, err)
		}
	}
	for _, requirement := range request.Requirements {
		if counts[requirement.Kind] < requirement.Minimum {
			result.Findings = append(result.Findings, Finding{
				Code:        FindingMissingEvidence,
				Requirement: requirement.Kind,
				Message:     fmt.Sprintf("required %d evidence item(s), found %d", requirement.Minimum, counts[requirement.Kind]),
			})
		}
	}
	if len(result.Findings) > 0 {
		result.Verdict = VerdictFailed
	}
	if err := c.store.CreateResult(ctx, result); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			return c.store.GetResult(ctx, requestID)
		}
		return Result{}, fmt.Errorf("persist verification result: %w", err)
	}
	return result, nil
}
