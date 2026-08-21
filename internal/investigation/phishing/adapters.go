package phishing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/evidence"
)

type AuditStoreAdapter struct {
	store audit.AuditStore
}

func NewAuditStoreAdapter(store audit.AuditStore) (*AuditStoreAdapter, error) {
	if store == nil {
		return nil, errors.New("initialize phishing audit adapter: store is nil")
	}
	return &AuditStoreAdapter{store: store}, nil
}

func (a *AuditStoreAdapter) Record(ctx context.Context, event AuditEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	record := audit.DefaultAuditEvent(audit.EventTypeSecurityAlert)
	record.Action = event.Action
	record.ResourceType = "security_investigation"
	record.ResourceName = event.TaskID
	record.Result = audit.ResultSuccess
	record.Details = map[string]interface{}{
		"task_id":              event.TaskID,
		"evidence_ids":         append([]string(nil), event.EvidenceIDs...),
		"finding_id":           event.FindingID,
		"verification_verdict": string(event.Verification),
	}
	if err := a.store.SaveEvent(record); err != nil {
		return fmt.Errorf("save phishing audit event: %w", err)
	}
	return nil
}

type EvidenceChecker struct {
	store *evidence.FileStore
}

func NewEvidenceChecker(store *evidence.FileStore) (*EvidenceChecker, error) {
	if store == nil {
		return nil, errors.New("initialize phishing evidence checker: store is nil")
	}
	return &EvidenceChecker{store: store}, nil
}

func (c *EvidenceChecker) Check(ctx context.Context, request CheckRequest) (CheckResult, error) {
	if request.TaskID == "" || request.Finding.TaskID != request.TaskID || len(request.EvidenceIDs) == 0 {
		return CheckResult{Verdict: evidence.VerdictNeedsEvidence, Reason: "finding has no independently accessible evidence"}, nil
	}
	validated := make([]string, 0, len(request.EvidenceIDs))
	for _, evidenceID := range request.EvidenceIDs {
		item, _, err := c.store.GetEvidence(ctx, evidenceID)
		if err != nil {
			return CheckResult{Verdict: evidence.VerdictRejected, Reason: "evidence integrity validation failed"}, nil
		}
		if item.TaskID != request.TaskID || item.Completeness != evidence.CompletenessComplete {
			return CheckResult{Verdict: evidence.VerdictNeedsEvidence, Reason: "evidence is incomplete or belongs to another task"}, nil
		}
		validated = append(validated, evidenceID)
	}
	return CheckResult{
		Verdict: evidence.VerdictPassed, EvidenceIDs: validated,
		Reason: "all referenced evidence is complete, task-bound, and integrity-verified",
	}, nil
}

func NewProductionWorkflow(store *evidence.FileStore, auditStore audit.AuditStore, intel ThreatIntel, timeout time.Duration) (*Workflow, error) {
	checker, err := NewEvidenceChecker(store)
	if err != nil {
		return nil, err
	}
	auditor, err := NewAuditStoreAdapter(auditStore)
	if err != nil {
		return nil, err
	}
	return NewWorkflow(store, intel, checker, auditor, timeout)
}
