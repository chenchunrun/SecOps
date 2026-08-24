// Package scenarios implements evidence-first end-to-end security scenarios.
package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/chenchunrun/SecOps/internal/evidence"
)

type HostCollectionRequest struct {
	TaskID   string
	Target   string
	Platform string
	ReadOnly bool
}

type HostSnapshot struct {
	Processes  []string `json:"processes"`
	Network    []string `json:"network"`
	Accounts   []string `json:"accounts"`
	Logs       []string `json:"logs"`
	Suspicious bool     `json:"suspicious"`
}

type HostAdapter interface {
	Collect(context.Context, HostCollectionRequest) (HostSnapshot, error)
	Isolate(context.Context, string) error
}

type Approval struct {
	ID         string
	TaskID     string
	Target     string
	ApprovedBy string
	ExpiresAt  time.Time
}

type ScenarioAuditEvent struct {
	TaskID      string
	Action      string
	Target      string
	ApprovalID  string
	EvidenceIDs []string
}

type ScenarioAuditor interface {
	Record(context.Context, ScenarioAuditEvent) error
}

type HostIRInput struct {
	TaskID           string
	Target           string
	Platform         string
	MakerID          string
	CheckerID        string
	RequestIsolation bool
	Approval         *Approval
}

type HostIRReport struct {
	TaskID            string
	FindingID         string
	EvidenceIDs       []string
	Verification      evidence.Verdict
	ApprovalRequired  bool
	IsolationExecuted bool
}

type HostIRWorkflow struct {
	store   *evidence.FileStore
	adapter HostAdapter
	auditor ScenarioAuditor
	now     func() time.Time
}

func NewHostIRWorkflow(store *evidence.FileStore, adapter HostAdapter, auditor ScenarioAuditor) (*HostIRWorkflow, error) {
	if store == nil || adapter == nil || auditor == nil {
		return nil, errors.New("initialize host IR workflow: store, adapter, and auditor are required")
	}
	return &HostIRWorkflow{store: store, adapter: adapter, auditor: auditor, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (w *HostIRWorkflow) Run(ctx context.Context, input HostIRInput) (HostIRReport, error) {
	if input.TaskID == "" || input.Target == "" || input.MakerID == "" || input.CheckerID == "" || !supportedHostPlatform(input.Platform) {
		return HostIRReport{}, errors.New("run host IR workflow: invalid input")
	}
	findingID := input.TaskID + "-host-finding"
	if verification, err := w.store.GetVerification(ctx, findingID); err == nil {
		return HostIRReport{TaskID: input.TaskID, FindingID: findingID, EvidenceIDs: verification.EvidenceIDs, Verification: verification.Verdict}, nil
	} else if !errors.Is(err, evidence.ErrNotFound) {
		return HostIRReport{}, err
	}
	pre, err := w.adapter.Collect(ctx, HostCollectionRequest{TaskID: input.TaskID, Target: input.Target, Platform: input.Platform, ReadOnly: true})
	if err != nil {
		return HostIRReport{}, fmt.Errorf("collect pre-response host evidence: %w", err)
	}
	preEvidence, err := w.persistSnapshot(ctx, input.TaskID+"-host-pre", input, "pre_response", pre)
	if err != nil {
		return HostIRReport{}, err
	}
	report := HostIRReport{TaskID: input.TaskID, FindingID: findingID, EvidenceIDs: []string{preEvidence.ID}}
	if input.RequestIsolation {
		if !validApproval(input, w.now()) {
			report.ApprovalRequired = true
		} else {
			if err := w.auditor.Record(ctx, ScenarioAuditEvent{TaskID: input.TaskID, Action: "host_isolate", Target: input.Target, ApprovalID: input.Approval.ID, EvidenceIDs: report.EvidenceIDs}); err != nil {
				return HostIRReport{}, fmt.Errorf("audit host isolation: %w", err)
			}
			if err := w.adapter.Isolate(ctx, input.Target); err != nil {
				return HostIRReport{}, fmt.Errorf("isolate host: %w", err)
			}
			report.IsolationExecuted = true
			post, err := w.adapter.Collect(ctx, HostCollectionRequest{TaskID: input.TaskID, Target: input.Target, Platform: input.Platform, ReadOnly: true})
			if err != nil {
				return HostIRReport{}, fmt.Errorf("collect post-response host evidence: %w", err)
			}
			postEvidence, err := w.persistSnapshot(ctx, input.TaskID+"-host-post", input, "post_response", post)
			if err != nil {
				return HostIRReport{}, err
			}
			report.EvidenceIDs = append(report.EvidenceIDs, postEvidence.ID)
		}
	}
	statement := "Host process, network, account, and log state was collected using a read-only adapter."
	if pre.Suspicious {
		statement = "Read-only host collection contains suspicious activity indicators."
	}
	factID := input.TaskID + "-host-fact"
	if err := w.store.PutFact(ctx, evidence.Fact{ID: factID, TaskID: input.TaskID, Statement: statement, EvidenceIDs: []string{preEvidence.ID}}); err != nil {
		return HostIRReport{}, fmt.Errorf("persist host IR fact: %w", err)
	}
	severity := evidence.SeverityMedium
	if pre.Suspicious {
		severity = evidence.SeverityHigh
	}
	if err := w.store.PutFinding(ctx, evidence.Finding{
		ID: findingID, TaskID: input.TaskID, MakerID: input.MakerID, Severity: severity,
		FactIDs: []string{factID}, Recommendation: "Preserve evidence and obtain approval before containment actions.",
	}); err != nil {
		return HostIRReport{}, fmt.Errorf("persist host IR finding: %w", err)
	}
	if err := w.store.VerifyFinding(ctx, evidence.Verification{
		FindingID: findingID, TaskID: input.TaskID, CheckerID: input.CheckerID,
		Verdict: evidence.VerdictPassed, EvidenceIDs: report.EvidenceIDs, Reason: "pre/post host evidence integrity and task binding verified",
	}); err != nil {
		return HostIRReport{}, fmt.Errorf("verify host IR finding: %w", err)
	}
	report.Verification = evidence.VerdictPassed
	return report, nil
}

func (w *HostIRWorkflow) persistSnapshot(ctx context.Context, id string, input HostIRInput, phase string, snapshot HostSnapshot) (evidence.Evidence, error) {
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return evidence.Evidence{}, err
	}
	item, err := w.store.PutEvidence(ctx, evidence.Evidence{
		ID: id, TaskID: input.TaskID, Source: evidence.EvidenceSource{Type: "host_" + phase, Reference: input.Platform + ":" + input.Target},
		Summary: phase + " host state", TrustLevel: evidence.TrustHigh, Completeness: evidence.CompletenessComplete,
	}, raw)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("persist %s host evidence: %w", phase, err)
	}
	return item, nil
}

func supportedHostPlatform(platform string) bool {
	return platform == "linux" || platform == "darwin" || platform == "windows"
}

func validApproval(input HostIRInput, now time.Time) bool {
	return input.Approval != nil && input.Approval.ID != "" && input.Approval.TaskID == input.TaskID && input.Approval.Target == input.Target && input.Approval.ApprovedBy != "" && input.Approval.ExpiresAt.After(now)
}
