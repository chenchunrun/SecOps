// Package phishing implements an evidence-first phishing investigation flow.
package phishing

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/chenchunrun/SecOps/internal/evidence"
	"github.com/chenchunrun/SecOps/internal/security/promptguard"
)

var urlPattern = regexp.MustCompile(`https?://[^\s<>"']+`)

type Input struct {
	TaskID           string
	MessageReference string
	Message          []byte
	MakerID          string
	CheckerID        string
}

type IntelResult struct {
	Indicator string
	Malicious bool
	Source    string
	Summary   string
	Raw       []byte
}

type ThreatIntel interface {
	Lookup(ctx context.Context, indicator string) (IntelResult, error)
}

type CheckRequest struct {
	TaskID      string
	Finding     evidence.Finding
	EvidenceIDs []string
}

type CheckResult struct {
	Verdict     evidence.Verdict
	EvidenceIDs []string
	Reason      string
}

type IndependentChecker interface {
	Check(ctx context.Context, request CheckRequest) (CheckResult, error)
}

type AuditEvent struct {
	TaskID       string
	Action       string
	EvidenceIDs  []string
	FindingID    string
	Verification evidence.Verdict
}

type Auditor interface {
	Record(ctx context.Context, event AuditEvent) error
}

type Report struct {
	TaskID                  string                `json:"task_id"`
	EvidenceIDs             []string              `json:"evidence_ids"`
	FactIDs                 []string              `json:"fact_ids"`
	Finding                 evidence.Finding      `json:"finding"`
	Verification            evidence.Verification `json:"verification"`
	Warnings                []string              `json:"warnings,omitempty"`
	PromptInjectionDetected bool                  `json:"prompt_injection_detected"`
}

type Workflow struct {
	store   *evidence.FileStore
	intel   ThreatIntel
	checker IndependentChecker
	auditor Auditor
	timeout time.Duration
}

func NewWorkflow(store *evidence.FileStore, intel ThreatIntel, checker IndependentChecker, auditor Auditor, timeout time.Duration) (*Workflow, error) {
	if store == nil || checker == nil || auditor == nil || timeout <= 0 {
		return nil, errors.New("initialize phishing workflow: store, checker, auditor, and positive timeout are required")
	}
	return &Workflow{store: store, intel: intel, checker: checker, auditor: auditor, timeout: timeout}, nil
}

func (w *Workflow) Run(ctx context.Context, input Input) (Report, error) {
	if strings.TrimSpace(input.TaskID) == "" || strings.TrimSpace(input.MessageReference) == "" || len(input.Message) == 0 || strings.TrimSpace(input.MakerID) == "" || strings.TrimSpace(input.CheckerID) == "" {
		return Report{}, errors.New("run phishing workflow: invalid input")
	}
	findingID := input.TaskID + "-phishing"
	if persisted, err := w.store.GetVerification(ctx, findingID); err == nil {
		finding, getErr := w.store.GetFinding(ctx, findingID)
		if getErr != nil {
			return Report{}, fmt.Errorf("load completed phishing finding: %w", getErr)
		}
		return Report{
			TaskID: input.TaskID, EvidenceIDs: append([]string(nil), persisted.EvidenceIDs...),
			FactIDs: []string{input.TaskID + "-message-fact"}, Finding: finding, Verification: persisted,
		}, nil
	} else if !errors.Is(err, evidence.ErrNotFound) {
		return Report{}, fmt.Errorf("load phishing verification: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	if err := w.auditor.Record(runCtx, AuditEvent{TaskID: input.TaskID, Action: "phishing_investigation_started"}); err != nil {
		return Report{}, fmt.Errorf("audit phishing investigation start: %w", err)
	}

	report := Report{TaskID: input.TaskID}
	report.PromptInjectionDetected = promptguard.ContainsInjection(string(input.Message))
	if report.PromptInjectionDetected {
		report.Warnings = append(report.Warnings, "message contains instruction-like content; treated only as untrusted evidence")
	}

	messageEvidence, err := w.store.PutEvidence(runCtx, evidence.Evidence{
		ID: input.TaskID + "-message", TaskID: input.TaskID,
		Source:  evidence.EvidenceSource{Type: "email", Reference: input.MessageReference},
		Summary: "Original suspicious email", TrustLevel: evidence.TrustUntrusted,
		Completeness: evidence.CompletenessComplete,
	}, input.Message)
	if err != nil {
		return Report{}, fmt.Errorf("persist phishing message evidence: %w", err)
	}
	report.EvidenceIDs = append(report.EvidenceIDs, messageEvidence.ID)

	indicators := uniqueURLs(urlPattern.FindAllString(string(input.Message), -1))
	malicious := false
	for index, indicator := range indicators {
		if w.intel == nil {
			report.Warnings = append(report.Warnings, "threat intelligence unavailable for "+indicator)
			continue
		}
		result, lookupErr := w.intel.Lookup(runCtx, indicator)
		if lookupErr != nil {
			if runCtx.Err() != nil {
				return Report{}, fmt.Errorf("query threat intelligence: %w", runCtx.Err())
			}
			report.Warnings = append(report.Warnings, "threat intelligence lookup failed for "+indicator)
			continue
		}
		intelEvidence, putErr := w.store.PutEvidence(runCtx, evidence.Evidence{
			ID: fmt.Sprintf("%s-intel-%d", input.TaskID, index+1), TaskID: input.TaskID,
			Source:  evidence.EvidenceSource{Type: "threat_intel", Reference: result.Source},
			Summary: result.Summary, TrustLevel: evidence.TrustMedium,
			Completeness: evidence.CompletenessComplete,
		}, result.Raw)
		if putErr != nil {
			return Report{}, fmt.Errorf("persist threat intelligence evidence: %w", putErr)
		}
		report.EvidenceIDs = append(report.EvidenceIDs, intelEvidence.ID)
		malicious = malicious || result.Malicious
	}

	statement := "The message was collected for analysis."
	if len(indicators) > 0 {
		statement = fmt.Sprintf("The message contains %d HTTP(S) indicator(s).", len(indicators))
	}
	factID := input.TaskID + "-message-fact"
	if err := w.store.PutFact(runCtx, evidence.Fact{
		ID: factID, TaskID: input.TaskID, Statement: statement, EvidenceIDs: []string{messageEvidence.ID},
	}); err != nil {
		return Report{}, fmt.Errorf("persist phishing fact: %w", err)
	}
	report.FactIDs = []string{factID}

	severity := evidence.SeverityMedium
	if malicious {
		severity = evidence.SeverityHigh
	}
	finding := evidence.Finding{
		ID: findingID, TaskID: input.TaskID, MakerID: input.MakerID, Severity: severity,
		FactIDs: []string{factID}, Recommendation: "Quarantine the message and validate affected identities before response actions.",
		Status: evidence.FindingPreliminary,
	}
	if err := w.store.PutFinding(runCtx, finding); err != nil {
		return Report{}, fmt.Errorf("persist phishing finding: %w", err)
	}
	report.Finding = finding

	check, err := w.checker.Check(runCtx, CheckRequest{
		TaskID: input.TaskID, Finding: finding, EvidenceIDs: append([]string(nil), report.EvidenceIDs...),
	})
	if err != nil {
		return Report{}, fmt.Errorf("independent phishing check: %w", err)
	}
	verification := evidence.Verification{
		FindingID: finding.ID, TaskID: input.TaskID, CheckerID: input.CheckerID,
		Verdict: check.Verdict, EvidenceIDs: check.EvidenceIDs, Reason: check.Reason,
	}
	if err := w.store.VerifyFinding(runCtx, verification); err != nil {
		return Report{}, fmt.Errorf("persist phishing verification: %w", err)
	}
	verification, err = w.store.GetVerification(runCtx, finding.ID)
	if err != nil {
		return Report{}, fmt.Errorf("reload phishing verification: %w", err)
	}
	report.Verification = verification

	if err := w.auditor.Record(runCtx, AuditEvent{
		TaskID: input.TaskID, Action: "phishing_investigation_completed",
		EvidenceIDs: report.EvidenceIDs, FindingID: finding.ID, Verification: verification.Verdict,
	}); err != nil {
		return Report{}, fmt.Errorf("audit phishing investigation completion: %w", err)
	}
	return report, nil
}

func uniqueURLs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimRight(value, ".,;:!?)")
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
