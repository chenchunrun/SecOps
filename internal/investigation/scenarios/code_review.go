package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/chenchunrun/SecOps/internal/evidence"
)

type DependencyFinding struct {
	ID             string   `json:"id"`
	Package        string   `json:"package"`
	Version        string   `json:"version"`
	AdvisorySource string   `json:"advisory_source"`
	Reachable      bool     `json:"reachable"`
	AllowedPaths   []string `json:"allowed_paths"`
}

type ScanResult struct {
	Findings []DependencyFinding `json:"findings"`
	Raw      []byte              `json:"-"`
}

type CodeScanner interface {
	Scan(context.Context, string) (ScanResult, error)
}

type ChangeSet struct {
	TouchedPaths []string          `json:"touched_paths"`
	BeforeHashes map[string]string `json:"before_hashes"`
	AfterHashes  map[string]string `json:"after_hashes"`
	Raw          []byte            `json:"-"`
}

type CodeFixer interface {
	Apply(context.Context, DependencyFinding) (ChangeSet, error)
}

type TestResult struct {
	Passed bool   `json:"passed"`
	Raw    []byte `json:"-"`
}

type CodeTester interface {
	Test(context.Context, []string) (TestResult, error)
}

type CodeReviewInput struct {
	TaskID            string
	Repository        string
	MakerID           string
	CheckerID         string
	ApplyFix          bool
	FixApproved       bool
	WorkspaceBaseline map[string]string
}

type CodeReviewReport struct {
	TaskID       string
	FindingID    string
	EvidenceIDs  []string
	Reachable    []string
	Theoretical  []string
	FixApplied   bool
	TestsPassed  bool
	Verification evidence.Verdict
}

type CodeReviewWorkflow struct {
	store   *evidence.FileStore
	scanner CodeScanner
	fixer   CodeFixer
	tester  CodeTester
	auditor ScenarioAuditor
}

func NewCodeReviewWorkflow(store *evidence.FileStore, scanner CodeScanner, fixer CodeFixer, tester CodeTester, auditor ScenarioAuditor) (*CodeReviewWorkflow, error) {
	if store == nil || scanner == nil || auditor == nil {
		return nil, errors.New("initialize code review workflow: store, scanner, and auditor are required")
	}
	return &CodeReviewWorkflow{store: store, scanner: scanner, fixer: fixer, tester: tester, auditor: auditor}, nil
}

func (w *CodeReviewWorkflow) Run(ctx context.Context, input CodeReviewInput) (CodeReviewReport, error) {
	if input.TaskID == "" || input.Repository == "" || input.MakerID == "" || input.CheckerID == "" {
		return CodeReviewReport{}, errors.New("run code review workflow: invalid input")
	}
	scan, err := w.scanner.Scan(ctx, input.Repository)
	if err != nil {
		return CodeReviewReport{}, fmt.Errorf("scan repository: %w", err)
	}
	if err := validateDependencyFindings(scan.Findings); err != nil {
		return CodeReviewReport{}, err
	}
	if len(scan.Raw) == 0 {
		scan.Raw, _ = json.Marshal(scan.Findings)
	}
	scanEvidence, err := w.store.PutEvidence(ctx, evidence.Evidence{
		ID: input.TaskID + "-code-scan", TaskID: input.TaskID,
		Source:  evidence.EvidenceSource{Type: "dependency_scan", Reference: input.Repository},
		Summary: "Versioned dependency and reachability scan", TrustLevel: evidence.TrustHigh,
		Completeness: evidence.CompletenessComplete,
	}, scan.Raw)
	if err != nil {
		return CodeReviewReport{}, fmt.Errorf("persist code scan evidence: %w", err)
	}
	report := CodeReviewReport{TaskID: input.TaskID, FindingID: input.TaskID + "-code-finding", EvidenceIDs: []string{scanEvidence.ID}}
	var target *DependencyFinding
	for index := range scan.Findings {
		finding := scan.Findings[index]
		if finding.Reachable {
			report.Reachable = append(report.Reachable, finding.ID)
			if target == nil {
				target = &scan.Findings[index]
			}
		} else {
			report.Theoretical = append(report.Theoretical, finding.ID)
		}
	}

	if input.ApplyFix {
		if !input.FixApproved || target == nil || w.fixer == nil || w.tester == nil {
			return CodeReviewReport{}, errors.New("code fix requires approval, a reachable finding, fixer, and tester")
		}
		if err := w.auditor.Record(ctx, ScenarioAuditEvent{TaskID: input.TaskID, Action: "code_fix", Target: input.Repository, EvidenceIDs: report.EvidenceIDs}); err != nil {
			return CodeReviewReport{}, fmt.Errorf("audit code fix: %w", err)
		}
		change, err := w.fixer.Apply(ctx, *target)
		if err != nil {
			return CodeReviewReport{}, fmt.Errorf("apply code fix: %w", err)
		}
		if err := validateChangeSet(change, target.AllowedPaths, input.WorkspaceBaseline); err != nil {
			return CodeReviewReport{}, err
		}
		changeRaw := change.Raw
		if len(changeRaw) == 0 {
			changeRaw, _ = json.Marshal(change)
		}
		changeEvidence, err := w.store.PutEvidence(ctx, evidence.Evidence{
			ID: input.TaskID + "-change", TaskID: input.TaskID,
			Source:  evidence.EvidenceSource{Type: "change_set", Reference: input.Repository},
			Summary: "Minimal approved code change", TrustLevel: evidence.TrustHigh, Completeness: evidence.CompletenessComplete,
		}, changeRaw)
		if err != nil {
			return CodeReviewReport{}, err
		}
		report.EvidenceIDs = append(report.EvidenceIDs, changeEvidence.ID)
		testResult, err := w.tester.Test(ctx, change.TouchedPaths)
		if err != nil || !testResult.Passed {
			return CodeReviewReport{}, errors.New("code fix cannot be verified without passing test evidence")
		}
		testEvidence, err := w.store.PutEvidence(ctx, evidence.Evidence{
			ID: input.TaskID + "-tests", TaskID: input.TaskID,
			Source:  evidence.EvidenceSource{Type: "test_result", Reference: input.Repository},
			Summary: "Post-fix regression tests passed", TrustLevel: evidence.TrustHigh, Completeness: evidence.CompletenessComplete,
		}, testResult.Raw)
		if err != nil {
			return CodeReviewReport{}, err
		}
		report.EvidenceIDs = append(report.EvidenceIDs, testEvidence.ID)
		report.FixApplied = true
		report.TestsPassed = true
	}

	factID := input.TaskID + "-code-fact"
	statement := fmt.Sprintf("Dependency scan found %d reachable and %d theoretical finding(s), with version and advisory source recorded.", len(report.Reachable), len(report.Theoretical))
	if err := w.store.PutFact(ctx, evidence.Fact{ID: factID, TaskID: input.TaskID, Statement: statement, EvidenceIDs: []string{scanEvidence.ID}}); err != nil {
		return CodeReviewReport{}, err
	}
	severity := evidence.SeverityMedium
	if len(report.Reachable) > 0 {
		severity = evidence.SeverityHigh
	}
	if err := w.store.PutFinding(ctx, evidence.Finding{
		ID: report.FindingID, TaskID: input.TaskID, MakerID: input.MakerID, Severity: severity,
		FactIDs: []string{factID}, Recommendation: "Prioritize reachable vulnerabilities and verify fixes with tests.",
	}); err != nil {
		return CodeReviewReport{}, err
	}
	verificationEvidence := []string{scanEvidence.ID}
	if input.ApplyFix {
		verificationEvidence = report.EvidenceIDs
	}
	if err := w.store.VerifyFinding(ctx, evidence.Verification{
		FindingID: report.FindingID, TaskID: input.TaskID, CheckerID: input.CheckerID,
		Verdict: evidence.VerdictPassed, EvidenceIDs: verificationEvidence,
		Reason: "dependency source, reachability, workspace integrity, and available test evidence verified",
	}); err != nil {
		return CodeReviewReport{}, err
	}
	report.Verification = evidence.VerdictPassed
	return report, nil
}

func validateDependencyFindings(findings []DependencyFinding) error {
	for _, finding := range findings {
		if finding.ID == "" || finding.Package == "" || finding.Version == "" || finding.AdvisorySource == "" {
			return errors.New("dependency finding requires id, package, version, and advisory source")
		}
	}
	return nil
}

func validateChangeSet(change ChangeSet, allowed []string, baseline map[string]string) error {
	allowedSet := make(map[string]bool, len(allowed))
	for _, path := range allowed {
		allowedSet[path] = true
	}
	for _, path := range change.TouchedPaths {
		if !allowedSet[path] {
			return fmt.Errorf("code fix touched unrelated path %s", path)
		}
		if baseline[path] == "" || change.BeforeHashes[path] != baseline[path] || change.AfterHashes[path] == "" {
			return fmt.Errorf("workspace baseline changed for %s", path)
		}
	}
	sorted := append([]string(nil), change.TouchedPaths...)
	sort.Strings(sorted)
	if len(sorted) == 0 {
		return errors.New("code fix produced no changes")
	}
	return nil
}
