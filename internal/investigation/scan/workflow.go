// Package scan implements a durable, human-reviewed local scanning workflow.
package scan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chenchunrun/SecOps/internal/evidence"
	"github.com/chenchunrun/SecOps/internal/skills"
	"github.com/google/uuid"
)

type Scanner interface {
	ExecuteContext(context.Context, interface{}) (interface{}, error)
}

// Authorize must validate the session's current, unrevoked target grant.
type (
	Authorize func(sessionID, subject, target string) error
	Audit     func(sessionID, taskID, action, target string) error
)

var errSessionMismatch = errors.New("scan session mismatch")

type Record struct {
	ID         string    `json:"id"`
	SessionID  string    `json:"session_id"`
	Subject    string    `json:"subject"`
	Directory  string    `json:"directory"`
	Scope      string    `json:"scope"`
	State      string    `json:"state"`
	Error      string    `json:"error,omitempty"`
	EvidenceID string    `json:"evidence_id,omitempty"`
	FindingID  string    `json:"finding_id,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Service struct {
	mu        sync.Mutex
	root      string
	evidence  *evidence.FileStore
	runner    *skills.Runner
	manifest  *skills.SkillManifest
	authorize Authorize
	audit     Audit
	active    map[string]context.CancelFunc
}

func New(root string, store *evidence.FileStore, scanner Scanner, authorize Authorize, audit Audit) (*Service, error) {
	if root == "" || store == nil || scanner == nil || authorize == nil || audit == nil {
		return nil, errors.New("scan workflow requires persistence, scanner, authorization and audit")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	runner, manifest, err := newScanSkill(scanner)
	if err != nil {
		return nil, err
	}
	return &Service{root: root, evidence: store, runner: runner, manifest: manifest, authorize: authorize, audit: audit, active: make(map[string]context.CancelFunc)}, nil
}

// Target binds a grant to one canonical directory without host normalization.
func Target(directory string) (string, string, error) {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return "", "", err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", "", err
	}
	if !info.IsDir() {
		return "", "", errors.New("scan target must be a directory")
	}
	return abs, fmt.Sprintf("scan-%x", sha256.Sum256([]byte(abs))), nil
}

// Prepare reserves a durable task before any scanner process is launched.
func (s *Service) Prepare(ctx context.Context, sessionID, subject, directory string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	directory, scope, err := Target(directory)
	if err != nil {
		return Record{}, err
	}
	if sessionID == "" || subject == "" {
		return Record{}, errors.New("session and subject are required")
	}
	if err := s.authorize(sessionID, subject, scope); err != nil {
		return Record{}, err
	}
	record := Record{ID: uuid.NewString(), SessionID: sessionID, Subject: subject, Directory: directory, Scope: scope, State: "pending"}
	s.mu.Lock()
	defer s.mu.Unlock()
	return record, s.save(record)
}

func (s *Service) Run(ctx context.Context, sessionID, id string) (record Record, err error) {
	s.mu.Lock()
	record, err = s.load(sessionID, id)
	if err != nil {
		s.mu.Unlock()
		return record, err
	}
	if record.State != "pending" {
		s.mu.Unlock()
		return record, errors.New("scan is not pending")
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.active[id] = cancel
	record.State = "running"
	err = s.save(record)
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.active, id)
		if err != nil {
			record.State, record.Error = "failed", err.Error()
			if errors.Is(err, context.Canceled) {
				record.State = "canceled"
			}
			err = errors.Join(err, s.audit(sessionID, id, "scan_"+record.State, record.Directory))
		}
		if saveErr := s.save(record); saveErr != nil {
			err = errors.Join(err, saveErr)
		}
	}()
	if err != nil {
		return record, err
	}
	if err = s.authorize(record.SessionID, record.Subject, record.Scope); err != nil {
		return record, err
	}
	// Check canonicalization again after queueing to reject a replaced symlink.
	_, scope, targetErr := Target(record.Directory)
	if targetErr != nil || scope != record.Scope {
		return record, errors.New("scan target changed since authorization")
	}
	if err = s.audit(sessionID, id, "scan_started", record.Directory); err != nil {
		return record, err
	}
	// Revocation and expiry also stop an already running scan.
	watchDone := make(chan struct{})
	defer close(watchDone)
	watchSession, watchSubject, watchScope := record.SessionID, record.Subject, record.Scope
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if s.authorize(watchSession, watchSubject, watchScope) != nil {
					cancel()
					return
				}
			}
		}
	}()
	output, scanErr := s.runner.Run(runCtx, *s.manifest, skills.RuntimeRequest{
		Platform: runtime.GOOS, SignedScope: true,
		GrantedCapabilities: map[string]bool{"security:scan": true},
		Input:               map[string]interface{}{"task_id": id, "directory": record.Directory},
	})
	if scanErr != nil {
		return record, scanErr
	}
	if err = runCtx.Err(); err != nil {
		return record, err
	}
	if err = s.authorize(record.SessionID, record.Subject, record.Scope); err != nil {
		return record, err
	}
	result, err := decodeScanOutput(output.Output)
	if err != nil {
		return record, err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return record, err
	}
	record.EvidenceID, record.FindingID = id+"-output", id+"-finding"
	_, err = s.evidence.PutEvidence(runCtx, evidence.Evidence{
		ID: record.EvidenceID, TaskID: id, Source: evidence.EvidenceSource{Type: "scanner_output", Reference: record.Directory},
		Summary: "Normalized Trivy vulnerability output; requires human review", TrustLevel: evidence.TrustUntrusted, Completeness: evidence.CompletenessComplete,
	}, raw)
	if err != nil {
		return record, err
	}
	if err = s.evidence.PutFact(runCtx, evidence.Fact{ID: id + "-fact", TaskID: id, Statement: fmt.Sprintf("Trivy reported %d vulnerabilities; this is not independent confirmation of exploitability", result.TotalVulnerabilities), EvidenceIDs: []string{record.EvidenceID}}); err != nil {
		return record, err
	}
	severity := evidence.SeverityLow
	if result.MediumCount > 0 {
		severity = evidence.SeverityMedium
	}
	if result.HighCount > 0 {
		severity = evidence.SeverityHigh
	}
	if result.CriticalCount > 0 {
		severity = evidence.SeverityCritical
	}
	if err = s.evidence.PutFinding(runCtx, evidence.Finding{ID: record.FindingID, TaskID: id, MakerID: "trivy-scanner", Severity: severity, FactIDs: []string{id + "-fact"}, Recommendation: "Review package applicability and scanner evidence before remediation; no automatic fix was performed"}); err != nil {
		return record, err
	}
	if err = s.audit(sessionID, id, "scan_awaiting_review", record.Directory); err != nil {
		return record, err
	}
	record.State = "awaiting_review"
	return record, nil
}

// Review records an explicit human decision; it is not exposed as an LLM tool.
func (s *Service) Review(ctx context.Context, sessionID, id string, verdict evidence.Verdict, reason string) (evidence.Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.load(sessionID, id)
	if err != nil {
		return evidence.Report{}, err
	}
	if record.State != "awaiting_review" {
		return evidence.Report{}, errors.New("scan is not awaiting review")
	}
	if strings.TrimSpace(reason) == "" || (verdict != evidence.VerdictPassed && verdict != evidence.VerdictRejected) {
		return evidence.Report{}, errors.New("review requires passed/rejected and a reason")
	}
	reviewer, err := user.Current()
	if err != nil || reviewer.Uid == "" {
		return evidence.Report{}, errors.New("cannot resolve local reviewer identity")
	}
	if err := s.audit(sessionID, id, "scan_review_"+string(verdict), record.Directory); err != nil {
		return evidence.Report{}, err
	}
	checkerID := fmt.Sprintf("local-user-%x", sha256.Sum256([]byte(reviewer.Uid)))
	verification := evidence.Verification{FindingID: record.FindingID, TaskID: id, CheckerID: checkerID, Verdict: verdict, EvidenceIDs: []string{record.EvidenceID}, Reason: reason}
	if err := s.evidence.VerifyFinding(ctx, verification); err != nil {
		// Recover a report write failure without overwriting an existing decision.
		if !errors.Is(err, evidence.ErrAlreadyExists) {
			return evidence.Report{}, err
		}
		previous, loadErr := s.evidence.GetVerification(ctx, record.FindingID)
		if loadErr != nil || previous.Verdict != verdict || previous.Reason != reason {
			return evidence.Report{}, errors.New("review decision is already recorded")
		}
	}
	if verdict == evidence.VerdictRejected {
		record.State = "rejected"
		return evidence.Report{}, s.save(record)
	}
	report, err := s.evidence.BuildReport(ctx, record.FindingID)
	if err != nil {
		return report, err
	}
	record.State = "reviewed"
	return report, s.save(record)
}

func (s *Service) Get(sessionID, id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.load(sessionID, id)
	if r.State == "running" && s.active[id] == nil {
		r.State = "interrupted"
	}
	return r, err
}

func (s *Service) List(sessionID string) ([]Record, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		r, err := s.Get(sessionID, strings.TrimSuffix(entry.Name(), ".json"))
		if errors.Is(err, errSessionMismatch) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("load scan %s: %w", entry.Name(), err)
		}
		records = append(records, r)
	}
	return records, nil
}

func (s *Service) Report(ctx context.Context, sessionID, id string) (evidence.Report, error) {
	r, err := s.Get(sessionID, id)
	if err != nil {
		return evidence.Report{}, err
	}
	if r.State != "reviewed" {
		return evidence.Report{}, errors.New("report requires a passed human review")
	}
	return s.evidence.BuildReport(ctx, r.FindingID)
}

func (s *Service) Cancel(sessionID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.load(sessionID, id)
	if err != nil {
		return err
	}
	if err := s.audit(sessionID, id, "scan_cancel", r.Directory); err != nil {
		return err
	}
	if cancel := s.active[id]; cancel != nil {
		cancel()
		return nil
	}
	if r.State == "pending" {
		r.State = "canceled"
		return s.save(r)
	}
	return errors.New("scan is not running or pending")
}

func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cancel := range s.active {
		cancel()
	}
}

func (s *Service) load(sessionID, id string) (Record, error) {
	if _, err := uuid.Parse(id); err != nil {
		return Record{}, errors.New("invalid scan id")
	}
	data, err := os.ReadFile(filepath.Join(s.root, id+".json"))
	if err != nil {
		return Record{}, err
	}
	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		return Record{}, err
	}
	if record.ID != id || record.SessionID != sessionID {
		return Record{}, errSessionMismatch
	}
	return record, nil
}

func (s *Service) save(record Record) error {
	record.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(s.root, ".scan-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(s.root, record.ID+".json"))
}
