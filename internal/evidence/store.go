package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type FileStore struct {
	root          string
	evidenceRoot  string
	rawRoot       string
	factRoot      string
	inferenceRoot string
	findingRoot   string
	verifyRoot    string
	mu            sync.Mutex
}

func NewFileStore(root string) (*FileStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("initialize evidence store: root is empty")
	}
	store := &FileStore{
		root:          root,
		evidenceRoot:  filepath.Join(root, "evidence"),
		rawRoot:       filepath.Join(root, "raw"),
		factRoot:      filepath.Join(root, "facts"),
		inferenceRoot: filepath.Join(root, "inferences"),
		findingRoot:   filepath.Join(root, "findings"),
		verifyRoot:    filepath.Join(root, "verifications"),
	}
	for _, directory := range []string{store.root, store.evidenceRoot, store.rawRoot, store.factRoot, store.inferenceRoot, store.findingRoot, store.verifyRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create evidence store directory: %w", err)
		}
	}
	return store, nil
}

func (s *FileStore) PutEvidence(ctx context.Context, item Evidence, raw []byte) (Evidence, error) {
	if err := contextError(ctx); err != nil {
		return Evidence{}, err
	}
	if !validID(item.ID) || !validID(item.TaskID) || strings.TrimSpace(item.Source.Type) == "" || strings.TrimSpace(item.Source.Reference) == "" || !validTrust(item.TrustLevel) || !validCompleteness(item.Completeness) {
		return Evidence{}, ErrInvalidRecord
	}
	if item.Completeness == CompletenessComplete && item.Failure != "" {
		return Evidence{}, ErrInvalidRecord
	}
	if item.CollectedAt.IsZero() {
		item.CollectedAt = time.Now().UTC()
	}
	digest := sha256.Sum256(raw)
	item.ContentHash = "sha256:" + hex.EncodeToString(digest[:])
	item.RawReference = item.ID + ".bin"

	s.mu.Lock()
	defer s.mu.Unlock()
	rawPath := filepath.Join(s.rawRoot, item.RawReference)
	if err := writeImmutable(rawPath, raw); err != nil {
		return Evidence{}, fmt.Errorf("persist raw evidence: %w", err)
	}
	metadataPath := recordPath(s.evidenceRoot, item.ID)
	if err := writeImmutableJSON(metadataPath, item); err != nil {
		_ = os.Remove(rawPath)
		return Evidence{}, fmt.Errorf("persist evidence metadata: %w", err)
	}
	return item, nil
}

func (s *FileStore) GetEvidence(ctx context.Context, id string) (Evidence, []byte, error) {
	var item Evidence
	if err := readJSON(ctx, recordPath(s.evidenceRoot, id), &item); err != nil {
		return Evidence{}, nil, err
	}
	if item.RawReference != item.ID+".bin" {
		return Evidence{}, nil, ErrIntegrity
	}
	raw, err := os.ReadFile(filepath.Join(s.rawRoot, item.RawReference))
	if err != nil {
		return Evidence{}, nil, fmt.Errorf("%w: read raw evidence: %v", ErrIntegrity, err)
	}
	digest := sha256.Sum256(raw)
	if item.ContentHash != "sha256:"+hex.EncodeToString(digest[:]) {
		return Evidence{}, nil, ErrIntegrity
	}
	return item, raw, nil
}

func (s *FileStore) PutFact(ctx context.Context, fact Fact) error {
	if !validID(fact.ID) || !validID(fact.TaskID) || strings.TrimSpace(fact.Statement) == "" || len(fact.EvidenceIDs) == 0 {
		return ErrInvalidRecord
	}
	for _, evidenceID := range unique(fact.EvidenceIDs) {
		item, _, err := s.GetEvidence(ctx, evidenceID)
		if err != nil {
			return fmt.Errorf("validate fact evidence %s: %w", evidenceID, err)
		}
		if item.TaskID != fact.TaskID {
			return ErrTaskMismatch
		}
		if item.Completeness != CompletenessComplete {
			return ErrIncomplete
		}
	}
	fact.EvidenceIDs = unique(fact.EvidenceIDs)
	return writeImmutableJSON(recordPath(s.factRoot, fact.ID), fact)
}

func (s *FileStore) GetFact(ctx context.Context, id string) (Fact, error) {
	var fact Fact
	if err := readJSON(ctx, recordPath(s.factRoot, id), &fact); err != nil {
		return Fact{}, err
	}
	return fact, nil
}

func (s *FileStore) PutInference(ctx context.Context, inference Inference) error {
	if !validID(inference.ID) || !validID(inference.TaskID) || strings.TrimSpace(inference.Statement) == "" || len(inference.FactIDs) == 0 || inference.Confidence < 0 || inference.Confidence > 1 {
		return ErrInvalidRecord
	}
	for _, factID := range unique(inference.FactIDs) {
		fact, err := s.GetFact(ctx, factID)
		if err != nil {
			return fmt.Errorf("validate inference fact %s: %w", factID, err)
		}
		if fact.TaskID != inference.TaskID {
			return ErrTaskMismatch
		}
	}
	inference.FactIDs = unique(inference.FactIDs)
	return writeImmutableJSON(recordPath(s.inferenceRoot, inference.ID), inference)
}

func (s *FileStore) GetInference(ctx context.Context, id string) (Inference, error) {
	var inference Inference
	if err := readJSON(ctx, recordPath(s.inferenceRoot, id), &inference); err != nil {
		return Inference{}, err
	}
	return inference, nil
}

func (s *FileStore) PutFinding(ctx context.Context, finding Finding) error {
	if !validID(finding.ID) || !validID(finding.TaskID) || !validID(finding.MakerID) || !validSeverity(finding.Severity) || len(finding.FactIDs) == 0 || strings.TrimSpace(finding.Recommendation) == "" {
		return ErrInvalidRecord
	}
	if finding.Status == FindingVerified {
		return fmt.Errorf("%w: findings must be verified by a checker", ErrInvalidRecord)
	}
	if finding.Status == "" {
		finding.Status = FindingPreliminary
	}
	if finding.Status != FindingPreliminary && finding.Status != FindingNeedsEvidence {
		return ErrInvalidRecord
	}
	for _, factID := range unique(finding.FactIDs) {
		fact, err := s.GetFact(ctx, factID)
		if err != nil {
			return fmt.Errorf("validate finding fact %s: %w", factID, err)
		}
		if fact.TaskID != finding.TaskID {
			return ErrTaskMismatch
		}
	}
	finding.FactIDs = unique(finding.FactIDs)
	return writeImmutableJSON(recordPath(s.findingRoot, finding.ID), finding)
}

func (s *FileStore) GetFinding(ctx context.Context, id string) (Finding, error) {
	var finding Finding
	if err := readJSON(ctx, recordPath(s.findingRoot, id), &finding); err != nil {
		return Finding{}, err
	}
	return finding, nil
}

func (s *FileStore) VerifyFinding(ctx context.Context, verification Verification) error {
	var finding Finding
	if err := readJSON(ctx, recordPath(s.findingRoot, verification.FindingID), &finding); err != nil {
		return fmt.Errorf("load finding for verification: %w", err)
	}
	if !validID(verification.CheckerID) || verification.CheckerID == finding.MakerID {
		return ErrCheckerNotIsolated
	}
	if verification.TaskID != finding.TaskID || !validVerdict(verification.Verdict) || strings.TrimSpace(verification.Reason) == "" {
		return ErrInvalidRecord
	}
	if (finding.Severity == SeverityHigh || finding.Severity == SeverityCritical) && verification.Verdict == VerdictPassed && len(verification.EvidenceIDs) == 0 {
		return ErrIncomplete
	}
	for _, evidenceID := range unique(verification.EvidenceIDs) {
		item, _, err := s.GetEvidence(ctx, evidenceID)
		if err != nil {
			return fmt.Errorf("validate verification evidence %s: %w", evidenceID, err)
		}
		if item.TaskID != finding.TaskID {
			return ErrTaskMismatch
		}
		if item.Completeness != CompletenessComplete {
			return ErrIncomplete
		}
	}
	if verification.CheckedAt.IsZero() {
		verification.CheckedAt = time.Now().UTC()
	}
	verification.EvidenceIDs = unique(verification.EvidenceIDs)
	return writeImmutableJSON(recordPath(s.verifyRoot, verification.FindingID), verification)
}

func (s *FileStore) GetVerification(ctx context.Context, findingID string) (Verification, error) {
	var verification Verification
	if err := readJSON(ctx, recordPath(s.verifyRoot, findingID), &verification); err != nil {
		return Verification{}, err
	}
	return verification, nil
}

func recordPath(root, id string) string {
	if !validID(id) {
		return filepath.Join(root, "__invalid__")
	}
	return filepath.Join(root, id+".json")
}

func writeImmutableJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode evidence record: %w", err)
	}
	return writeImmutable(path, data)
}

func writeImmutable(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrAlreadyExists
	}
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func readJSON(ctx context.Context, path string, target any) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode evidence record: %w", err)
	}
	return nil
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func validID(value string) bool { return idPattern.MatchString(value) }

func validTrust(value TrustLevel) bool {
	return value == TrustUntrusted || value == TrustLow || value == TrustMedium || value == TrustHigh
}

func validCompleteness(value Completeness) bool {
	return value == CompletenessComplete || value == CompletenessTruncated || value == CompletenessFailed
}

func validSeverity(value Severity) bool {
	return value == SeverityLow || value == SeverityMedium || value == SeverityHigh || value == SeverityCritical
}

func validVerdict(value Verdict) bool {
	return value == VerdictPassed || value == VerdictRejected || value == VerdictNeedsEvidence
}

func unique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !validID(value) {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
