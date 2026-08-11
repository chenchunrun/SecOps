package verification

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
	"sort"
	"strings"
)

var recordIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type FileStore struct {
	root         string
	requestsRoot string
	evidenceRoot string
	payloadRoot  string
	resultsRoot  string
}

func NewFileStore(root string) (*FileStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("initialize verification store: root is empty")
	}
	store := &FileStore{
		root:         root,
		requestsRoot: filepath.Join(root, "requests"),
		evidenceRoot: filepath.Join(root, "evidence"),
		payloadRoot:  filepath.Join(root, "payloads"),
		resultsRoot:  filepath.Join(root, "results"),
	}
	for _, directory := range []string{store.root, store.requestsRoot, store.evidenceRoot, store.payloadRoot, store.resultsRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create verification store directory: %w", err)
		}
	}
	return store, nil
}

func (s *FileStore) CreateRequest(ctx context.Context, request Request) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	return writeImmutableJSON(filepath.Join(s.requestsRoot, request.ID+".json"), request)
}

func (s *FileStore) GetRequest(ctx context.Context, id string) (Request, error) {
	var request Request
	if !recordIDPattern.MatchString(id) {
		return request, ErrNotFound
	}
	if err := readJSON(ctx, filepath.Join(s.requestsRoot, id+".json"), &request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func (s *FileStore) CreateEvidence(ctx context.Context, evidence Evidence, payload []byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !recordIDPattern.MatchString(evidence.ID) || !recordIDPattern.MatchString(evidence.Locator) {
		return ErrInvalidEvidence
	}
	if err := writeImmutableBytes(s.payloadPath(evidence.Locator), payload); err != nil {
		return err
	}
	if err := writeImmutableJSON(filepath.Join(s.evidenceRoot, evidence.ID+".json"), evidence); err != nil {
		return err
	}
	return nil
}

func (s *FileStore) ListEvidence(ctx context.Context, requestID string) ([]Evidence, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.evidenceRoot)
	if err != nil {
		return nil, fmt.Errorf("list verification evidence: %w", err)
	}
	evidence := make([]Evidence, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		var item Evidence
		if err := readJSON(ctx, filepath.Join(s.evidenceRoot, entry.Name()), &item); err != nil {
			return nil, err
		}
		if item.RequestID == requestID {
			evidence = append(evidence, item)
		}
	}
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].ID < evidence[j].ID })
	return evidence, nil
}

func (s *FileStore) LoadPayload(ctx context.Context, evidence Evidence) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !recordIDPattern.MatchString(evidence.Locator) {
		return nil, ErrIntegrity
	}
	payload, err := os.ReadFile(s.payloadPath(evidence.Locator))
	if err != nil {
		return nil, fmt.Errorf("%w: read evidence %s: %v", ErrIntegrity, evidence.ID, err)
	}
	digest := sha256.Sum256(payload)
	actual := "sha256:" + hex.EncodeToString(digest[:])
	if actual != evidence.Digest || int64(len(payload)) != evidence.Size {
		return nil, fmt.Errorf("%w: evidence %s digest or size mismatch", ErrIntegrity, evidence.ID)
	}
	return payload, nil
}

func (s *FileStore) CreateResult(ctx context.Context, result Result) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	return writeImmutableJSON(filepath.Join(s.resultsRoot, result.RequestID+".json"), result)
}

func (s *FileStore) GetResult(ctx context.Context, requestID string) (Result, error) {
	var result Result
	if !recordIDPattern.MatchString(requestID) {
		return result, ErrNotFound
	}
	if err := readJSON(ctx, filepath.Join(s.resultsRoot, requestID+".json"), &result); err != nil {
		return Result{}, err
	}
	return result, nil
}

func (s *FileStore) payloadPath(locator string) string {
	return filepath.Join(s.payloadRoot, locator+".bin")
}

func writeImmutableJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode verification record: %w", err)
	}
	return writeImmutableBytes(path, data)
}

func writeImmutableBytes(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("create verification record: %w", err)
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write verification record: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync verification record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close verification record: %w", err)
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
		return fmt.Errorf("read verification record: %w", err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode verification record: %w", err)
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
