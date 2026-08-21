package collaboration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Receipt struct {
	HandoffID  string    `json:"handoff_id"`
	Consumer   string    `json:"consumer"`
	ResultRef  string    `json:"result_ref"`
	ConsumedAt time.Time `json:"consumed_at"`
}

type Handler func(context.Context, HandoffEnvelope) (string, error)

type FileStore struct {
	envelopes string
	receipts  string
	mu        sync.Mutex
}

func NewFileStore(root string) (*FileStore, error) {
	if root == "" {
		return nil, errors.New("initialize handoff store: root is empty")
	}
	store := &FileStore{envelopes: filepath.Join(root, "envelopes"), receipts: filepath.Join(root, "receipts")}
	for _, directory := range []string{store.envelopes, store.receipts} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create handoff store: %w", err)
		}
	}
	return store, nil
}

func (s *FileStore) Publish(ctx context.Context, envelope HandoffEnvelope) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := envelope.Validate(); err != nil {
		return err
	}
	if envelope.CreatedAt.IsZero() {
		envelope.CreatedAt = time.Now().UTC()
	}
	return writeImmutableJSON(filepath.Join(s.envelopes, envelope.ID+".json"), envelope)
}

func (s *FileStore) Get(ctx context.Context, id string) (HandoffEnvelope, error) {
	var envelope HandoffEnvelope
	if !validID(id) {
		return envelope, ErrNotFound
	}
	if err := readJSON(ctx, filepath.Join(s.envelopes, id+".json"), &envelope); err != nil {
		return HandoffEnvelope{}, err
	}
	return envelope, nil
}

func (s *FileStore) Consume(ctx context.Context, id, consumer string, grants map[string]bool, handler Handler) (Receipt, bool, error) {
	if handler == nil {
		return Receipt{}, false, errors.New("consume handoff: handler is nil")
	}
	envelope, err := s.Get(ctx, id)
	if err != nil {
		return Receipt{}, false, err
	}
	if consumer != envelope.Consumer {
		return Receipt{}, false, ErrPermissionDenied
	}
	for _, capability := range envelope.RequiredCapabilities {
		if !grants[capability] {
			return Receipt{}, false, fmt.Errorf("%w: %s", ErrPermissionDenied, capability)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var existing Receipt
	receiptPath := filepath.Join(s.receipts, id+".json")
	if err := readJSON(ctx, receiptPath, &existing); err == nil {
		return existing, false, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Receipt{}, false, err
	}
	resultRef, err := handler(ctx, envelope)
	if err != nil {
		return Receipt{}, false, fmt.Errorf("consume handoff %s: %w", id, err)
	}
	if !validID(resultRef) {
		return Receipt{}, false, errors.New("consume handoff: handler returned invalid result reference")
	}
	receipt := Receipt{HandoffID: id, Consumer: consumer, ResultRef: resultRef, ConsumedAt: time.Now().UTC()}
	if err := writeImmutableJSON(receiptPath, receipt); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			if loadErr := readJSON(ctx, receiptPath, &existing); loadErr == nil {
				return existing, false, nil
			}
		}
		return Receipt{}, false, err
	}
	return receipt, true, nil
}

func writeImmutableJSON(path string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
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

func readJSON(ctx context.Context, path string, target interface{}) error {
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
		return err
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
