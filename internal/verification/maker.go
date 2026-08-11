package verification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type Maker struct {
	store *FileStore
	now   func() time.Time
}

func NewMaker(store *FileStore) (*Maker, error) {
	if store == nil {
		return nil, fmt.Errorf("initialize verification maker: store is nil")
	}
	return &Maker{store: store, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (m *Maker) Make(ctx context.Context, request Request, artifacts []Artifact) ([]Evidence, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	if err := validateArtifacts(artifacts); err != nil {
		return nil, err
	}
	if request.CreatedAt.IsZero() {
		request.CreatedAt = m.now()
	}
	if err := m.store.CreateRequest(ctx, request); err != nil {
		return nil, fmt.Errorf("persist verification request: %w", err)
	}

	evidence := make([]Evidence, 0, len(artifacts))
	for index, artifact := range artifacts {
		digest := sha256.Sum256(artifact.Payload)
		id := fmt.Sprintf("%s-%04d", request.ID, index+1)
		item := Evidence{
			ID:        id,
			RequestID: request.ID,
			Kind:      artifact.Kind,
			Source:    artifact.Source,
			Digest:    "sha256:" + hex.EncodeToString(digest[:]),
			Size:      int64(len(artifact.Payload)),
			Locator:   id,
			CreatedAt: m.now(),
		}
		if err := m.store.CreateEvidence(ctx, item, artifact.Payload); err != nil {
			return nil, fmt.Errorf("persist verification evidence %s: %w", item.ID, err)
		}
		evidence = append(evidence, item)
	}
	return evidence, nil
}

func validateRequest(request Request) error {
	if !recordIDPattern.MatchString(request.ID) || !recordIDPattern.MatchString(request.TaskID) || strings.TrimSpace(string(request.ComputerID)) == "" {
		return ErrInvalidRequest
	}
	if len(request.Requirements) == 0 {
		return fmt.Errorf("%w: requirements are empty", ErrInvalidRequest)
	}
	seen := make(map[string]struct{}, len(request.Requirements))
	for _, requirement := range request.Requirements {
		if !recordIDPattern.MatchString(requirement.Kind) || requirement.Minimum < 1 {
			return fmt.Errorf("%w: invalid requirement", ErrInvalidRequest)
		}
		if _, exists := seen[requirement.Kind]; exists {
			return fmt.Errorf("%w: duplicate requirement %q", ErrInvalidRequest, requirement.Kind)
		}
		seen[requirement.Kind] = struct{}{}
	}
	return nil
}

func validateArtifacts(artifacts []Artifact) error {
	for _, artifact := range artifacts {
		if !recordIDPattern.MatchString(artifact.Kind) || strings.TrimSpace(artifact.Source) == "" || strings.ContainsAny(artifact.Source, "\r\n\x00") {
			return ErrInvalidEvidence
		}
	}
	return nil
}
