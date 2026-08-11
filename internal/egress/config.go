package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrInvalidConfig = errors.New("invalid egress config")

// Config contains validated egress runtime dependencies without secret values.
type Config struct {
	Policy                *Policy
	CredentialEnvironment map[string]string
	MaxCredentialTTL      time.Duration
	AuditPath             string
}

type fileConfig struct {
	Rules                 []Rule            `json:"rules"`
	CredentialEnvironment map[string]string `json:"credential_environment"`
	MaxCredentialTTL      string            `json:"max_credential_ttl"`
	AuditPath             string            `json:"audit_path"`
}

// LoadConfig strictly decodes and validates an egress configuration file.
// Relative audit paths are resolved next to the configuration file.
func LoadConfig(path string) (*Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrInvalidConfig
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read file: %v", ErrInvalidConfig, err)
	}
	var raw fileConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: decode file: %v", ErrInvalidConfig, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing JSON value", ErrInvalidConfig)
	}
	policy, err := NewPolicy(raw.Rules)
	if err != nil {
		return nil, fmt.Errorf("%w: policy: %v", ErrInvalidConfig, err)
	}
	source, err := NewEnvironmentSource(raw.CredentialEnvironment)
	if err != nil {
		return nil, fmt.Errorf("%w: credential environment: %v", ErrInvalidConfig, err)
	}
	ttl, err := time.ParseDuration(strings.TrimSpace(raw.MaxCredentialTTL))
	if err != nil || ttl <= 0 {
		return nil, fmt.Errorf("%w: max credential ttl", ErrInvalidConfig)
	}
	auditPath := strings.TrimSpace(raw.AuditPath)
	if auditPath == "" {
		return nil, fmt.Errorf("%w: audit path", ErrInvalidConfig)
	}
	if !filepath.IsAbs(auditPath) {
		auditPath = filepath.Join(filepath.Dir(path), auditPath)
	}
	return &Config{
		Policy:                policy,
		CredentialEnvironment: source.Mapping(),
		MaxCredentialTTL:      ttl,
		AuditPath:             filepath.Clean(auditPath),
	}, nil
}

// EnvironmentSource resolves configured references from process environment
// only when a lease is issued.
type EnvironmentSource struct {
	mapping map[string]string
}

// NewEnvironmentSource validates reference-to-environment-name mappings.
func NewEnvironmentSource(mapping map[string]string) (*EnvironmentSource, error) {
	normalized := make(map[string]string, len(mapping))
	for reference, name := range mapping {
		reference = strings.TrimSpace(reference)
		name = strings.TrimSpace(name)
		if reference == "" || !environmentNamePattern.MatchString(name) {
			return nil, ErrInvalidConfig
		}
		normalized[reference] = name
	}
	return &EnvironmentSource{mapping: normalized}, nil
}

// Resolve returns a copy of the current environment value for a mapped opaque
// reference.
func (s *EnvironmentSource) Resolve(ctx context.Context, reference string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("resolve environment credential: %w", err)
	}
	name, exists := s.mapping[strings.TrimSpace(reference)]
	if !exists {
		return nil, ErrCredentialUnavailable
	}
	value, exists := os.LookupEnv(name)
	if !exists || value == "" {
		return nil, ErrCredentialUnavailable
	}
	return []byte(value), nil
}

// Mapping returns a defensive copy containing names but no secret values.
func (s *EnvironmentSource) Mapping() map[string]string {
	mapping := make(map[string]string, len(s.mapping))
	for reference, name := range s.mapping {
		mapping[reference] = name
	}
	return mapping
}
