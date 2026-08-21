// Package connectors implements versioned security-platform connector contracts.
package connectors

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Manifest struct {
	APIVersion  string                `yaml:"api_version"`
	Name        string                `yaml:"name"`
	Version     string                `yaml:"version"`
	Provider    string                `yaml:"provider"`
	DataScopes  []string              `yaml:"data_scopes"`
	Credential  CredentialRequirement `yaml:"credential"`
	ProviderAPI string                `yaml:"provider_api_version"`
	RateLimit   RateLimitPolicy       `yaml:"rate_limit"`
	HealthPath  string                `yaml:"health_path"`
	EventSchema string                `yaml:"event_schema"`
	Operations  []OperationDescriptor `yaml:"operations"`
}

type CredentialRequirement struct {
	Type       string   `yaml:"type"`
	Scopes     []string `yaml:"scopes"`
	ShortLived bool     `yaml:"short_lived"`
}

type RateLimitPolicy struct {
	MaxRetries int           `yaml:"max_retries"`
	BackoffRaw string        `yaml:"backoff"`
	Backoff    time.Duration `yaml:"-"`
}

type OperationDescriptor struct {
	Name       string `yaml:"name"`
	Method     string `yaml:"method"`
	Path       string `yaml:"path"`
	SideEffect bool   `yaml:"side_effect"`
	Risk       string `yaml:"risk"`
}

func LoadManifest(path string) (*Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open connector manifest: %w", err)
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode connector manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func (m *Manifest) Validate() error {
	var errs []error
	if m.APIVersion != "secops/connectors/v1" || m.Name == "" || m.Version == "" || m.Provider == "" || m.ProviderAPI == "" {
		errs = append(errs, errors.New("connector identity and API versions are required"))
	}
	if len(m.DataScopes) == 0 || m.Credential.Type == "" || len(m.Credential.Scopes) == 0 || !m.Credential.ShortLived {
		errs = append(errs, errors.New("connector requires data scopes and short-lived credential scopes"))
	}
	backoff, err := time.ParseDuration(m.RateLimit.BackoffRaw)
	if err != nil || backoff <= 0 || m.RateLimit.MaxRetries < 0 {
		errs = append(errs, errors.New("connector retry policy is invalid"))
	} else {
		m.RateLimit.Backoff = backoff
	}
	if !strings.HasPrefix(m.HealthPath, "/") || m.EventSchema == "" || len(m.Operations) == 0 {
		errs = append(errs, errors.New("connector health, event schema, and operations are required"))
	}
	seen := make(map[string]bool, len(m.Operations))
	for _, operation := range m.Operations {
		if operation.Name == "" || seen[operation.Name] || !strings.HasPrefix(operation.Path, "/") || !validMethod(operation.Method) || !validRisk(operation.Risk) {
			errs = append(errs, fmt.Errorf("invalid connector operation %q", operation.Name))
		}
		if operation.SideEffect && operation.Method == "GET" {
			errs = append(errs, fmt.Errorf("side-effect operation %q cannot use GET", operation.Name))
		}
		seen[operation.Name] = true
	}
	return errors.Join(errs...)
}

func (m Manifest) Operation(name string) (OperationDescriptor, bool) {
	for _, operation := range m.Operations {
		if operation.Name == name {
			return operation, true
		}
	}
	return OperationDescriptor{}, false
}

func validMethod(method string) bool {
	return method == "GET" || method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE"
}

func validRisk(risk string) bool {
	return risk == "low" || risk == "medium" || risk == "high" || risk == "critical"
}
