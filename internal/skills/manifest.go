package skills

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type SkillManifest struct {
	APIVersion    string                `yaml:"api_version"`
	Name          string                `yaml:"name"`
	Version       string                `yaml:"version"`
	Description   string                `yaml:"description"`
	Roles         []string              `yaml:"roles"`
	Capabilities  ManifestCaps          `yaml:"capabilities"`
	Risk          ManifestRisk          `yaml:"risk"`
	Runtime       ManifestRuntime       `yaml:"runtime"`
	InputSchema   string                `yaml:"input_schema"`
	OutputSchema  string                `yaml:"output_schema"`
	Integrity     ManifestIntegrity     `yaml:"integrity"`
	Authorization ManifestAuthorization `yaml:"authorization,omitempty"`
}

type ManifestCaps struct {
	Required []string `yaml:"required"`
}

type ManifestRisk struct {
	Base           RiskLevel            `yaml:"base"`
	ParameterRules map[string]RiskLevel `yaml:"parameter_rules"`
}

type ManifestRuntime struct {
	Platforms   []string        `yaml:"platforms"`
	Network     ManifestNetwork `yaml:"network"`
	Timeout     time.Duration   `yaml:"-"`
	TimeoutRaw  string          `yaml:"timeout"`
	OutputLimit int64           `yaml:"output_limit"`
}

type ManifestNetwork struct {
	Required       bool     `yaml:"required"`
	AllowedDomains []string `yaml:"allowed_domains"`
}

type ManifestIntegrity struct {
	SkillSHA256 string `yaml:"skill_sha256"`
}

type ManifestAuthorization struct {
	Required  bool   `yaml:"required"`
	ScopeType string `yaml:"scope_type"`
}

type ExecutionRequest struct {
	Platform         string
	ActiveParameters map[string]bool
	SignedScope      bool
}

func LoadManifest(path string) (*SkillManifest, error) {
	return loadManifest(path, nil)
}

func LoadManifestWithSkillContent(path string, skillContent []byte) (*SkillManifest, error) {
	return loadManifest(path, append([]byte(nil), skillContent...))
}

func loadManifest(path string, skillContent []byte) (*SkillManifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open skill manifest: %w", err)
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var manifest SkillManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode skill manifest: %w", err)
	}
	if err := manifest.validate(filepath.Dir(path), skillContent); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func (m *SkillManifest) EffectiveRisk(activeParameters map[string]bool) RiskLevel {
	risk := m.Risk.Base
	for parameter, active := range activeParameters {
		if active && riskRank(m.Risk.ParameterRules[parameter]) > riskRank(risk) {
			risk = m.Risk.ParameterRules[parameter]
		}
	}
	return risk
}

func (m *SkillManifest) SupportsCurrentPlatform() bool {
	return m.SupportsPlatform(runtime.GOOS)
}

func (m *SkillManifest) SupportsPlatform(platform string) bool {
	for _, supported := range m.Runtime.Platforms {
		if supported == platform {
			return true
		}
	}
	return false
}

func (m *SkillManifest) AuthorizeExecution(request ExecutionRequest) (RiskLevel, error) {
	if !m.SupportsPlatform(request.Platform) {
		return "", fmt.Errorf("skill %s does not support platform %s", m.Name, request.Platform)
	}
	if m.Authorization.Required && !request.SignedScope {
		return "", fmt.Errorf("skill %s requires machine-verifiable %s authorization", m.Name, m.Authorization.ScopeType)
	}
	return m.EffectiveRisk(request.ActiveParameters), nil
}

func (m *SkillManifest) validate(root string, skillContent []byte) error {
	var errs []error
	if m.APIVersion != "secops/v1" {
		errs = append(errs, errors.New("api_version must be secops/v1"))
	}
	if !namePattern.MatchString(m.Name) || strings.TrimSpace(m.Version) == "" || strings.TrimSpace(m.Description) == "" || len(m.Roles) == 0 {
		errs = append(errs, errors.New("name, version, description, and roles are required"))
	}
	if len(m.Capabilities.Required) == 0 {
		errs = append(errs, errors.New("at least one required capability is required"))
	}
	if !validRisk(m.Risk.Base) {
		errs = append(errs, errors.New("invalid base risk"))
	}
	for parameter, risk := range m.Risk.ParameterRules {
		if !namePattern.MatchString(strings.ReplaceAll(parameter, "_", "-")) || !validRisk(risk) {
			errs = append(errs, fmt.Errorf("invalid parameter risk rule %q", parameter))
		}
	}
	for _, platform := range m.Runtime.Platforms {
		if platform != "darwin" && platform != "linux" && platform != "windows" {
			errs = append(errs, fmt.Errorf("unsupported platform %q", platform))
		}
	}
	timeout, err := time.ParseDuration(m.Runtime.TimeoutRaw)
	if err != nil || timeout <= 0 {
		errs = append(errs, errors.New("runtime timeout must be a positive duration"))
	} else {
		m.Runtime.Timeout = timeout
	}
	if m.Runtime.OutputLimit <= 0 {
		errs = append(errs, errors.New("runtime output_limit must be positive"))
	}
	if m.Authorization.Required && strings.TrimSpace(m.Authorization.ScopeType) == "" {
		errs = append(errs, errors.New("required authorization must declare scope_type"))
	}
	for _, schema := range []string{m.InputSchema, m.OutputSchema} {
		if err := validateRelativeFile(root, schema); err != nil {
			errs = append(errs, err)
		}
	}
	skill := skillContent
	if skill == nil {
		var err error
		skill, err = os.ReadFile(filepath.Join(root, SkillFileName))
		if err != nil {
			errs = append(errs, fmt.Errorf("read skill content for integrity: %w", err))
		}
	}
	if skill != nil {
		digest := sha256.Sum256(skill)
		actual := hex.EncodeToString(digest[:])
		if !strings.EqualFold(m.Integrity.SkillSHA256, actual) {
			errs = append(errs, errors.New("skill content hash mismatch"))
		}
	}
	return errors.Join(errs...)
}

func validateRelativeFile(root, value string) error {
	if value == "" || filepath.IsAbs(value) {
		return fmt.Errorf("invalid schema path %q", value)
	}
	trustedRoot, err := filepath.Abs(filepath.Dir(root))
	if err != nil {
		return fmt.Errorf("resolve trusted skill root: %w", err)
	}
	target, err := filepath.Abs(filepath.Join(root, value))
	if err != nil || (target != trustedRoot && !strings.HasPrefix(target, trustedRoot+string(os.PathSeparator))) {
		return fmt.Errorf("invalid schema path %q", value)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("read schema %q: %w", value, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return fmt.Errorf("schema %q is empty", value)
	}
	return nil
}

func validRisk(risk RiskLevel) bool {
	return risk == RiskLow || risk == RiskMedium || risk == RiskHigh || risk == RiskCritical
}

func riskRank(risk RiskLevel) int {
	switch risk {
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	case RiskCritical:
		return 4
	default:
		return 0
	}
}
