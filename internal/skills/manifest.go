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
	APIVersion   string            `yaml:"api_version"`
	Name         string            `yaml:"name"`
	Version      string            `yaml:"version"`
	Description  string            `yaml:"description"`
	Roles        []string          `yaml:"roles"`
	Capabilities ManifestCaps      `yaml:"capabilities"`
	Risk         ManifestRisk      `yaml:"risk"`
	Runtime      ManifestRuntime   `yaml:"runtime"`
	InputSchema  string            `yaml:"input_schema"`
	OutputSchema string            `yaml:"output_schema"`
	Integrity    ManifestIntegrity `yaml:"integrity"`
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

func LoadManifest(path string) (*SkillManifest, error) {
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
	if err := manifest.validate(filepath.Dir(path)); err != nil {
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
	for _, platform := range m.Runtime.Platforms {
		if platform == runtime.GOOS {
			return true
		}
	}
	return false
}

func (m *SkillManifest) validate(root string) error {
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
	for _, schema := range []string{m.InputSchema, m.OutputSchema} {
		if err := validateRelativeFile(root, schema); err != nil {
			errs = append(errs, err)
		}
	}
	skillPath := filepath.Join(root, SkillFileName)
	skill, err := os.ReadFile(skillPath)
	if err != nil {
		errs = append(errs, fmt.Errorf("read skill content for integrity: %w", err))
	} else {
		digest := sha256.Sum256(skill)
		actual := hex.EncodeToString(digest[:])
		if !strings.EqualFold(m.Integrity.SkillSHA256, actual) {
			errs = append(errs, errors.New("skill content hash mismatch"))
		}
	}
	return errors.Join(errs...)
}

func validateRelativeFile(root, value string) error {
	if value == "" || filepath.IsAbs(value) || strings.HasPrefix(filepath.Clean(value), "..") {
		return fmt.Errorf("invalid schema path %q", value)
	}
	data, err := os.ReadFile(filepath.Join(root, value))
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
