package skills

import (
	"fmt"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
)

// NewLocalScanContract defines the compiled-in local scan skill. Unlike file
// skills, its contracts come from trusted application types, not workspace files.
// Callers must verify the real target grant before setting SignedScope.
func NewLocalScanContract(input, output *jsonschema.Schema) (*SkillManifest, error) {
	if input == nil || output == nil {
		return nil, fmt.Errorf("scan contracts are required")
	}
	in, err := input.Resolve(nil)
	if err != nil {
		return nil, fmt.Errorf("resolve scan input: %w", err)
	}
	out, err := output.Resolve(nil)
	if err != nil {
		return nil, fmt.Errorf("resolve scan output: %w", err)
	}
	return &SkillManifest{
		APIVersion: "secops/v1", Name: "local-vulnerability-scan", Version: "1.0.0",
		Description: "Authorized local Trivy scan with validated output", Roles: []string{"analyst"},
		Capabilities: ManifestCaps{Required: []string{"security:scan"}}, Risk: ManifestRisk{Base: RiskMedium},
		Runtime:        ManifestRuntime{Platforms: []string{"linux", "darwin", "windows"}, Timeout: 5 * time.Minute, OutputLimit: 16 << 20},
		Authorization:  ManifestAuthorization{Required: true, ScopeType: "local-directory"},
		inputValidator: in, outputValidator: out,
	}, nil
}
