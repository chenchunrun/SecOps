package skills

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSkillManifestLoadsAndEscalatesParameterRisk(t *testing.T) {
	t.Parallel()
	path := writeManifestFixture(t, "")
	manifest, err := LoadManifest(path)
	require.NoError(t, err)
	require.Equal(t, RiskMedium, manifest.EffectiveRisk(nil))
	require.Equal(t, RiskCritical, manifest.EffectiveRisk(map[string]bool{"attachment_execute": true}))
}

func TestSkillManifestRejectsUnknownFieldsAndIntegrityMismatch(t *testing.T) {
	t.Parallel()
	path := writeManifestFixture(t, "unknown_field: true\n")
	_, err := LoadManifest(path)
	require.ErrorContains(t, err, "field unknown_field not found")

	path = writeManifestFixture(t, "")
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(path), SkillFileName), []byte("changed"), 0o600))
	_, err = LoadManifest(path)
	require.ErrorContains(t, err, "hash mismatch")
}

func TestSkillManifestRejectsMissingCapabilitiesAndInvalidRisk(t *testing.T) {
	t.Parallel()
	path := writeManifestFixture(t, "", func(content string) string {
		content = replaceOnce(content, "required:\n    - file:read", "required: []")
		return replaceOnce(content, "base: medium", "base: extreme")
	})
	_, err := LoadManifest(path)
	require.ErrorContains(t, err, "required capability")
	require.ErrorContains(t, err, "invalid base risk")
}

func TestCoreSecuritySkillManifestContracts(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	for _, name := range []string{
		"phishing-analysis", "auth-log-analysis", "linux-ir", "code-audit",
		"sca-analyzer", "prompt-injection-detect", "ttp-extractor", "redteam-intrusion-hunter",
	} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			content, err := exec.CommandContext(t.Context(), "git", "show", "HEAD:skills/"+name+"/SKILL.md").Output()
			require.NoError(t, err)
			manifest, err := LoadManifestWithSkillContent(filepath.Join(root, "skills", name, "manifest.yaml"), content)
			require.NoError(t, err)
			require.Equal(t, name, manifest.Name)
			require.NotEmpty(t, manifest.Capabilities.Required)
			require.NotEmpty(t, manifest.Runtime.Platforms)
		})
	}
}

func TestRedTeamSkillFailsClosedWithoutSignedScope(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	content, err := exec.CommandContext(t.Context(), "git", "show", "HEAD:skills/redteam-intrusion-hunter/SKILL.md").Output()
	require.NoError(t, err)
	manifest, err := LoadManifestWithSkillContent(filepath.Join(root, "skills", "redteam-intrusion-hunter", "manifest.yaml"), content)
	require.NoError(t, err)
	_, err = manifest.AuthorizeExecution(ExecutionRequest{Platform: runtime.GOOS})
	require.ErrorContains(t, err, "machine-verifiable")
	risk, err := manifest.AuthorizeExecution(ExecutionRequest{Platform: runtime.GOOS, SignedScope: true})
	require.NoError(t, err)
	require.Equal(t, RiskHigh, risk)
}

func TestSkillExecutionRejectsUnsupportedPlatform(t *testing.T) {
	t.Parallel()
	manifest := &SkillManifest{Name: "test", Runtime: ManifestRuntime{Platforms: []string{"linux"}}}
	_, err := manifest.AuthorizeExecution(ExecutionRequest{Platform: "plan9"})
	require.ErrorContains(t, err, "does not support")
}

func writeManifestFixture(t *testing.T, extra string, transforms ...func(string) string) string {
	t.Helper()
	root := t.TempDir()
	skill := []byte("safe skill instructions")
	require.NoError(t, os.WriteFile(filepath.Join(root, SkillFileName), skill, 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "schemas"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "schemas", "input.json"), []byte(`{"type":"object"}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "schemas", "output.json"), []byte(`{"type":"object"}`), 0o600))
	digest := sha256.Sum256(skill)
	content := `api_version: secops/v1
name: phishing-analysis
version: 1.0.0
description: Analyze suspicious email safely.
roles: [security_expert]
capabilities:
  required:
    - file:read
risk:
  base: medium
  parameter_rules:
    attachment_execute: critical
runtime:
  platforms: [darwin, linux, windows]
  network:
    required: true
    allowed_domains: []
  timeout: 5m
  output_limit: 10485760
input_schema: schemas/input.json
output_schema: schemas/output.json
integrity:
  skill_sha256: ` + hex.EncodeToString(digest[:]) + "\n" + extra
	for _, transform := range transforms {
		content = transform(content)
	}
	path := filepath.Join(root, "manifest.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func replaceOnce(value, old, replacement string) string {
	for index := 0; index+len(old) <= len(value); index++ {
		if value[index:index+len(old)] == old {
			return value[:index] + replacement + value[index+len(old):]
		}
	}
	return value
}
