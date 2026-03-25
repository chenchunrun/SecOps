package prompt

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readTemplateFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "templates", name))
	require.NoError(t, err)
	return string(data)
}

func testConfigStore(t *testing.T) *config.ConfigStore {
	t.Helper()
	store, err := config.Init(t.TempDir(), t.TempDir(), false)
	if err != nil {
		t.Skipf("skipping test that requires config store: %v", err)
		return nil
	}
	return store
}

func TestOpsAgentPromptRender(t *testing.T) {
	tpl := readTemplateFile(t, "ops_agent.md.tpl")
	require.NotEmpty(t, tpl)

	// Verify key template variables are used
	assert.Contains(t, tpl, "{{.Model}}")
	assert.Contains(t, tpl, "{{.WorkingDir}}")
	assert.Contains(t, tpl, "{{.Platform}}")
	assert.Contains(t, tpl, "{{.Date}}")
	assert.Contains(t, tpl, "{{.TraceID}}")
	// Verify context files section uses template conditional syntax
	assert.Contains(t, tpl, "{{if .ContextFiles}}")

	// Verify role definition is present
	assert.Contains(t, tpl, "OpsAgent")
	assert.Contains(t, tpl, "operations automation agent")

	// Verify permission levels are defined
	assert.Contains(t, tpl, "Viewer")
	assert.Contains(t, tpl, "Operator")
	assert.Contains(t, tpl, "Admin")

	// Verify execution principles
	assert.Contains(t, tpl, "Read-First Policy")
	assert.Contains(t, tpl, "Never Modify Production Without Approval")
	assert.Contains(t, tpl, "Rollback")

	// Verify security principles
	assert.Contains(t, tpl, "No Hardcoded Credentials")
	assert.Contains(t, tpl, "No Unverified Scripts")

	// Verify available operations sections
	assert.Contains(t, tpl, "Log Analysis")
	assert.Contains(t, tpl, "Monitoring")
	assert.Contains(t, tpl, "Diagnostics")
	assert.Contains(t, tpl, "Security Scanning")
	assert.Contains(t, tpl, "Compliance")
	assert.Contains(t, tpl, "Incident Response")

	// Verify prohibited operations
	assert.Contains(t, tpl, "Prohibited Operations")
	assert.Contains(t, tpl, "rm -rf /")

	// Verify output format requirements
	assert.Contains(t, tpl, "Risk Assessment")
	assert.Contains(t, tpl, "Approval Level")
	assert.Contains(t, tpl, "Rollback Steps")

	// Verify example scenario
	assert.Contains(t, tpl, "Example Scenario")
	assert.Contains(t, tpl, "High CPU Usage")

	// Verify change workflow
	assert.Contains(t, tpl, "Change Workflow")
	assert.Contains(t, tpl, "Analyze")
	assert.Contains(t, tpl, "Plan")
	assert.Contains(t, tpl, "Review")
	assert.Contains(t, tpl, "Approve")
	assert.Contains(t, tpl, "Execute")
	assert.Contains(t, tpl, "Verify")

	// Verify template ends with separator
	assert.True(t, strings.HasSuffix(strings.TrimSpace(tpl), "---"))
}

func TestSecurityExpertAgentPromptRender(t *testing.T) {
	tpl := readTemplateFile(t, "security_expert_agent.md.tpl")
	require.NotEmpty(t, tpl)

	// Verify key template variables are used
	assert.Contains(t, tpl, "{{.Model}}")
	assert.Contains(t, tpl, "{{.WorkingDir}}")
	assert.Contains(t, tpl, "{{.Platform}}")
	assert.Contains(t, tpl, "{{.Date}}")
	assert.Contains(t, tpl, "{{.TraceID}}")
	// Verify context files section uses template conditional syntax
	assert.Contains(t, tpl, "{{if .ContextFiles}}")

	// Verify role definition
	assert.Contains(t, tpl, "SecurityExpertAgent")
	assert.Contains(t, tpl, "security expert agent")

	// Verify specialization areas
	assert.Contains(t, tpl, "Vulnerability Management")
	assert.Contains(t, tpl, "Penetration Testing")
	assert.Contains(t, tpl, "Incident Response")
	assert.Contains(t, tpl, "Compliance Auditing")
	assert.Contains(t, tpl, "Threat Intelligence")

	// Verify permission levels
	assert.Contains(t, tpl, "Viewer")
	assert.Contains(t, tpl, "Operator")
	assert.Contains(t, tpl, "Admin")

	// Verify workflow stages
	assert.Contains(t, tpl, "SCAN")
	assert.Contains(t, tpl, "CLASSIFY")
	assert.Contains(t, tpl, "VERIFY")
	assert.Contains(t, tpl, "REPORT")
	assert.Contains(t, tpl, "TRACK")

	// Verify data handling rules
	assert.Contains(t, tpl, "Encrypted Storage")
	assert.Contains(t, tpl, "Audit Trail")
	assert.Contains(t, tpl, "Chain of Custody")

	// Verify defensive-only boundary
	assert.Contains(t, tpl, "Defensive Operations Only")
	assert.Contains(t, tpl, "refuse")

	// Verify prohibited operations
	assert.Contains(t, tpl, "Prohibited Operations")

	// Verify incident classification table
	assert.Contains(t, tpl, "Incident Severity Classification")
	assert.Contains(t, tpl, "CRITICAL")
	assert.Contains(t, tpl, "HIGH")
	assert.Contains(t, tpl, "MEDIUM")
	assert.Contains(t, tpl, "LOW")

	// Verify output format requirements
	assert.Contains(t, tpl, "Severity")
	assert.Contains(t, tpl, "Evidence")
	assert.Contains(t, tpl, "Remediation")
	assert.Contains(t, tpl, "MITRE ATT&CK")

	// Verify template ends with separator
	assert.True(t, strings.HasSuffix(strings.TrimSpace(tpl), "---"))
}

func TestOpsAgentPromptBuild(t *testing.T) {
	tpl := readTemplateFile(t, "ops_agent.md.tpl")

	cfg := testConfigStore(t)

	prompt, err := NewPrompt("ops_agent", tpl)
	require.NoError(t, err)

	ctx := context.Background()
	output, err := prompt.Build(ctx, "anthropic", "claude-opus-4", cfg)
	require.NoError(t, err)

	// Verify template was executed with actual values
	assert.NotEmpty(t, output)
	assert.NotContains(t, output, "{{.Model}}")
	assert.NotContains(t, output, "{{.WorkingDir}}")
	assert.NotContains(t, output, "{{.TraceID}}")

	// Verify actual values were injected
	assert.Contains(t, output, "claude-opus-4")

	// Verify content sections are present
	assert.Contains(t, output, "OpsAgent")
	assert.Contains(t, output, "Viewer")
	assert.Contains(t, output, "Log Analysis")
	assert.Contains(t, output, "---")
}

func TestSecurityExpertAgentPromptBuild(t *testing.T) {
	tpl := readTemplateFile(t, "security_expert_agent.md.tpl")

	cfg := testConfigStore(t)

	prompt, err := NewPrompt("security_expert_agent", tpl)
	require.NoError(t, err)

	ctx := context.Background()
	output, err := prompt.Build(ctx, "anthropic", "claude-sonnet-4", cfg)
	require.NoError(t, err)

	assert.NotEmpty(t, output)
	assert.NotContains(t, output, "{{.ModelName}}")
	assert.NotContains(t, output, "{{.TraceID}}")

	// Verify content sections
	assert.Contains(t, output, "SecurityExpertAgent")
	assert.Contains(t, output, "Vulnerability Management")
	assert.Contains(t, output, "Threat Intelligence")
	assert.Contains(t, output, "---")
}

func TestOpsAgentPromptContextFiles(t *testing.T) {
	tpl := readTemplateFile(t, "ops_agent.md.tpl")

	cfg := testConfigStore(t)

	prompt, err := NewPrompt("ops_agent", tpl)
	require.NoError(t, err)

	ctx := context.Background()
	output, err := prompt.Build(ctx, "anthropic", "test-model", cfg)
	require.NoError(t, err)

	// ContextFiles section should be present but empty when no context files
	assert.Contains(t, output, "<context>")
}

func TestOpsAgentPromptHasCapabilityList(t *testing.T) {
	tpl := readTemplateFile(t, "ops_agent.md.tpl")

	// Verify key capabilities are documented
	assert.Contains(t, tpl, "Log Analysis")
	assert.Contains(t, tpl, "Monitoring")
	assert.Contains(t, tpl, "Diagnostics")
	assert.Contains(t, tpl, "Security Scanning")
	assert.Contains(t, tpl, "Compliance")
	assert.Contains(t, tpl, "Incident Response")

	// Verify sub-capabilities
	assert.Contains(t, tpl, "Prometheus")
	assert.Contains(t, tpl, "Grafana")
	assert.Contains(t, tpl, "Datadog")
	assert.Contains(t, tpl, "Trivy")
	assert.Contains(t, tpl, "Grype")
	assert.Contains(t, tpl, "Nuclei")
	assert.Contains(t, tpl, "ClamAV")
}

func TestSecurityExpertAgentPromptComplianceFrameworks(t *testing.T) {
	tpl := readTemplateFile(t, "security_expert_agent.md.tpl")

	// Verify compliance frameworks are documented
	assert.Contains(t, tpl, "CIS")
	assert.Contains(t, tpl, "PCI-DSS")
	assert.Contains(t, tpl, "SOC2")
	assert.Contains(t, tpl, "HIPAA")
	assert.Contains(t, tpl, "ISO 27001")
	assert.Contains(t, tpl, "GDPR")
}

func TestSecurityExpertAgentPromptMITREMapping(t *testing.T) {
	tpl := readTemplateFile(t, "security_expert_agent.md.tpl")

	assert.Contains(t, tpl, "MITRE ATT&CK")
}

func TestOpsAgentPromptProhibitedCommands(t *testing.T) {
	tpl := readTemplateFile(t, "ops_agent.md.tpl")

	// Verify specific prohibited commands are listed
	assert.Contains(t, tpl, "rm -rf /")
}

func TestOpsAgentPromptRoleBoundary(t *testing.T) {
	tpl := readTemplateFile(t, "ops_agent.md.tpl")

	assert.Contains(t, tpl, "Do not self-identify as a security expert")
	assert.Contains(t, tpl, "hand off to SecurityExpertAgent")
	assert.Contains(t, tpl, "Role Boundary")
}

func TestSecurityExpertAgentPromptDataClassification(t *testing.T) {
	tpl := readTemplateFile(t, "security_expert_agent.md.tpl")

	// Verify data classification levels
	assert.Contains(t, tpl, "PUBLIC")
	assert.Contains(t, tpl, "INTERNAL")
	assert.Contains(t, tpl, "CONFIDENTIAL")
	assert.Contains(t, tpl, "RESTRICTED")
}

func TestBothPromptsEndWithSeparator(t *testing.T) {
	tpls := []string{"ops_agent.md.tpl", "security_expert_agent.md.tpl"}

	for _, name := range tpls {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "templates", name))
			require.NoError(t, err)
			content := strings.TrimSpace(string(data))
			assert.True(t, strings.HasSuffix(content, "---"),
				"template %s should end with ---", name)
		})
	}
}

func TestBothPromptsHaveEnvSection(t *testing.T) {
	tpls := []string{"ops_agent.md.tpl", "security_expert_agent.md.tpl"}
	envVars := []string{"{{.WorkingDir}}", "{{.Platform}}", "{{.Date}}", "{{.Model}}", "{{.TraceID}}", "{{if .ContextFiles}}"}

	for _, name := range tpls {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "templates", name))
			require.NoError(t, err)
			content := string(data)
			for _, v := range envVars {
				assert.Contains(t, content, v, "template %s should contain %s", name, v)
			}
		})
	}
}
