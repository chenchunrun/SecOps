# SecOps Reasoning Test Report

Date: 2026-03-29

## Scope

This report covers the newly added MITRE ATT&CK-guided reasoning workflow used
by the merged SecOps runtime:

`incident_assess -> attack_reason -> SecurityExpertAgent -> TUI renderer`

## Components Covered

- ATT&CK knowledge and ranking logic under `internal/security/attack/`
- SecOps tools:
  - `attack_reason`
  - `incident_assess`
- `SecurityExpertAgent` prompt and runtime workflow selection
- Structured security response rendering
- TUI tool rendering for reasoning workflow output
- Security incident integration path

## Commands Executed

### 1. Reasoning tools

```bash
env GOCACHE=/Users/newmba/SecOpsCode/crush-main/.gocache \
go test ./internal/agent/tools/secops \
  -run 'TestAttackReasonTool|TestIncidentAssessTool' -count=1
```

Result: PASS

### 2. Security agent runtime workflow

```bash
env GOCACHE=/Users/newmba/SecOpsCode/crush-main/.gocache \
go test ./internal/agent \
  -run 'TestSecurityExpertAgent_ProcessTask_ThreatAssessment|TestSecurityExpertAgent_ProcessTask_IncidentResponse|TestSecurityExpertAgent_selectSecurityWorkflow_MetadataEvidence|TestAgentResponse_RenderWorkflowSummary|TestAgentResponse_RenderSecurityAssessment' \
  -count=1
```

Result: PASS

### 3. Prompt validation

```bash
env GOCACHE=/Users/newmba/SecOpsCode/crush-main/.gocache \
go test ./internal/agent/prompt \
  -run 'TestSecurityExpertAgentPromptMITREMapping|TestSecurityExpertAgentPromptBuild|TestSecurityExpertAgentPromptRender' \
  -count=1
```

Result: PASS

### 4. TUI SecOps renderer

```bash
env GOCACHE=/Users/newmba/SecOpsCode/crush-main/.gocache \
go test ./internal/ui/chat \
  -run 'TestSummarizeIncidentAssessResult|TestSummarizeAttackReasonResult|TestNewToolMessageItem_UsesSecOpsRenderer|TestExtractMessageItems_SecOpsToolSessionFlow' \
  -count=1
```

Result: PASS

### 5. End-to-end integration

```bash
env GOCACHE=/Users/newmba/SecOpsCode/crush-main/.gocache \
go test ./internal/integration \
  -run 'TestSecuritySystemIntegration_IncidentResponse' \
  -count=1
```

Result: PASS

### 6. Demo chain

```bash
env GOCACHE=/Users/newmba/SecOpsCode/crush-main/.gocache \
bash ./scripts/demo_secops_reasoning.sh
```

Result: PASS

Verified stages:

1. `internal/agent/tools/secops`
2. `internal/agent`
3. `internal/ui/chat`
4. `internal/integration`

## Key Assertions Verified

### ATT&CK reasoning

- `attack_reason` converts normalized evidence into ATT&CK technique rankings
- `incident_assess` produces a consolidated investigation summary
- `incident_assess` uses `attack_reason` as the deeper follow-up step

### Runtime workflow

- `SecurityExpertAgent` prefers `incident_assess` for:
  - `threat_assessment`
  - `incident_response`
  - metadata indicating multi-source evidence
- `attack_reason` remains the follow-up tool for deeper technique ranking

### Output contract

- Security agent responses now include:
  - `workflow_summary`
  - rendered workflow text
  - rendered security assessment text

### TUI behavior

- `incident_assess` and `attack_reason` no longer fall back to generic JSON
- TUI tool cards show structured summaries such as:
  - executive summary / assessment
  - top technique
  - tactics
  - evidence summary
  - containment or next actions
- Session-level message flow correctly links assistant tool calls to tool results

## Files Most Relevant To Validation

- `/Users/newmba/SecOpsCode/crush-main/internal/security/attack/`
- `/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/secops/attack_reason.go`
- `/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/secops/incident_assess.go`
- `/Users/newmba/SecOpsCode/crush-main/internal/agent/secops_ops_agent.go`
- `/Users/newmba/SecOpsCode/crush-main/internal/agent/templates/security_expert_agent.md.tpl`
- `/Users/newmba/SecOpsCode/crush-main/internal/ui/chat/secops.go`
- `/Users/newmba/SecOpsCode/crush-main/scripts/demo_secops_reasoning.sh`

## Risks And Gaps

- Coverage is strong for the implemented workflow, but still scenario-limited.
- Current ATT&CK coverage is a high-value subset, not the full matrix.
- Build reproducibility still depends on module proxy reachability if caches are cold.
- The CLI help banner still uses the upstream `crush` naming even when running the
  built `SecOps` binary.

## Conclusion

The MITRE ATT&CK-based reasoning workflow is functionally integrated and
validated across tool logic, agent workflow selection, structured output,
TUI rendering, and incident-response integration.

This feature can be treated as implemented and test-passing for the current
scope. The next stage is broader scenario coverage and release-facing
operational documentation.
