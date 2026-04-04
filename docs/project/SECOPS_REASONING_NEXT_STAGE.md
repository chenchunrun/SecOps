# SecOps Reasoning Next Stage

## Current Status

The newly added SecOps reasoning workflow has passed targeted validation for:

- ATT&CK reasoning tools: `attack_reason`, `incident_assess`
- `SecurityExpertAgent` runtime workflow selection
- TUI rendering for SecOps reasoning tool output
- End-to-end security incident integration
- Demo chain execution:
  `incident_assess -> attack_reason -> SecurityExpertAgent -> TUI renderer`

## What Is Already Complete

- ATT&CK knowledge, mapping, and ranking logic exists under
  `internal/security/attack/`
- `incident_assess` is the default multi-source investigation entry point
- `attack_reason` is the deeper ATT&CK follow-up step
- Security agent prompt and runtime behavior both prefer the new workflow
- TUI chat messages now render structured summaries for these tools
- Demo and release-note materials exist for verification and handoff

## Next Stage Goal

Move from "validated reasoning workflow" to "release-ready operator workflow".

That means the next stage should focus on making the feature easier to operate,
easier to verify, and easier to explain externally.

## Recommended Next Stage Work

### 1. Operator-facing guidance

- Add a short user-facing runbook for when to use `incident_assess`
- Document typical evidence inputs:
  `alert_check`, `log_analyze`, `incident_timeline`, `access_review`
- Add example investigation prompts for Security mode

### 2. Broader regression coverage

- Add one or two higher-value integration cases for:
  - suspicious login / valid account abuse
  - secret exposure / credential misuse
- Add a release gate that includes the reasoning demo in non-sandbox runs

### 3. Full ATT&CK data expansion

- Expand beyond the current high-value technique subset
- Add more platform- and scenario-specific mappings
- Improve candidate ranking coverage for lateral movement, defense evasion,
  and exfiltration paths

### 4. Reporting and export

- Reuse the structured workflow summary in release reports or investigation
  exports
- Add a consistent markdown or JSON export format for investigation results

## Suggested Success Criteria

The next stage can be considered complete when:

1. An operator can run the workflow from existing SecOps inputs without
   reading source code.
2. At least two realistic investigation scenarios are covered by integration
   tests.
3. The reasoning demo is part of the normal validation story.
4. Investigation output is documented in a form suitable for handoff or audit.

## Recommended Command Set

```bash
GOCACHE=$(pwd)/.gocache bash ./scripts/demo_secops_reasoning.sh
GOCACHE=$(pwd)/.gocache go test ./internal/agent/tools/secops ./internal/agent ./internal/ui/chat ./internal/integration -count=1
```

## Bottom Line

The new reasoning workflow is no longer experimental code. The next stage is
about operationalization, broader scenario coverage, and release-facing
documentation.
