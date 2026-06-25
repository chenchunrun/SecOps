---
name: remote-ops-troubleshooting
description: Execute safe remote troubleshooting with evidence-first diagnostics, minimal-change interventions, and complete operation auditability.
license: Apache-2.0
compatibility: Crush SecOps remote SSH execution profile support.
---
# Remote Ops Troubleshooting

## When to use this skill
Use when diagnosing production issues on remote hosts.

## Required tool usage
- `network_diagnostic`
- `monitoring_query`
- `log_analyze`
- `configuration_audit`
- `bash` with approved remote profile

## Workflow
1. Confirm target profile, environment, and approval level.
2. Collect read-only evidence first.
3. Perform minimal, reversible interventions only when justified.
4. Re-check health and record results.

## Output contract
- Host/service symptom summary.
- Evidence collected and key findings.
- Action taken (if any) and rollback notes.
- Next actions.

## Red lines
- No high-risk or irreversible operations without explicit approval.
- No secret exposure in outputs.
- Keep full command and decision audit trail.
