---
name: rca-report
description: Produce a rigorous root-cause analysis report with evidence chain, contributing factors, remediation, and prevention actions.
license: Apache-2.0
compatibility: Crush SecOps incident and audit data.
---
# RCA Report

## When to use this skill
Use after incident containment for formal postmortem.

## Required tool usage
- `incident_timeline`
- `log_analyze`
- `monitoring_query`
- `configuration_audit`
- `audit` records

## Workflow
1. Build factual timeline and impact quantification.
2. Separate root cause from contributing factors.
3. Validate each claim with evidence references.
4. Define corrective and preventive actions (CAPA).
5. Produce executive and technical versions.

## Output contract
- What happened.
- Why it happened (root + contributing factors).
- Why detection/response succeeded or failed.
- CAPA list with owner and due date.

## Red lines
- No blame language.
- No unsupported conclusions.
- Clearly mark unknowns and pending verification.
