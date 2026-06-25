---
name: incident-triage
description: Triage incoming security or operations alerts into severity, impact scope, likely cause buckets, and immediate next checks.
license: Apache-2.0
compatibility: Crush SecOps alerting and observability toolchain.
---
# Incident Triage

## When to use this skill
Use on first alert reception to perform consistent, fast triage.

## Required tool usage
- `alert_check`
- `monitoring_query`
- `log_analyze`
- `network_diagnostic` (if network symptoms are present)

## Workflow
1. Normalize input alert: service, env, timestamp, trigger source.
2. Assign provisional severity (P1-P4) by impact and urgency.
3. Estimate blast radius: single node/service/region/global.
4. Run first-check queries and identify most likely cause buckets.
5. Output next-step checklist and escalation requirement.

## Output contract
- Severity + confidence.
- Impact scope + affected user estimate.
- Top 3 hypotheses with supporting evidence.
- Immediate actions for next 15 minutes.

## Red lines
- No offensive security actions.
- No production mutations during triage phase.
- If evidence conflicts, mark as inconclusive and escalate.
