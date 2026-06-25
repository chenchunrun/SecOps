---
name: weekly-secops-report
description: Produce a weekly SecOps report with incident trend, risk posture, remediation progress, and key operational metrics for leadership.
license: Apache-2.0
compatibility: Crush SecOps audit, alert, and monitoring data.
---
# Weekly SecOps Report

## When to use this skill
Use for weekly leadership reporting and team review.

## Required tool usage
- `alert_check`
- `incident_timeline`
- `security_scan`
- `compliance_check`
- `audit` and `siem_export`

## Workflow
1. Aggregate week-level incident and alert metrics.
2. Summarize top risks and unresolved items.
3. Track remediation throughput and SLA adherence.
4. Provide next-week priorities and blockers.

## Output contract
- Executive summary.
- KPI section (trend and deltas).
- Top risks and mitigation status.
- Priority action list.

## Red lines
- No metric manipulation.
- Highlight data completeness and confidence.
