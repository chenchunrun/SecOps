---
name: incident-commander
description: Run a structured incident command flow covering timeline, role assignment, communication cadence, and decision checkpoints.
license: Apache-2.0
compatibility: Crush SecOps incident response workflow.
---
# Incident Commander

## When to use this skill
Use for P1/P2 incidents requiring cross-team coordination.

## Required tool usage
- `incident_timeline`
- `alert_check`
- `deployment_status`
- `log_analyze`
- `monitoring_query`

## Workflow
1. Start incident record with owner and severity.
2. Build timeline from alerts, changes, and key operator actions.
3. Set role tracks: lead, comms, investigation, remediation.
4. Define 15-minute cadence updates and decision gates.
5. Track decisions with rationale and evidence pointers.

## Output contract
- Current status and impact statement.
- Timeline table.
- Decision log with owner and ETA.
- External/internal communication summary.

## Red lines
- No unapproved high-risk changes.
- No irreversible actions without rollback plan.
- Keep audit trail complete and timestamped.
