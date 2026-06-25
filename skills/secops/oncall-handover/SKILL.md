---
name: oncall-handover
description: Generate a shift handover summary with active incidents, unresolved risks, key changes, and next actions using auditable evidence.
license: Apache-2.0
compatibility: Crush SecOps with audit log access and built-in SecOps tools.
---
# On-Call Handover

## When to use this skill
Use this skill at shift end/start to create a standardized handover package.

## Scope and boundaries
- This skill orchestrates workflow only.
- It does not replace built-in tools.
- Use built-in tools to collect evidence, then synthesize handover content.

## Required tool usage
- `alert_check`: fetch open/firing alerts.
- `incident_timeline`: summarize major events per incident.
- `deployment_status` and `monitoring_query`: confirm service posture.
- `audit`/event records: include approvals and denied operations.

## Workflow
1. Collect active alerts and unresolved incidents.
2. Extract top risks: customer impact, data/security risk, and blast radius.
3. Summarize recent changes and post-change health.
4. List unfinished actions with owner, deadline, and rollback readiness.
5. Output: Executive summary + detailed action table.

## Output contract
- Section 1: Shift summary (3-6 bullets).
- Section 2: Open incidents and severity.
- Section 3: Key changes and health checks.
- Section 4: Pending actions (Owner/ETA/Risk).
- Section 5: Evidence references (tool output IDs/paths).

## Red lines
- Defensive operations only.
- No destructive commands without explicit approval.
- Never hide uncertainty; clearly label assumptions and data gaps.
- Do not fabricate closure status or SLA results.
