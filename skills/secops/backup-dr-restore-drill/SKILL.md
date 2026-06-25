---
name: backup-dr-restore-drill
description: Plan and evaluate backup and disaster recovery drills, including restore verification, RTO RPO validation, and remediation actions.
license: Apache-2.0
compatibility: Crush SecOps backup and infrastructure tooling.
---
# Backup and DR Restore Drill

## When to use this skill
Use for scheduled resilience drills and audit preparation.

## Required tool usage
- `backup_check`
- `database_query`
- `replication_status`
- `infrastructure_query`

## Workflow
1. Validate backup freshness and integrity signals.
2. Execute sample restore verification plan.
3. Measure RTO and RPO against targets.
4. Document failure points and improvements.

## Output contract
- Drill plan and scope.
- Restore verification results.
- RTO/RPO actual vs target.
- Corrective actions.

## Red lines
- Do not run destructive restore in production by default.
- Require explicit environment and rollback confirmation.
