---
name: change-gate
description: Pre-change gate for security and reliability, deciding go or no-go with explicit risk evidence and rollback readiness.
license: Apache-2.0
compatibility: Crush SecOps change management process.
---
# Change Gate

## When to use this skill
Use before production changes, especially security-sensitive changes.

## Required tool usage
- `compliance_check`
- `configuration_audit`
- `security_scan`
- `backup_check`
- `deployment_status`

## Workflow
1. Validate scope, target systems, and maintenance window.
2. Run security/compliance/config prechecks.
3. Verify backup and rollback paths.
4. Assign risk score and approval requirement.
5. Produce GO/NO-GO decision and blocking items.

## Output contract
- Gate verdict: GO, GO-with-conditions, or NO-GO.
- Blocking items and fix owner.
- Rollback readiness checklist.
- Audit references.

## Red lines
- Never bypass approvals for high-risk operations.
- No change execution in this skill; this is gate decision only.
