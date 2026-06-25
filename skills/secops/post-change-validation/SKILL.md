---
name: post-change-validation
description: Validate service and security health after a change, detect regressions quickly, and trigger rollback recommendation when thresholds fail.
license: Apache-2.0
compatibility: Crush SecOps deployment and observability stack.
---
# Post-Change Validation

## When to use this skill
Use immediately after deployment or configuration changes.

## Required tool usage
- `deployment_status`
- `monitoring_query`
- `log_analyze`
- `alert_check`

## Workflow
1. Compare pre/post baseline for SLI indicators.
2. Check error, latency, saturation, and alert deltas.
3. Inspect logs for new anomaly classes.
4. Decide pass, watch, or rollback recommendation.

## Output contract
- Validation status with confidence.
- Metric and alert delta summary.
- Rollback recommendation criteria.
- Follow-up watch window and owner.

## Red lines
- No silent acceptance if key thresholds fail.
- Any rollback recommendation must include clear evidence.
