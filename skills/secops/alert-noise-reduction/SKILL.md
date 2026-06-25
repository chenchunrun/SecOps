---
name: alert-noise-reduction
description: Identify noisy or redundant alerts and propose safe suppression, deduplication, and threshold tuning with validation criteria.
license: Apache-2.0
compatibility: Crush SecOps alerting and monitoring stack.
---
# Alert Noise Reduction

## When to use this skill
Use when alert fatigue is high or repeated non-actionable alerts occur.

## Required tool usage
- `alert_check`
- `monitoring_query`
- `incident_timeline`
- `log_analyze`

## Workflow
1. Find top noisy rules by frequency and low actionability.
2. Group duplicates and flapping patterns.
3. Propose tuning: threshold, window, dedupe, routing.
4. Define validation window and rollback criteria.

## Output contract
- Noise candidates ranked by impact.
- Tuning proposal per candidate.
- Risk assessment of missed-detection tradeoff.
- Validation and rollback plan.

## Red lines
- Never suppress critical detections without compensating controls.
- Require measurable validation before permanent rule changes.
