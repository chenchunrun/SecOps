---
name: compliance-evidence-pack
description: Assemble compliance evidence packs by control mapping, evidence indexing, gap annotation, and reviewer-ready export structure.
license: Apache-2.0
compatibility: Crush SecOps compliance and audit functions.
---
# Compliance Evidence Pack

## When to use this skill
Use for periodic audits and control attestations.

## Required tool usage
- `compliance_check`
- `secret_audit`
- `access_review`
- `audit` and `siem_export`

## Workflow
1. Map requested controls to required evidence types.
2. Collect evidence artifacts and link to controls.
3. Mark gaps, exceptions, and compensating controls.
4. Build reviewer-ready index and summary.

## Output contract
- Control matrix: pass/fail/partial.
- Evidence index with traceable paths.
- Gap list with remediation owner/ETA.
- Reviewer summary.

## Red lines
- No fabricated evidence.
- Preserve original timestamps and provenance.
- Flag any missing evidence explicitly.
