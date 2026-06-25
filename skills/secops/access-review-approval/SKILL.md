---
name: access-review-approval
description: Evaluate access requests and existing privileges with least-privilege policy, segregation-of-duties checks, and approval recommendations.
license: Apache-2.0
compatibility: Crush SecOps IAM and access audit capabilities.
---
# Access Review Approval

## When to use this skill
Use for new access requests or periodic privilege recertification.

## Required tool usage
- `access_review`
- `rotation_check` (for credential hygiene context)
- `audit` records

## Workflow
1. Evaluate requested privilege scope and duration.
2. Check SoD conflicts and toxic combinations.
3. Recommend approve, approve-with-condition, or reject.
4. Define expiry and monitoring controls for approved access.

## Output contract
- Decision recommendation with rationale.
- Risk score and compensating controls.
- Expiry, review cadence, and owner.

## Red lines
- No permanent broad access by default.
- Require explicit business justification for elevated privileges.
