---
name: vuln-remediation-orchestrator
description: Orchestrate vulnerability remediation from detection to verification with risk prioritization, owner assignment, and closure criteria.
license: Apache-2.0
compatibility: Crush SecOps vulnerability and deployment workflows.
---
# Vulnerability Remediation Orchestrator

## When to use this skill
Use when vulnerabilities are discovered and need tracked closure.

## Required tool usage
- `security_scan`
- `configuration_audit`
- `compliance_check`
- `deployment_status`

## Workflow
1. De-duplicate findings and prioritize by exploitability and exposure.
2. Define patch or mitigation path for each item.
3. Assign owner, SLA, and rollback constraints.
4. Re-verify fixes and record closure evidence.

## Output contract
- Prioritized remediation backlog.
- Action plan per vulnerability.
- Re-test result and closure state.

## Red lines
- No suppressing critical findings without approved exception.
- No claiming closure without verification evidence.
