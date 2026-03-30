# SecOps Reasoning Release Note

## Summary

This change adds a MITRE ATT&CK-guided investigation workflow to the merged
SecOps runtime.

The new default investigation path is:

`incident_assess -> attack_reason -> SecurityExpertAgent -> TUI SecOps renderer`

## What Changed

- Added ATT&CK knowledge, mapping, and reasoning modules under
  `internal/security/attack/`
- Added `attack_reason` as a SecOps tool for ATT&CK technique ranking
- Added `incident_assess` as a higher-level incident investigation tool
- Updated `SecurityExpertAgent` prompt and runtime workflow selection so
  multi-source security investigations prefer `incident_assess`
- Added structured security workflow summaries to agent responses
- Added dedicated TUI renderers for `incident_assess` and `attack_reason`
- Added a repeatable demo script:
  `bash ./scripts/demo_secops_reasoning.sh`

## User-Facing Outcome

- Multi-source security evidence can now be consolidated into an
  investigation-ready assessment
- ATT&CK technique ranking is available as a follow-up reasoning step instead
  of free-form prompt speculation
- Security-mode tool output in the TUI now shows structured summaries instead
  of generic JSON blobs

## Validation

The demo chain validates:

1. ATT&CK reasoning tools
2. SecurityExpertAgent runtime workflow selection
3. TUI SecOps tool rendering
4. End-to-end incident response integration

Recommended command:

```bash
GOCACHE=$(pwd)/.gocache bash ./scripts/demo_secops_reasoning.sh
```

## Known Notes

- In environments without the `task` binary, use the script directly even
  though `Taskfile.yaml` includes `demo:secops-reasoning`
- Full repository validation may still depend on local network/module cache
  conditions and sandbox permissions
