# SecOps Reasoning Demo

This demo exercises the ATT&CK-guided security investigation chain that now
exists in the merged SecOps runtime:

`incident_assess -> attack_reason -> SecurityExpertAgent -> TUI SecOps renderer`

## Run

From [`crush-main/`](/Users/newmba/SecOpsCode/crush-main):

```bash
task demo:secops-reasoning
```

If you want to run the script directly:

```bash
GOCACHE=$(pwd)/.gocache bash ./scripts/demo_secops_reasoning.sh
```

## What It Covers

1. `attack_reason` and `incident_assess` tool behavior
2. `SecurityExpertAgent` runtime workflow selection
3. TUI rendering for `incident_assess` and `attack_reason`
4. End-to-end incident response integration

## Expected Outcome

- `incident_assess` is the default primary tool for security investigation
  flows with multi-source evidence.
- `attack_reason` remains the follow-up tool for deeper ATT&CK technique
  ranking.
- TUI tool cards render a structured security summary instead of generic JSON.
- The integration test path confirms the rendered incident assessment includes
  workflow summary, recommendations, and next steps.
