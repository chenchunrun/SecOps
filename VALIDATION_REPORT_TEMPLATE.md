# Validation Report Template

Date: YYYY-MM-DD

## Scope

- Describe the exact release gate or validation scope.
- Note whether this run is pre-release, post-fix, or routine regression.

## Environment

- Workspace: `/absolute/path/to/crush-main`
- Go version: `go version`
- Host OS:
- Shell:
- Network access available: yes/no
- Local port binding available: yes/no
- Cache strategy:
  - `GOCACHE=...`
  - `GOMODCACHE=...` if overridden

## Commands Executed

```bash
task validate:secops
```

If a narrower run was used instead, capture the exact command:

```bash
SKIP_FULL=1 bash ./scripts/validate_secops_release.sh
```

If the ATT&CK reasoning workflow was demonstrated separately, capture it too:

```bash
task demo:secops-reasoning
```

## Results

- PASS/FAIL: focused security and reliability subset
- PASS/FAIL: `internal/agent/tools/secops`
- PASS/FAIL: `internal/integration`
- PASS/FAIL/SKIPPED: full repository regression suite

## Evidence

- Current branch:
- Current commit:
- Relevant local diff state:
- Notable suites and durations:
- Any failing test names:

## Notes

- Record environment blockers separately from code regressions.
- If the run required elevated permissions, say so explicitly.
- If module download was required, note whether the run depended on network.

## Follow-up Actions

1. Add any required fixes or reruns.
2. Note any manual checks still outstanding.
3. Link the final release note or checklist if applicable.
