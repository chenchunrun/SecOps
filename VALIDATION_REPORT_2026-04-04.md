# Validation Report (2026-04-04)

## Scope
- Release-closeout regression rerun for the merged SecOps mainline.
- Validation focused on the previously outstanding non-sandbox gates:
  - focused SecOps tool suite
  - integration suite
  - safety-related suites
  - full repository test gate
  - full repository build gate

## Environment
- Workspace: `/Users/newmba/SecOpsCode/crush-main`
- Date: `2026-04-04 08:55:42 CST`
- Go version: `go version go1.26.1 darwin/arm64`
- Host OS: `darwin/arm64`
- Shell: `zsh`
- Network access available: not required for this run
- Local port binding available: yes
- Cache strategy:
  - `GOCACHE=$(pwd)/.gocache`
- Build mode for full gates:
  - `CGO_ENABLED=0`

## Commands Executed
```bash
GOCACHE=$(pwd)/.gocache go test ./internal/agent/tools/secops -count=1
GOCACHE=$(pwd)/.gocache go test ./internal/integration -count=1
GOCACHE=$(pwd)/.gocache go test ./internal/audit ./internal/sandbox ./internal/permission ./internal/security -count=1
CGO_ENABLED=0 GOCACHE=$(pwd)/.gocache go test ./... -count=1
CGO_ENABLED=0 GOCACHE=$(pwd)/.gocache go build ./...
```

## Results
- PASS: focused security and reliability subset
- PASS: `internal/agent/tools/secops`
- PASS: `internal/integration`
- PASS: `internal/audit ./internal/sandbox ./internal/permission ./internal/security`
- PASS: full repository regression suite
- PASS: full repository build gate

## Evidence
- Current branch: `main`
- Current commit: `b121783`
- Relevant local diff state:
  - workspace contains ongoing local source changes and report files
  - validation completed against that current working tree state
- Notable suite durations:
  - `internal/agent/tools/secops` ~193s as focused run
  - `internal/agent/tools/secops` ~133s inside full suite
  - `internal/audit` ~49s
  - `internal/sandbox` ~17s
- Any failing test names:
  - none

## Notes
- Earlier full-gate attempts without `CGO_ENABLED=0` stalled in `cgo -V=full`
  probing rather than surfacing source failures.
- Re-running the full test/build gates with `CGO_ENABLED=0`, which matches the
  project-default build mode, completed successfully.
- The previously documented local-port bind concern did not reproduce in this
  environment; both the focused integration suite and full suite passed.
- A follow-up closeout security audit also completed on 2026-04-04; see
  [`SECURITY_AUDIT_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/SECURITY_AUDIT_2026-04-04.md).

## Follow-up Actions
1. Perform the remaining manual TUI acceptance pass for `AUTO -> OPS -> SEC -> AUTO`.
2. Confirm release/package artifacts after the latest UI/routing and naming changes.
3. Update status/checklist docs to mark non-sandbox validation rerun complete.
