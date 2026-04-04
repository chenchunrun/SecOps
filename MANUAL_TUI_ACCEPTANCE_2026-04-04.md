# Manual TUI Acceptance Record (2026-04-04)

> Local execution record for the remaining mainline manual acceptance work.
> Fill this out during the closeout pass. Do not push to remote unless you
> intentionally want to publish it.

## Scope

- TUI mode switching
- AUTO routing visibility
- Placeholder updates by mode
- Basic startup and readability
- Restart persistence checks tied to user-facing flows

Automated baseline already passed:

- [`VALIDATION_REPORT_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/VALIDATION_REPORT_2026-04-04.md)

## Environment

- Date: `2026-04-04 10:03:53 CST`
- Operator: Codex precheck
- Host OS:
- Terminal app:
- Terminal theme:
- Build/binary under test: `/tmp/crush-mainline-smoke`

## Automated Precheck

Completed before manual execution:

- `CGO_ENABLED=0 GOCACHE=$(pwd)/.gocache GOMODCACHE=$(pwd)/.gomodcache go build -o /tmp/crush-mainline-smoke .`
- `/tmp/crush-mainline-smoke --version`
  - Result:
    `SecOps version v0.0.0-secops-rc3.0.20260402102621-b12178311fc1+dirty`
- `/tmp/crush-mainline-smoke --help`
  - Result:
    CLI help rendered successfully and command startup path is healthy.
- `go test ./internal/ui/model ./internal/agent/prompt -count=1`
  - Result:
    PASS

Code-backed UI references confirmed before manual execution:

- Header mode labels are defined in
  [`internal/ui/model/header.go`](/Users/newmba/SecOpsCode/crush-main/internal/ui/model/header.go).
- Mode placeholders and info messages are defined in
  [`internal/ui/model/ui.go`](/Users/newmba/SecOpsCode/crush-main/internal/ui/model/ui.go).

## Expected UI References

- Header labels:
  - `AUTO`
  - `OPS`
  - `SEC`
  - `CODE`
- Mode-switch info messages:
  - `Agent switched to Ops: monitoring, change safety, recovery, and remote maintenance`
  - `Agent switched to Security: vulnerabilities, alerts, compliance, and evidence review`
  - `Agent mode set to auto: route by operational, security, or coding intent`
- AUTO pre-reply routing messages:
  - `Auto routed to Ops: monitoring, change safety, recovery, and remote maintenance`
  - `Auto routed to Security: vulnerabilities, alerts, compliance, and evidence review`
  - `Auto routed to Coder: implementation, debugging, and code review`

## Checklist

### 1. Basic Startup

- [x] `crush --version` or the chosen packaged binary returns expected identity.
- [x] Application launches successfully into the TUI.
- [ ] Text contrast is readable in the current terminal theme.
- Notes:
  - Binary smoke precheck passed with `/tmp/crush-mainline-smoke --version`.
  - CLI help path also rendered successfully via `/tmp/crush-mainline-smoke --help`.

### 2. AUTO Mode Baseline

- [ ] Initial or selected mode shows header label `AUTO`.
- [ ] Editor placeholder is AUTO-oriented rather than stale from another mode.
- [ ] Placeholder is consistent with auto-routing language.
- Notes:
  - AUTO header label is the default fallback in
    [`internal/ui/model/header.go`](/Users/newmba/SecOpsCode/crush-main/internal/ui/model/header.go).
  - AUTO placeholders are sourced from
    [`internal/ui/model/ui.go`](/Users/newmba/SecOpsCode/crush-main/internal/ui/model/ui.go).

### 3. AUTO -> OPS Routing

- Prompt used:
- [ ] Prompt is clearly operations-oriented.
- [ ] Pre-reply info message announces Ops routing.
- [ ] Subsequent response behavior is Ops-oriented.
- Notes:

### 4. AUTO -> SEC Routing

- Prompt used:
- [ ] Prompt is clearly security-oriented.
- [ ] Pre-reply info message announces Security routing.
- [ ] Subsequent response behavior is Security-oriented.
- Notes:

### 5. Explicit OPS Mode

- [ ] Switching to Ops from `/` menu succeeds.
- [ ] Header label changes to `OPS`.
- [ ] Editor placeholder mentions ops workflows such as alerts, monitoring, rollback, or remote hosts.
- [ ] No stale security/coder placeholder text remains.
- Notes:
  - OPS placeholders and mode-switch banner strings are defined in
    [`internal/ui/model/ui.go`](/Users/newmba/SecOpsCode/crush-main/internal/ui/model/ui.go).

### 6. Explicit SEC Mode

- [ ] Switching to Security from `/` menu succeeds.
- [ ] Header label changes to `SEC`.
- [ ] Editor placeholder mentions vulnerabilities, evidence, alerts, or access risk.
- [ ] No stale ops/coder placeholder text remains.
- Notes:
  - SEC placeholders and mode-switch banner strings are defined in
    [`internal/ui/model/ui.go`](/Users/newmba/SecOpsCode/crush-main/internal/ui/model/ui.go).

### 7. Return to AUTO

- [ ] Switching back to AUTO succeeds.
- [ ] Header label returns to `AUTO`.
- [ ] AUTO placeholder returns and does not retain OPS/SEC wording.
- [ ] No stale routing banner remains after mode change.
- Notes:
  - AUTO reset message is defined in
    [`internal/ui/model/ui.go`](/Users/newmba/SecOpsCode/crush-main/internal/ui/model/ui.go).

### 8. Full Transition Path

- [ ] `AUTO -> OPS -> SEC -> AUTO` completes without stuck mode state.
- [ ] Header label is correct at each transition.
- [ ] Placeholder updates correctly at each transition.
- [ ] Routing/info messages remain consistent across transitions.
- Notes:

### 9. Restart Persistence

- [ ] Restart preserves the expected agent mode selection behavior.
- [ ] Restart does not regress header label or placeholder behavior.
- [ ] If provider config was changed before restart, persisted config is still present after restart.
- Notes:

## Result Summary

- PASS/FAIL:
- Blocking issues:
- Non-blocking issues:
- Follow-up actions:
