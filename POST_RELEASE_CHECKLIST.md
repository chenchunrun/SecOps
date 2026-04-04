# Post Release Checklist (SecOps Mainline Closeout)

> Local checklist for release verification. Do not push to remote.

## Current Automated Baseline

- [x] Focused SecOps tool suite passed.
- [x] Integration suite passed.
- [x] Safety-related suites passed.
- [x] `CGO_ENABLED=0 GOCACHE=$(pwd)/.gocache go test ./... -count=1` passed.
- [x] `CGO_ENABLED=0 GOCACHE=$(pwd)/.gocache go build ./...` passed.
- Reference:
  - [`VALIDATION_REPORT_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/VALIDATION_REPORT_2026-04-04.md)

## Basic Availability

- [x] Local mainline CLI entry (`crush --version`) returns the expected current build identity.
- [x] Local mainline CLI entry (`crush`) starts successfully on target terminal.
- [ ] TUI text contrast is readable in both light and dark terminal themes.

## Configuration Persistence

- [ ] Configure provider API key once; restart `crush`; key is still available.
- [ ] Agent mode selection persists after restart.
- [ ] Fast/Deep mode selection can be toggled from `/` menu and is effective.

## Agent Routing and Modes

Working record:

- [`MANUAL_TUI_ACCEPTANCE_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/MANUAL_TUI_ACCEPTANCE_2026-04-04.md)

- [ ] Start in `AUTO` mode and verify header label shows `AUTO`.
- [ ] Trigger an Ops-style prompt in `AUTO`; verify pre-reply routing message announces Ops routing.
- [ ] Trigger a Security-style prompt in `AUTO`; verify pre-reply routing message announces Security routing.
- [ ] Switch to Ops from `/` menu; verify header label shows `OPS`.
- [ ] In Ops mode, editor placeholder mentions ops-oriented workflows such as alerts, monitoring, rollback, or remote hosts.
- [ ] Switch to Security from `/` menu; verify header label shows `SEC`.
- [ ] In Security mode, editor placeholder mentions vulnerabilities, evidence, alerts, or access risk.
- [ ] Switch back to `AUTO`; verify header label returns to `AUTO`.
- [ ] Switch `AUTO -> OPS -> SEC -> AUTO` without stuck mode state, stale placeholder text, or stale routing banner.

## SecOps Tools (18) Smoke Test

- [ ] `monitoring_query` executes with valid parameters.
- [ ] `log_analyze` executes with valid parameters.
- [ ] `security_scan` executes with valid parameters.
- [ ] `compliance_check` executes with valid parameters.
- [ ] At least one remote execution path is validated (SSH target).

## Permission, Risk, and Guardrails

- [ ] High-risk action triggers permission confirmation dialog.
- [ ] `Allow`, `Allow for Session`, `Deny` all behave correctly.
- [ ] Bypass-intent prompt triggers security audit alert (`permission_bypass_intent_detected`).
- [ ] High/Critical requests are not auto-approved by yolo/allowlist/session auto-approve.

## Audit and SIEM

- [ ] Audit events are persisted to `data_directory/audit/events.jsonl`.
- [ ] Remote execution audit fields exist (`transport`, `target_host`, `target_env`, `target_id`).
- [ ] SIEM export over TLS succeeds.
- [ ] Sensitive fields are redacted in exported payloads.
- [ ] Retry behavior works on temporary SIEM delivery failure.
- Reference:
  - [`SECURITY_AUDIT_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/SECURITY_AUDIT_2026-04-04.md)

## Packaging and Distribution

Working record:

- [`WINDOWS_PACKAGING_VERIFICATION_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/WINDOWS_PACKAGING_VERIFICATION_2026-04-04.md)

- [ ] Confirm latest packaging outputs after UI/routing and naming changes.
- [ ] On Windows packaging outputs, verify `secops-agent.exe` is primary and `crush.exe` remains a compatibility alias.
- [ ] Smoke test startup for at least one packaged artifact path.

## Release Notes and Records

- [ ] Decide whether `CURRENT_MAINLINE_STATUS_2026-03-28.md` remains local-only or is replaced by a formal release status artifact.
- [ ] Decide whether `PROJECT_COMPLETION_CHECKLIST_2026-03-28.md` remains local-only or is folded into release records.
- [ ] Decide whether [`SECURITY_AUDIT_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/SECURITY_AUDIT_2026-04-04.md) remains local-only or is folded into release records.
- [ ] If ATT&CK reasoning workflow is part of the release story, run `task demo:secops-reasoning` and archive the outcome.
- [ ] Ensure the release note references the latest validation baseline instead of older RC-only validation.

## Stability Follow-up

- [ ] No unexpected rate-limit spikes under normal single-user usage.
- [ ] No mode/routing regressions after a restart.

## Sign-Off

- [ ] Engineering sign-off
- [ ] Security sign-off
- [ ] Operations sign-off
- [ ] Release announcement published
