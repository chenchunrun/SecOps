# Release Notes: v0.0.0-secops-rc3

## Release Type

SecOps release candidate (RC3) focused on security hardening, runtime
stability, and release readiness.

## Highlights

- Hardened permission guardrails against prompt/skill bypass attempts.
- Added configurable bypass-intent markers:
  - `permissions.bypass_intent_markers` (override defaults)
  - `permissions.extra_bypass_intent_markers` (append defaults)
- Enforced high/critical-risk requests to require interactive confirmation even
  when `allowed_tools`, `--yolo`, or session auto-approve are enabled.
- Added security audit alert for suspected bypass intent:
  - `event_type=security_alert`
  - `action=permission_bypass_intent_detected`
- Reworked SecOps role resolution to use runtime context (active agent path)
  instead of process-level env role toggles.
- Removed provider configuration global env mutation side effects.
- Upgraded config secret protection:
  - random persistent master key (`secrets.key`)
  - optional `CRUSH_MASTER_KEY` override
  - backward-compatible decryption for legacy encrypted values
- Added file-backed audit persistence (`events.jsonl`) with in-memory fallback.
- Stabilized TUI contrast/permission dialog behavior and refreshed release docs.

## Commits in RC3

- `53c3d71` sec: harden runtime env, role context, key storage and audit persistence
- `08f781c` sec: harden permission bypass guardrails and persist agent/config updates
- `c56a253` sec: harden remote execution validation and audit observability
- `9d9d931` feat: commit remaining secops, ui, audit, and test updates
- `04ed82d` fix: harden tool compatibility and startup refresh path
- `0a0f158` fix(ui): adapt theme to terminal dark/light background
- `e9f7492` feat(secops): improve ops safety, readability, and packaging
- `b5f80ad` fix(ui): enforce light theme and improve tui contrast readability
- `53aa224` docs(secops): rewrite secops readme for release and compliance
- `29c1e1c` docs: add publisher attribution and secops compliance notices
- `5b350f7` chore(repo): keep secops planning docs local only

## Verification Summary

Executed and passed on RC3:

```bash
go test ./... -count=1
go build ./...
```

## Notes

- `gh` CLI is not installed in this environment; release artifact publication is
  expected to be completed via GitHub web UI using this note.
