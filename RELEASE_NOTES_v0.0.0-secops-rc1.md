# Release Notes: v0.0.0-secops-rc1

## Release Type

SecOps feature-complete release candidate (RC1).

## Highlights

- Delivered 18 SecOps tools with default runtime registration and invocation path.
- Enforced capability gates (`RequiredCapabilities`) and integrated risk-decision flow into execution chain.
- Replaced core placeholder/mock behavior with real execution-first paths (with controlled fallback/error handling).
- Completed compliance framework coverage including `GDPR`, `ISO27001`, and `Docker Bench` in `compliance_check`.
- Hardened config persistence: provider/API key encrypted at rest (`ENC:`) and reloaded correctly after restart.
- Completed SIEM security path: TLS required, credential redaction (13 patterns), retry with exponential backoff.
- Fixed TUI permission dialog stability: no overflow deformation and no option-label jitter on selection changes.

## End-to-End Coverage Added

- `permission -> risk -> tool -> audit -> SIEM` integration path.
- `save key -> restart -> reload key -> audit event -> SIEM reconciliation` integration path.

## Verification Summary

Executed on this release candidate:

```bash
go test ./internal/agent/tools/secops -count=1
go test ./internal/integration -count=1
go test ./internal/sandbox ./internal/audit -count=1
go test ./... -count=1
```

Result: all passed.

## Security Audit Summary

### Automated checks run

- `go test ./... -count=1`: passed
- `go vet ./...`: 1 non-security warning in `internal/csync/maps.go` (copying struct containing `sync.RWMutex`)

### Tool availability in current environment

- `govulncheck`: not installed in environment
- `gosec`: not installed in environment

### Manual security-focused review outcomes

- SIEM export enforces TLS and rejects plaintext export mode.
- Credential redaction is applied before SIEM serialization (13 patterns).
- Sensitive config fields (e.g., API key, tokens) are encrypted at rest and decrypted at load time.
- Permission audit log sanitizes params and truncates execution description to 64 chars.
- `certificate_audit` uses `InsecureSkipVerify: true` only to retrieve peer certificate for audit/inspection workflows; this is intentional for diagnostic coverage and is not used as trust acceptance.

## Known Non-Blocking Items

- `go vet` warning in `internal/csync/maps.go` (lock-by-value in schema alias method) should be cleaned in a follow-up hardening patch.
- For stricter supply-chain and SAST assurance before GA, run:
  - `govulncheck ./...`
  - `gosec ./...`
  in CI with pinned tool versions.

## Recommended Publish Steps

1. Push main and tag:
   - `git push origin main`
   - `git push origin v0.0.0-secops-rc1`
2. Publish GitHub release with this note.
3. Gate production rollout on smoke checks in target environment (provider auth, sandbox backend, SIEM endpoint).

