# SecOps Agent

SecOps Agent is an independent security-operations fork based on Crush.
It is maintained and released by **chenchunrun**.

- Upstream base: Crush by Charmbracelet
- Repository module: `github.com/chenchunrun/SecOps`
- Scope: SecOps tools, risk/capability enforcement, audit/SIEM, and secure runtime workflows

## Project Positioning

SecOps Agent extends the upstream terminal coding assistant with production-focused
security operations capabilities.

Key additions in this fork:

- 18 SecOps tool categories under `internal/agent/tools/secops`
- Capability gate and risk-aware permission decisions
- Audit pipeline and SIEM export with sensitive-data redaction
- Local/Docker/SSH sandbox execution controls
- Integration tests covering permission, risk, tools, audit, SIEM, and persistence

## Architecture (Current)

```text
internal/
  agent/
    coordinator.go
    secops_adapter.go
    secops_ops_agent.go
    secops_security_expert_agent.go
    tools/secops/                 # SecOps tool implementations
  permission/
    permission.go
    secops_permission.go
  security/
    capability.go
    risk_assessment.go
  sandbox/
    executor.go
  audit/
    audit.go
    audit_store.go
    compliance_report.go
    siem_export.go
  integration/                    # End-to-end integration tests
```

## SecOps Tooling

Primary tool categories include:

- `security_scan`
- `monitoring_query`
- `log_analyze`
- `compliance_check`
- `certificate_audit`
- `configuration_audit`
- `network_diagnostic`
- `database_query`
- `backup_check`
- `replication_status`
- `secret_audit`
- `rotation_check`
- `access_review`
- `infrastructure_query`
- `deployment_status`
- `alert_check`
- `incident_timeline`
- `resource_monitor`

## Security Model

### Capability + Role Model

Role hierarchy:

`Viewer -> Operator -> Admin`

Capabilities are validated before tool execution in the SecOps adapter and
permission layer.

### Risk Scoring

The risk engine evaluates requests using multiple factors (for example banned
commands, sensitive path access, credential exposure, system modification, and
network access) and maps them to risk levels.

Permission decisions can result in:

- allow
- require confirmation/review
- block

Decision context is captured for later auditing.

## Audit and SIEM

The audit subsystem supports:

- event recording with metadata
- filtering and reporting
- SIEM export targets (ELK, Splunk, Azure Sentinel, generic JSON)
- redaction of sensitive fields before export

## Build and Test

From repository root:

```bash
go build ./...
go test ./...
```

Recommended SecOps verification:

```bash
go test ./internal/agent/tools/secops -count=1
go test ./internal/integration -count=1
go test ./internal/sandbox ./internal/audit -count=1
```

## Runtime Configuration

Typical config search order:

1. `.crush.json`
2. `crush.json`
3. `$HOME/.config/crush/crush.json`

Persistent state and local data are written under the user data/config
locations used by Crush.

### Bypass-Intent Guardrail (New)

The permission service now enforces a bypass-intent guardrail before applying
`skip_requests`, `allowed_tools`, or session auto-approve.

- High/Critical risk requests are forced into interactive confirmation.
- Suspicious bypass intent is emitted to audit as `security_alert` with action
  `permission_bypass_intent_detected`.
- Marker rules are configurable:
  - `permissions.bypass_intent_markers`: override the default marker set
  - `permissions.extra_bypass_intent_markers`: append organization-specific markers

Example:

```json
{
  "permissions": {
    "allowed_tools": ["view", "ls"],
    "bypass_intent_markers": ["ignore all guardrails", "org-bypass-keyword"],
    "extra_bypass_intent_markers": ["临时绕过审批"]
  }
}
```

## Compliance and Legal

- License: see `LICENSE.md`
- Attribution and fork notice: see `NOTICE`
- This project is an independent fork and is not affiliated with or endorsed by
  Charmbracelet.

## Release Notes and Support

- Releases: <https://github.com/chenchunrun/SecOps/releases>
- Issues: <https://github.com/chenchunrun/SecOps/issues>

## Changelog Note

This document was refreshed on **2026-03-23** to match the current repository
structure and release posture.
