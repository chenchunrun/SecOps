# SecOps Agent v0.0.0-secops-rc4

This release candidate consolidates the SecOps runtime work completed after
rc3 and is intended for final production-readiness validation before v1.0.

## Highlights

- Twenty governed SecOps tools, including ATT&CK reasoning and consolidated
  incident assessment.
- Thirty-five bundled security skills with explicit authorization gates for
  red-team workflows.
- Evidence-first investigations with task-bound hashes, verified reports, and
  independent Maker/Checker identities for high-risk findings.
- Durable task scheduling, workspace snapshots, resource admission,
  pause/resume controls, crash recovery, and side-effect deduplication.
- Local, Docker, and SSH computer backends with egress decisions, transient
  credential leases, readiness checks, and health monitoring.
- Tamper-evident audit storage and redacted export to Elastic, Splunk, Azure
  Sentinel, syslog, and JSON-compatible sinks.
- Versioned connector contracts for Sentinel, Splunk, Elastic, Defender XDR,
  CrowdStrike Falcon, and Jira.
- Security workbench views for tasks, evidence, approvals, and verification.

## Release hardening

- Build, test, lint, snapshot, CodeQL, Grype, and govulncheck gates run in
  GitHub Actions.
- The SecOps control-plane statement coverage gate is enforced at 80%.
- Cross-platform packages include per-artifact SHA-256 files, an aggregate
  checksum manifest, and a CycloneDX source SBOM.
- Unknown tools use the production generic renderer instead of exposing a
  placeholder, and provider retries emit bounded metadata-only diagnostics.
- Release automation is repository-local and no longer depends on upstream
  project publishing credentials.

## Safety defaults

- Read-only investigation remains the default release policy.
- Approved response, automatic response, and red-team execution are separate
  gates and fail closed.
- Red-team execution requires explicit authorization; signed-scope workflows
  additionally validate target, ports, time window, and kill-switch state.
- External scanners, SIEM endpoints, and connector credentials must be
  configured by the operator and are not bundled into release artifacts.

## Upgrade notes

- The preferred executable is `SecOps` on macOS and Linux and
  `secops-agent.exe` on Windows. Windows packages retain `crush.exe` as a
  compatibility alias.
- Existing `.crush` data and configuration directories remain compatible.
- Review governance, sandbox, egress, and red-team authorization settings
  before enabling any write-capable workflow.

## Verification

Release artifacts are produced only after the full Go test suite and the
SecOps coverage gate pass. The release workflow attaches cross-platform
archives, SHA-256 checksums, and a CycloneDX SBOM to the GitHub prerelease.
