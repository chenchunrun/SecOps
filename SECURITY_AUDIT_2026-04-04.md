# Security Audit Record (2026-04-04)

This document records the targeted closeout security audit performed during the
mainline release-closeout cycle.

It focuses on the security-sensitive paths reviewed in:

- [`internal/audit/siem_export.go`](/Users/newmba/SecOpsCode/crush-main/internal/audit/siem_export.go)
- [`internal/sandbox/executor.go`](/Users/newmba/SecOpsCode/crush-main/internal/sandbox/executor.go)
- [`internal/permission/secops_permission.go`](/Users/newmba/SecOpsCode/crush-main/internal/permission/secops_permission.go)
- [`internal/agent/secops_adapter.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/secops_adapter.go)

## Scope

- SIEM export transport enforcement
- Sandbox local/docker/ssh execution controls
- SecOps remote parameter validation
- Permission and audit integration around SecOps execution

## Findings Summary

### Fixed in this audit pass

#### 1. SIEM exporters now require real HTTPS endpoints

Issue:

- ELK and Splunk exporters previously trusted `TLSEnabled` as a policy flag but
  did not verify that `Endpoint` actually used the `https://` scheme.
- A misconfigured `http://` endpoint could therefore send redacted audit data
  and authentication material over plaintext transport.

Fix:

- Added endpoint validation in
  [`internal/audit/siem_export.go`](/Users/newmba/SecOpsCode/crush-main/internal/audit/siem_export.go)
  so ELK and Splunk exporters now reject non-HTTPS endpoints even when
  `TLSEnabled` is set.
- Updated tests in
  [`internal/audit/siem_export_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/audit/siem_export_test.go)
  to use TLS test servers and added explicit regression coverage for
  non-HTTPS rejection.

Severity:

- High

#### 2. SSH target allowlists are now enforced

Issue:

- `SandboxConfig.AllowedHosts` and `SandboxConfig.AllowedPorts` existed in the
  executor contract but were not enforced before remote SSH execution.
- This created a policy gap where configuration implied host/port scoping but
  runtime execution did not honor it.

Fix:

- Added `validateSSHExecutionTarget(...)` and target parsing logic in
  [`internal/sandbox/executor.go`](/Users/newmba/SecOpsCode/crush-main/internal/sandbox/executor.go).
- SSH execution now rejects targets outside configured host/port allowlists.
- Added regression tests in
  [`internal/sandbox/executor_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/sandbox/executor_test.go)
  for disallowed host, disallowed port, and SSH target parsing.

Severity:

- High

#### 3. Configured deny/read-only paths now participate in command safety checks

Issue:

- `DenyPaths` and `ReadOnlyPaths` were meaningful for Docker argument building,
  but local and SSH execution still relied only on a hardcoded path denylist.
- This meant caller-supplied path restrictions could be silently ignored
  outside Docker mode.

Fix:

- Extended `checkCommandSafety(...)` in
  [`internal/sandbox/executor.go`](/Users/newmba/SecOpsCode/crush-main/internal/sandbox/executor.go)
  to:
  - reject commands referencing configured `DenyPaths`
  - reject write-like commands that target configured `ReadOnlyPaths`
- Added regression tests in
  [`internal/sandbox/executor_test.go`](/Users/newmba/SecOpsCode/crush-main/internal/sandbox/executor_test.go)
  for both cases.

Severity:

- Medium

#### 4. Sandbox config validation now rejects invalid CPU/port settings

Issue:

- `MaxCPU` and `AllowedPorts` were not fully validated at config-check time.

Fix:

- Added validation in
  [`internal/sandbox/executor.go`](/Users/newmba/SecOpsCode/crush-main/internal/sandbox/executor.go)
  for negative CPU values and out-of-range allowed ports.

Severity:

- Low

## Residual Risk

### Local and SSH execution still rely on command-string inspection

Current state:

- Docker mode has stronger isolation primitives available through container
  runtime flags.
- Local execution still uses `sh -c`.
- SSH execution still forwards a command string to `ssh target cmd`.
- For local and SSH modes, configured `ReadOnlyPaths` are enforced only through
  command-level heuristics, not through filesystem-enforced read-only mounts or
  equivalent kernel/runtime isolation.

Risk assessment:

- This is not currently a known direct bypass with a tested exploit path in the
  reviewed code.
- It is, however, a meaningful architectural security debt because the
  protection boundary is weaker than a true filesystem isolation mechanism.
- In trusted operator workflows, this is acceptable for current release
  closeout.
- In stronger adversarial or model-evasion scenarios, this should not be
  treated as equivalent to hard sandbox isolation.

Recommended follow-up:

1. Keep Docker mode as the preferred stronger isolation path for execution that
   requires real filesystem restrictions.
2. If local/SSH execution needs stronger guarantees, move enforcement down from
   command parsing into an execution environment that can apply OS/runtime-level
   controls.
3. Treat local/SSH read-only restrictions as policy guardrails, not hard
   isolation, until that work is done.

Severity:

- Medium architectural risk

## Verification

The following regression suites passed after the fixes:

```bash
go test ./internal/sandbox ./internal/audit -count=1
go test ./internal/permission ./internal/security -count=1
```

## Bottom Line

- The concrete high-value security gaps found in this audit pass were fixed.
- The remaining security concern is an architectural limitation in local/SSH
  execution isolation, not a release-blocking source-level defect discovered in
  this pass.
