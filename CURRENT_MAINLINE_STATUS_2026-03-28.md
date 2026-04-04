# Current Mainline Status

Date: 2026-03-28

## Scope

This summary covers the recent mainline work completed on top of the SecOps
customized Crush build, with emphasis on:

- OpsAgent / SecurityExpertAgent differentiation
- TUI visibility and routing feedback
- Capability registry and tool/runtime governance genericization
- Windows packaging consistency
- Security hardening work already merged earlier in the same stream
- Release-closeout validation and architecture-status mapping

## Recently Completed

### 1. OpsAgent and SecurityExpertAgent are now clearly differentiated

Completed:

- Rewrote the `OpsAgent` system prompt to center on:
  - monitoring triage
  - release safety
  - rollback and recovery
  - capacity and availability work
  - approved remote maintenance
- Rewrote the `SecurityExpertAgent` system prompt to center on:
  - vulnerability and exposure analysis
  - suspicious activity investigation
  - evidence and containment
  - access review
  - compliance and control gaps

Result:

- Ops answers now bias toward:
  - symptom
  - impact
  - likely cause
  - runbook steps
  - rollback or recovery
- Security answers now bias toward:
  - threat
  - scope
  - evidence
  - severity
  - containment
  - remediation

Key commits:

- `75d62cf` `feat: sharpen ops and security agent workflows`

### 2. Auto routing is more scenario-driven

Completed:

- Expanded routing heuristics for operations scenarios:
  - CPU high
  - memory high
  - disk full
  - latency
  - timeout
  - rollback
  - release
  - replication
  - backup/restore
  - SSH / remote host
- Expanded routing heuristics for security scenarios:
  - CVE / CVSS
  - suspicious login
  - credential or secret exposure
  - IOC / MITRE
  - forensic intent
  - containment intent
  - compliance / audit

Result:

- `AUTO` mode now routes closer to real SecOps work intent instead of relying
  on a small keyword set.

### 3. TUI now exposes agent identity more clearly

Completed:

- Header now shows current mode:
  - `OPS`
  - `SEC`
  - `CODE`
  - `AUTO`
- Editor placeholders now change by mode:
  - Ops placeholders mention alerts, monitoring, rollback, remote hosts
  - Security placeholders mention vulnerabilities, alerts, evidence, access risk
  - Auto placeholders explain automatic routing
- `/` and `ctrl+p` help text now points to `modes`
- Commands dialog agent entries now explain real use cases instead of only
  showing a raw mode name

Key commits:

- `0094420` `feat: surface active agent mode in tui chrome`

### 4. Auto mode now announces routing before the reply starts

Completed:

- Added immediate UI info messages before model reply:
  - `Auto routed to Ops: ...`
  - `Auto routed to Security: ...`
  - `Auto routed to Coder: ...`

Result:

- Users can see routing decisions instantly, without waiting for the first
  generated answer.

Key commits:

- `a8560d5` `feat: show auto-routed agent before reply`

### 5. Windows packaging is now consistent with the SecOps Agent product name

Completed:

- Windows packages now ship `secops-agent.exe` as the primary executable
- `crush.exe` is retained as a compatibility alias
- Installer and uninstall scripts handle both names
- Install instructions now reflect both launch options

Result:

- Fixes the previous mismatch between product naming and executable naming in
  Windows distribution packages.

Key commits:

- `d040904` `fix: align windows package binary names`

## Security and Hardening State

Already completed in the recent mainline stream:

- Syslog audit export hardening
- Bounded async audit export queue
- RFC5424 header sanitization
- Safer SSH host key behavior in sandbox execution
- Certificate probe integrity marking and explicit unverified mode handling

Relevant commits:

- `53ec49b` `sec: harden syslog audit export path`
- `bcaab66` `sec: harden ssh trust and certificate probe integrity`
- `3103473` `sec: require explicit mode for unverified certificate probes`

## Validation State

Validated in earlier iterations:

- `go test ./internal/ui/model -count=1`
- `go test ./internal/ui/model ./internal/agent/prompt -count=1`
- `go build ./...`

Release-closeout validation rerun on 2026-04-04:

- `GOCACHE=$(pwd)/.gocache go test ./internal/agent/tools/secops -count=1`
- `GOCACHE=$(pwd)/.gocache go test ./internal/integration -count=1`
- `GOCACHE=$(pwd)/.gocache go test ./internal/audit ./internal/sandbox ./internal/permission ./internal/security -count=1`
- `CGO_ENABLED=0 GOCACHE=$(pwd)/.gocache go test ./... -count=1`
- `CGO_ENABLED=0 GOCACHE=$(pwd)/.gocache go build ./...`

Result:

- Automated validation gates passed on the current mainline workspace.

Current build status:

- Mainline builds successfully.
- Validation baseline is now
  [`VALIDATION_REPORT_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/VALIDATION_REPORT_2026-04-04.md).
- The working tree includes ongoing local source and documentation changes tied
  to closeout work; validation was run against that current workspace state.

## Architecture Mapping Status

The current architecture-level closeout conclusion is:

- The tool/runtime governance path is the most completely optimized area.
- The SecOps-facing TUI improvements are code-complete, but still await manual
  acceptance.
- Other architecture areas described in
  [`/Users/newmba/SecOpsCode/PROJECT_ANALYSIS.md`](/Users/newmba/SecOpsCode/PROJECT_ANALYSIS.md)
  are implemented and functional, but were not all treated as dedicated
  optimization workstreams in this closeout cycle.

Reference:

- [`PROJECT_ANALYSIS_MAPPING_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/PROJECT_ANALYSIS_MAPPING_2026-04-04.md)

## Current Residual Items

Not code defects, but still worth follow-up:

- Perform a fresh manual TUI pass for:
  - `AUTO -> OPS -> SEC -> AUTO`
  - placeholder changes
  - header label changes
  - pre-reply routing messages
- Confirm release/package outputs after the latest naming and UI/routing
  changes
- Decide whether local summary documents should remain local-only or be moved
  into a formal release process outside the public repository

## Bottom Line

The current mainline is in a good state for continued SecOps feature work:

- agent roles are clearer
- routing is more explainable
- TUI feedback is more explicit
- tool/runtime governance has been significantly cleaned up and unified
- Windows packaging is corrected
- recent security hardening changes are already in the merged stream
- remaining work is now primarily manual acceptance and release signoff
