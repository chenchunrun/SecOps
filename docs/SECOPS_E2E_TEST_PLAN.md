# SecOps End-to-End Test Plan

## 1. Goal and acceptance
Validate the full path across security and operations workflows:
- Prompt -> agent routing -> built-in SecOps tools -> permission/risk -> audit/SIEM -> TUI user experience.

Definition of Done:
- Critical scenarios pass with reproducible evidence.
- No red-line violations (defensive-only, approval enforcement, audit completeness).
- Tool fallback status is visible and not misleading.

## 2. Test environment matrix
- Local sandbox: default developer environment.
- Remote SSH profile: at least one staging host profile.
- Providers: zhipu, zai, minimax (or minimax-china), one fallback provider.
- Modes: run mode Auto/Fast/Deep; agent mode Auto/Coder/Ops/Security.

## 3. Core E2E suites

### Suite A: Alert-to-triage
1. Inject synthetic alert.
2. Run `incident-triage` skill flow.
3. Verify severity, impact scope, and first-check list.
4. Ensure tool evidence references are present.

Expected:
- Uses `alert_check`, `monitoring_query`, `log_analyze`.
- Output includes confidence and unresolved assumptions.

### Suite B: Incident command and timeline
1. Simulate multi-step incident updates.
2. Run `incident-commander` workflow.
3. Verify timeline continuity and decision log.

Expected:
- Uses `incident_timeline` and status tools.
- No missing ownership/ETA fields.

### Suite C: Change gate and post-change validation
1. Run pre-change checks on target service.
2. Trigger a controlled deployment.
3. Run post-change validation.

Expected:
- Gate verdict is GO/NO-GO with blockers.
- Rollback recommendation triggers on threshold failure.

### Suite D: Compliance evidence package
1. Execute compliance + access + secret audits.
2. Build evidence package output.
3. Validate control-to-evidence mapping.

Expected:
- Gaps explicitly flagged.
- No fabricated control pass state.

### Suite E: Vulnerability remediation closure
1. Detect vulnerabilities.
2. Apply mitigation/fix in staging.
3. Re-scan and verify closure.

Expected:
- Critical findings cannot be silently suppressed.
- Closure requires re-verification evidence.

### Suite F: Remote ops troubleshooting
1. Use approved remote profile.
2. Run read-only diagnostics first.
3. Apply minimal reversible action if needed.

Expected:
- Audit includes target host, command, approval chain.
- No destructive operation without explicit approval.

## 4. Agent routing tests

### A. Manual switch
- In `/` menu, set Agent Mode to `Ops`, `Security`, `Coder`.
- Verify next prompt runs under selected agent prompt role.

### B. Auto switch
- Set Agent Mode `Auto`.
- Security-heavy prompt should route to `security_expert_agent`.
- Ops-heavy prompt should route to `ops_agent`.
- Generic coding prompt should route to `coder`.

### C. Prefix override
- `/ops ...`, `/sec ...`, `/coder ...` must override auto mode.

## 5. Streaming UX tests
1. Send long-running prompt on high-latency model.
2. Verify incremental assistant output appears before completion.
3. Verify tool-call and thinking states progress in TUI.
4. Verify cancellation behavior under streaming.

Expected:
- User sees ongoing progress (not blank wait).
- No stuck state after cancel/retry.

## 6. Security guardrail tests
- High-risk command requires approval and is auditable.
- Permission deny path leaves clear denial reason.
- Fallback data source is explicitly labeled in outputs.
- SIEM export contains required fields and correlation IDs.

## 7. Regression checklist
- `go test ./internal/agent ./internal/ui/model ./internal/skills`
- Spot-check: tool availability in new session without manual allowed_tools edits.
- Config persistence: key/model/agent mode survive restart.

## 8. Evidence artifacts
For each suite, capture:
- Input prompt and mode settings.
- Tool call list and outputs.
- Audit event IDs.
- Final summary/result screenshot.
- Pass/fail with defect links.
