# PROJECT_ANALYSIS Mapping (2026-04-04)

This document maps the architecture themes described in
[`/Users/newmba/SecOpsCode/PROJECT_ANALYSIS.md`](/Users/newmba/SecOpsCode/PROJECT_ANALYSIS.md)
to the current `crush-main` implementation and indicates whether the related
optimization work is complete, partial, or not part of the recent closeout
stream.

## Summary

The short version:

- The recent closeout work fully covered the tool/runtime governance path.
- UI work related to mode visibility and routing feedback is implemented, but
  still has manual acceptance work outstanding.
- Other architecture areas from `PROJECT_ANALYSIS.md` exist in `crush-main`,
  but were not all turned into dedicated optimization workstreams in this
  iteration.

## Mapping Table

| Architecture theme from `PROJECT_ANALYSIS.md` | Current `crush-main` mapping | Status | Notes |
|---|---|---|---|
| Startup and initialization | `main.go`, `internal/cmd/root.go`, `internal/app/` | Partial | Implemented and working, but not a major focus of the recent optimization stream. |
| Command system | `internal/cmd/` and TUI command flows | Partial | Command infrastructure exists, but no dedicated closeout optimization campaign was completed here. |
| Tool system / tool calling | `internal/agent/tools/`, `internal/capability/registry/`, `internal/agent/coordinator.go`, `internal/agent/secops_adapter.go` | Complete (for recent optimization scope) | This is the strongest completed area: registry genericization, fixed toolset builders, config/runtime/catalog consistency, and SecOps single-source metadata. |
| Query loop / session engine | `internal/agent/coordinator.go`, `internal/agent/agent.go` | Partial | Runtime loop and session behavior exist, but were not comprehensively re-architected in this closeout stream. |
| API and model invocation layer | provider/model handling in `internal/agent/coordinator.go`, config/provider definitions in `internal/config/config.go` | Partial | Functional and validated, but not fully treated as a dedicated optimization workstream. |
| Terminal UI layer | `internal/ui/model/`, `internal/ui/chat/` | Partial | Key SecOps-facing UI improvements are implemented (mode labels, placeholders, auto-routing messages), but manual acceptance is still outstanding. |
| Extensions and integrations | MCP/LSP/remote/SecOps runtime integration across `internal/agent/tools/`, `internal/permission/`, `internal/sandbox/` | Mostly complete | Core integration paths exist and are validated; not every extension axis was separately optimized in this stream. |

## Detailed Assessment

### 1. Startup and Initialization

Status: Partial

Implemented:

- CLI entry and command bootstrap are in place.
- App setup, config loading, and TUI startup are in place.

Why not marked complete:

- The recent optimization stream did not include a dedicated initialization
  refactor or closeout campaign comparable to the tool/runtime work.

Key files:

- [`main.go`](/Users/newmba/SecOpsCode/crush-main/main.go)
- [`internal/cmd/root.go`](/Users/newmba/SecOpsCode/crush-main/internal/cmd/root.go)

### 2. Command System

Status: Partial

Implemented:

- The command layer is present and functional.

Why not marked complete:

- No distinct closeout workstream was completed here in the same sense as the
  capability registry and tool wiring work.

Key files:

- [`internal/cmd/root.go`](/Users/newmba/SecOpsCode/crush-main/internal/cmd/root.go)
- [`internal/cmd/`](/Users/newmba/SecOpsCode/crush-main/internal/cmd)

### 3. Tool System / Tool Calling

Status: Complete for the recent optimization scope

Implemented:

- Generic capability registry spec/build flow.
- Shared dataset rows for descriptor generation and runtime tool registration.
- Fixed toolset builders for built-in tool families.
- Cross-package consistency checks tying together tools, config, coordinator,
  and SecOps registry metadata.

Key files:

- [`internal/capability/registry/spec.go`](/Users/newmba/SecOpsCode/crush-main/internal/capability/registry/spec.go)
- [`internal/capability/registry/secops.go`](/Users/newmba/SecOpsCode/crush-main/internal/capability/registry/secops.go)
- [`internal/agent/tools/catalog.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/catalog.go)
- [`internal/agent/coordinator.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/coordinator.go)
- [`internal/agent/secops_adapter.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/secops_adapter.go)

### 4. Query Loop / Session Engine

Status: Partial

Implemented:

- Coordinator/session runtime is present and validated.
- AUTO/FAST/DEEP routing behavior and agent selection are implemented.

Why not marked complete:

- The closeout work did not comprehensively turn this area into a dedicated
  optimization/refactor stream.

Key files:

- [`internal/agent/coordinator.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/coordinator.go)
- [`internal/agent/agent.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/agent.go)

### 5. API and Model Invocation Layer

Status: Partial

Implemented:

- Provider config, model config, provider-aware options, and rate-limit
  behavior are present.

Why not marked complete:

- This area was validated, but it was not the center of the recent
  optimization effort.

Key files:

- [`internal/agent/coordinator.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/coordinator.go)
- [`internal/config/config.go`](/Users/newmba/SecOpsCode/crush-main/internal/config/config.go)

### 6. Terminal UI Layer

Status: Partial

Implemented:

- Header labels for `AUTO`, `OPS`, `SEC`, `CODE`.
- Mode-specific placeholder text.
- Pre-reply AUTO routing messages.

Why not marked complete:

- Manual acceptance remains outstanding, so this area is code-complete but not
  acceptance-complete.

Key files:

- [`internal/ui/model/header.go`](/Users/newmba/SecOpsCode/crush-main/internal/ui/model/header.go)
- [`internal/ui/model/ui.go`](/Users/newmba/SecOpsCode/crush-main/internal/ui/model/ui.go)
- [`MANUAL_TUI_ACCEPTANCE_2026-04-04.md`](/Users/newmba/SecOpsCode/crush-main/MANUAL_TUI_ACCEPTANCE_2026-04-04.md)

### 7. Extensions and Integrations

Status: Mostly complete

Implemented:

- MCP helper toolsets.
- LSP toolsets.
- SecOps runtime registration and permission/risk integration.
- Remote execution policy and audit integration.

Why not marked fully complete:

- The broad platform-extension space from `PROJECT_ANALYSIS.md` is larger than
  what this closeout stream explicitly optimized.

Key files:

- [`internal/agent/tools/mcp_toolset.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/mcp_toolset.go)
- [`internal/agent/tools/lsp_toolset.go`](/Users/newmba/SecOpsCode/crush-main/internal/agent/tools/lsp_toolset.go)
- [`internal/permission/secops_permission.go`](/Users/newmba/SecOpsCode/crush-main/internal/permission/secops_permission.go)
- [`internal/sandbox/executor.go`](/Users/newmba/SecOpsCode/crush-main/internal/sandbox/executor.go)

## Bottom Line

- If the question is whether the core optimization stream driven by the
  `PROJECT_ANALYSIS.md` architecture ideas is complete, the answer is:
  mostly yes for the tool/runtime governance path, and partially yes for UI.
- If the question is whether every architecture module listed in
  `PROJECT_ANALYSIS.md` was turned into a dedicated optimization plan and fully
  completed, the answer is no.
- The remaining work after this closeout is predominantly:
  - manual TUI acceptance,
  - packaging verification,
  - release-side signoff and record cleanup.
