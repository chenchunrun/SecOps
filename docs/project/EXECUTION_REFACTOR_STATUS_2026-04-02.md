# Execution Refactor Status

Date: 2026-04-02

## Scope

This document summarizes the current state of the phase-2 execution-layer
refactor in `SecOps`.

It focuses on:

- what has already moved out of tool code
- what still remains in tool code
- the current middleware chain
- validated behavior and known residual gaps

## Current Architecture

### Execution package

The execution-layer work now lives in:

- `internal/execution/types.go`
- `internal/execution/local.go`
- `internal/execution/remote.go`
- `internal/execution/middleware.go`
- `internal/execution/output.go`

### Local execution chain

The local execution path is now:

`policy -> audit -> error classification -> base`

Concretely:

- `PolicyLocalMiddleware`
- `AuditLocalMiddleware`
- `ErrorClassificationMiddleware`
- local shell/background execution base

### Remote execution chain

The remote execution path is now:

`policy -> audit -> base`

Concretely:

- `PolicyRemoteMiddleware`
- `AuditRemoteMiddleware`
- SSH execution base

## What Has Moved Into Execution

### 1. Local command execution

Moved out of `bash` tool code:

- local synchronous execution
- local background execution
- auto-background threshold handling
- local execution error classification
- local execution audit start/completion
- local policy deny enforcement

### 2. Remote SSH execution

Moved out of `bash` tool code:

- SSH command invocation
- remote execution output formatting
- remote execution audit start/completion
- remote policy deny enforcement

### 3. Shared execution concerns

Now handled in `internal/execution`:

- middleware composition
- normalized output formatting
- local error kinds
- remote/local audit insertion points

## What Still Remains In Tool Layer

### `internal/agent/tools/bash.go`

Still intentionally remains here:

- request parsing and tool schema
- remote profile expansion
- safe read-only heuristic
- call to `policy.Decider`
- permission request UX flow
- response metadata shaping for Fantasy tool responses

This is still acceptable for the current phase.

The major rule is now:

- tools decide *what request to make*
- execution decides *how to execute and how to apply execution middleware*

## Policy Boundary

The current state is intentionally split:

- `policy.Decider` still computes the decision
- execution middleware now enforces that decision on local and remote paths
- permission prompts are still initiated from the tool layer

This means the system is not yet at a fully unified pre-execution gate.

In particular:

- local/remote deny enforcement is now in execution
- approval prompting is still in `bash`

That split is deliberate for now, to avoid collapsing user-facing permission
flow and execution refactor into one risky change.

## Audit Boundary

Execution middleware now records:

- `command_started`
- `command_executed`
- `command_failed`

Important correction in this iteration:

- start events are no longer recorded as successful executions
- this avoids false success counts in compliance/reporting

## Validated Commands

Validated repeatedly during this refactor stream:

```bash
cd /Users/newmba/SecOpsCode/crush-main
GOCACHE=$(pwd)/.gocache GOMODCACHE=$(pwd)/.gomodcache \
  go test ./internal/execution ./internal/agent/tools ./internal/agent ./internal/app -count=1

cd /Users/newmba/SecOpsCode/crush-main
GOCACHE=$(pwd)/.gocache GOMODCACHE=$(pwd)/.gomodcache go build ./...
```

Latest validation result:

- PASS: `internal/execution`
- PASS: `internal/agent/tools`
- PASS: `internal/agent`
- PASS: `internal/app`
- PASS: `go build ./...`

## Key Commits In This Refactor Segment

- `e9370aa` `refactor: introduce policy, capability registry, and turn orchestrator`
- `360a296` `refactor: extract local command execution`
- `b38d655` `refactor: add execution middleware and error classification`
- `415cf73` `refactor: add execution audit middleware`
- `d659dd5` `refactor: add execution policy middleware`
- `02d76ae` `refactor: extract remote ssh execution`
- `652e1d2` `refactor: add remote execution audit middleware`
- `c2e6f5e` `refactor: add remote execution policy middleware`
- `1360657` `fix: restore deny ordering and neutral audit start events`

## Residual Gaps

These are the main remaining gaps before execution refactor can be considered
"structurally settled":

1. Permission prompting is still owned by tool code, not execution middleware.
2. Error classification exists only for local execution; remote execution does
   not yet have equivalent typed error mapping.
3. The execution package still depends on `policy.Decision` as an input type,
   rather than a thinner execution-specific decision contract.
4. There is still duplication between tool-level request shaping and
   execution-level request structs.

## Recommended Next Step

Do not immediately push permission prompting into execution.

The safer next move is:

1. Introduce remote error classification, so local and remote execution expose
   comparable failure signals.
2. Add a small architecture note or interface cleanup that reduces direct
   coupling from `execution` to `policy.Decision`.
3. Only then evaluate whether permission request flow should move downward.

## Bottom Line

The execution refactor is now in a materially better state than the original
tool-centric implementation:

- execution mechanics are separated from tool response shaping
- policy deny enforcement is in execution for both local and remote paths
- audit insertion points are now centralized
- local and remote execution each have explicit abstraction boundaries

The refactor is not fully complete, but it is now structured enough to extend
without reintroducing the original coupling.
