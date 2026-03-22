# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build all packages
go build ./...

# Run all tests (China proxy)
GOPROXY=https://goproxy.cn,direct go test ./...

# Run tests for a specific package
go test ./internal/security/...

# Run integration tests
go test ./internal/integration/...

# Run benchmarks
go test -bench=. ./internal/sandbox/...
```

**Proxy note:** Use `GOPROXY=https://goproxy.cn,direct` when `proxy.golang.org` times out (common in China).

## Architecture Overview

Crush is a terminal-based AI coding assistant built on the Charm ecosystem. It uses a multi-agent architecture with a `Coordinator` that orchestrates specialized agents and tools.

### Agent System (`internal/agent/`)
- `agent.go` — Core `SessionAgent` and `sessionAgent` types
- `coordinator.go` — `Coordinator` that builds tools and delegates to agents
- `prompts.go` — System prompt generation for agents
- `agent_tool.go` — Built-in `agent` tool (sub-agent invocation)
- `agentic_fetch_tool.go` — Web fetch/analysis tool
- `secops_adapter.go` — Integrates SecOps tools as `fantasy.AgentTool`
- `templates/` — Agent system prompt templates (`ops_agent.md.tpl`, `security_expert_agent.md.tpl`)

### SecOps Tools (`internal/agent/tools/secops/`)
Tools live in the `secops` subpackage to avoid naming collisions with `mcp-tools.go`'s `type Tool = mcp.Tool`.

All SecOps tools implement the `SecOpsTool` interface:
```go
type SecOpsTool interface {
    Type() ToolType
    Name() string
    Description() string
    RequiredCapabilities() []string
    Execute(params interface{}) (interface{}, error)
    ValidateParams(params interface{}) error
}
```

**Tool registry:** `NewToolRegistry()` returns `*SecOpsToolRegistry`.

Available tools:
| Tool | Type Constant | Purpose |
|------|--------------|---------|
| Log Analyze | `ToolTypeLogAnalyze` | Query logs with regex/keyword/aggregation |
| Monitoring Query | `ToolTypeMonitoringQuery` | Prometheus, Grafana, DataDog, InfluxDB |
| Compliance Check | `ToolTypeComplianceCheck` | CIS, PCI-DSS, SOC2, HIPAA |
| Certificate Audit | `ToolTypeCertificateAudit` | TLS certificate expiry and config |
| Security Scan | `ToolTypeSecurityScan` | Trivy, Grype, Nuclei, ClamAV |
| Configuration Audit | `ToolTypeConfigurationAudit` | System/service configs |
| Network Diagnostic | `ToolTypeNetworkDiagnostic` | ping, traceroute, DNS, port scan |
| Database Query | `ToolTypeDatabaseQuery` | Read-only DB queries |
| Backup Check | `ToolTypeBackupCheck` | Backup status |
| Replication Status | `ToolTypeReplicationStatus` | DB replication monitoring |
| Secret Audit | `ToolTypeSecretAudit` | Credential/API key scanning |
| Rotation Check | `ToolTypeRotationCheck` | Key/cert rotation status |
| Access Review | `ToolTypeAccessReview` | IAM access audit |
| Infrastructure Query | `ToolTypeInfrastructureQuery` | Terraform, Kubernetes, Cloud |
| Deployment Status | `ToolTypeDeploymentStatus` | Deployment health |
| Alert Check | `ToolTypeAlertCheck` | Prometheus, Grafana, DataDog, PagerDuty |
| Incident Timeline | `ToolTypeIncidentTimeline` | Incident timeline generation |
| Resource Monitor | `ToolTypeResourceMonitor` | CPU, memory, disk, network |

### Security (`internal/security/`)
- `capability.go` — Capability-based access control (viewer/operator/admin roles)
- `risk_assessment.go` — 5-factor risk scoring engine (banned commands, sensitive paths, credentials, system mods, network ops); block≥80, admin review≥60, user confirm≥40

### Audit (`internal/audit/`)
- `audit.go` — Core audit event model with full compliance/change/approval fields
- `audit_store.go` — `InMemoryAuditStore` implementation
- `compliance_report.go` — Report generator for SOC2, PCI-DSS, HIPAA, ISO 27001
- `siem_export.go` — ELKExporter (NDJSON bulk), SplunkExporter (HEC JSON); 3x retry with exponential backoff

### Sandbox (`internal/sandbox/`)
- `executor.go` — Sandboxed command execution (Local/Docker/SSH modes); cgroups/seccomp support
- `security.go` — Command filtering based on risk scoring

### Permission (`internal/permission/`)
- `permission.go` — Core `PermissionRequest`, `PermissionDecision`, `Severity`, `ResourceType` types; `Service` interface
- `secops_permission.go` — `SecOpsService` implementation with risk-based decision engine
- Extended `PermissionRequest` struct includes: `RiskScore`, `Severity`, `Decision`, `ResourceType`, `ResourcePath`, `UserID`, `Username`, `RiskFactors`, etc.

## SecOps 3-Layer Architecture

1. **Isolation execution layer** (`internal/sandbox/`) — Sandboxed command execution
2. **Security judgment layer** (`internal/security/`) — Risk scoring and capability checks
3. **Intelligent decision layer** (`internal/agent/`) — Agent orchestration with SecOps tools

## Package Layout Notes

- `Tool` and `ToolRegistry` names collide with `internal/agent/tools/mcp-tools.go`. SecOps tools **must** use the `secops` subpackage with renamed types (`SecOpsTool`, `SecOpsToolRegistry`).
- `Severity`, `PermissionDecision`, `PermissionLevel`, `ResourceType` are defined once in `permission/permission.go` — do not duplicate in `secops_permission.go`.
- Integration tests are in `internal/integration/secops_integration_test.go`.

## Key File Locations

- Agent prompts: `internal/agent/templates/ops_agent.md.tpl`, `security_expert_agent.md.tpl`
- Tool registry: `internal/agent/tools/secops/tool.go`
- Risk assessor: `internal/security/risk_assessment.go`
- SIEM export: `internal/audit/siem_export.go`
- Capability definitions: `internal/security/capability.go`
