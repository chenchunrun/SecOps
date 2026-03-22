# SecOps DoD Matrix and Test Mapping

This document is the Definition of Done baseline for SecOps delivery.
Each capability must have code path, test mapping, and regression gate.

## Capability Matrix

| Domain | Capability | Key Code Path | Test Mapping | DoD Gate |
|---|---|---|---|---|
| Tools availability | 18 SecOps tools default callable | `internal/config/config.go`, `internal/agent/coordinator.go`, `internal/agent/secops_adapter.go` | `internal/agent/secops_adapter_test.go`, `internal/integration/secops_integration_test.go` | New session can invoke all registered SecOps tools without manual allowlist patching |
| Permission & capability | `RequiredCapabilities` enforced | `internal/agent/secops_adapter.go` | `internal/agent/secops_adapter_test.go` | Missing capability blocks execution with explicit reason |
| Risk decision | 5-factor risk linked to decision chain | `internal/agent/secops_adapter.go`, `internal/permission/secops_permission.go`, `internal/security/risk_assessment.go` | `internal/integration/secops_integration_test.go` | high risk must be blocked/reviewed/confirmed and auditable |
| Security scan | Real scanner path + parse | `internal/agent/tools/secops/security_scan.go` | `internal/agent/tools/secops/security_scan_test.go` | At least one real execution path with retry/error handling |
| Monitoring query | Real API query path | `internal/agent/tools/secops/monitoring_query.go` | `internal/agent/tools/secops/monitoring_query_test.go` | Provider response parsed into series/points with errors surfaced |
| Log analyze | Real file collection + parse/filter | `internal/agent/tools/secops/log_analyze.go` | `internal/agent/tools/secops/log_analyze_test.go` | duration/min_level/offset/limit all effective |
| Compliance check | Framework rules evaluated | `internal/agent/tools/secops/compliance_check.go` | `internal/agent/tools/secops/compliance_check_test.go` | Rule status/evidence/remediation deterministic and auditable |
| Certificate audit | Real cert parse/collect/chain checks | `internal/agent/tools/secops/certificate_audit.go` | `internal/agent/tools/secops/certificate_audit_test.go` | PEM/DER parsing works; weak/expiry checks valid |
| Config audit | Real SSH/sudo/firewall/sysctl checks | `internal/agent/tools/secops/configuration_audit.go` | `internal/agent/tools/secops/configuration_audit_test.go` | read-failure degrades to warning, not silent pass |
| Network diagnostic | Real traceroute/mtr/dns/scan/ping paths | `internal/agent/tools/secops/network_diagnostic.go` | `internal/agent/tools/secops/network_diagnostic_test.go` | No hardcoded mock fallback in production path |
| Infra query | Terraform/K8s real query paths | `internal/agent/tools/secops/infrastructure_query.go` | `internal/agent/tools/secops/infra_tools_test.go` | Real-source preferred; empty env handled safely |
| Deployment status | K8s rollout/events live query path | `internal/agent/tools/secops/deployment_status.go` | `internal/agent/tools/secops/infra_tools_test.go` | health/replica/rollout result integrity |
| Alert check | Real endpoint query path + normalization | `internal/agent/tools/secops/alert_check.go` | `internal/agent/tools/secops/infra_tools_test.go` | Status/severity normalization stable |
| Incident timeline | Input events can build timeline | `internal/agent/tools/secops/incident_timeline.go` | `internal/agent/tools/secops/infra_tools_test.go` | Event ordering/duration/status consistent |
| Sandbox | local/docker/ssh policy and risk | `internal/sandbox/executor.go` | `internal/sandbox/executor_test.go` | dangerous commands blocked, logs complete |
| Audit store/report | persistent fields and compliance report | `internal/audit/audit_store.go`, `internal/audit/compliance_report.go` | `internal/audit/audit_store_test.go`, `internal/audit/compliance_report_test.go` | risk and event stats match source events |
| SIEM export | TLS required + redaction + retries | `internal/audit/siem_export.go` | `internal/audit/siem_export_test.go` | 5xx retry, credentials redacted, TLS enforced |
| Integration | permission-risk-tool-audit chain | `internal/integration/secops_integration_test.go` | `go test ./internal/integration -count=1` | end-to-end path passes on clean workspace |

## Regression Gates

- Fast gate:
  - `go test ./internal/agent/tools/secops -count=1`
  - `go test ./internal/integration -count=1`
- Safety gate:
  - `go test ./internal/sandbox ./internal/audit -count=1`
- Build gate:
  - `go build -o crush .`
- Full gate:
  - `go test ./...`

## Release DoD Checklist

- [x] 18 tools pass tool-level tests and integration tests.
- [x] No production fallback to hardcoded mock data on critical path.
- [x] Risk decisions are auditable with reasons.
- [x] SIEM exports redact secrets and enforce TLS.
- [x] Sandbox logs include command, mode, result, risk.
- [x] Config persistence and restart behavior validated by test.
- [x] Full gate `go test ./...` passes before release tag.

## Verification Evidence

- Tools/capabilities/risk chain:
  - `internal/agent/secops_adapter_test.go`
  - `internal/integration/secops_integration_test.go:551` (`TestPermissionRiskToolAuditSIEM_EndToEnd`)
- Config key persistence + restart + SIEM reconciliation:
  - `internal/config/load_test.go:82` (`TestConfigStore_SetProviderAPIKey_PersistsAcrossReload`)
  - `internal/integration/secops_integration_test.go:666` (`TestConfigKeyPersistenceAndAuditSIEMReconcile_EndToEnd`)
- SIEM TLS + redaction + retries:
  - `internal/audit/siem_export_test.go`
- Full regression gate:
  - `go test ./... -count=1` (latest run passed)

## Remaining Non-Blocking Debt

- Some test comments still mention “mock” wording (historical text) in:
  - `internal/agent/tools/secops/compliance_check_test.go`
  - `internal/agent/tools/secops/infra_tools_test.go`
- This is documentation/comment debt only and does not indicate runtime mock paths.
