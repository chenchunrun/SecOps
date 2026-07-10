# SecOps Closeout Gap Plan 2026-07-10

## Scope

This closeout plan tracks the specific gaps found while rechecking `SECOPS_PROJECT_PLAN.md`.

## Gap Plan

| Gap | TDD Target | Status |
| --- | --- | --- |
| Azure Sentinel SIEM export was listed in Phase 4 but only ELK/Splunk were implemented. | Add exporter tests for HTTPS, bearer auth, JSON payload, redaction, and TLS enforcement before implementation. | Completed in `internal/audit/siem_export_test.go` and `internal/audit/siem_export.go`. |
| PDF compliance report export was listed in Phase 4 but no PDF emitter was present. | Add report export test for `%PDF` header, title, report ID, status, and EOF before implementation. | Completed in `internal/audit/compliance_report_test.go` and `internal/audit/compliance_report.go`. |
| Phase 6 release evidence was not locally visible. | Create a local closeout artifact that records what is code-complete and what still requires an external GitHub release action. | This document. |

## Remaining External Release Work

The codebase now contains local coverage for the previously missing Phase 4 implementation items. The Phase 6 GitHub Release item still requires an external release operation outside this repository state:

- Tag the intended release commit.
- Publish the GitHub Release.
- Attach or link test evidence from the release run.
- Record the release URL in the project documentation.

## Suggested Verification Commands

```bash
go test ./internal/audit ./internal/bootstrap ./internal/config -count=1
go test ./internal/agent/tools/secops ./internal/integration -count=1
go test ./... -count=1
```
