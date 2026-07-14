# SecOps Closeout Gap Plan 2026-07-10

## Scope

This closeout plan tracks the specific gaps found while rechecking `SECOPS_PROJECT_PLAN.md`.

## Gap Plan

| Gap | TDD Target | Status |
| --- | --- | --- |
| Azure Sentinel SIEM export was listed in Phase 4 but only ELK/Splunk were implemented. | Add exporter tests for HTTPS, bearer auth, JSON payload, redaction, and TLS enforcement before implementation. | Completed in `internal/audit/siem_export_test.go` and `internal/audit/siem_export.go`. |
| PDF compliance report export was listed in Phase 4 but no PDF emitter was present. | Add report export test for `%PDF` header, title, report ID, status, and EOF before implementation. | Completed in `internal/audit/compliance_report_test.go` and `internal/audit/compliance_report.go`. |
| Phase 6 release evidence was not locally visible. | Create a local closeout artifact that records what is code-complete and what still requires an external GitHub release action. | This document. |

## CI Closure 2026-07-14

The final cross-platform CI stabilization commit is `86c91a3599e35fe36026bf9239dd2426b9e0bf0a` (`test: support Windows Azure CLI stubs`). The associated GitHub Actions workflows all passed:

- [Build](https://github.com/chenchunrun/SecOps/actions/runs/29317847409)
- [Security](https://github.com/chenchunrun/SecOps/actions/runs/29317847234)
- [Lint](https://github.com/chenchunrun/SecOps/actions/runs/29317847872)
- [Snapshot](https://github.com/chenchunrun/SecOps/actions/runs/29317847226)

The stabilization work made POSIX-only test helpers portable, skipped Linux-specific `/proc` assertions outside Linux, serialized concurrent database migrations, accepted the Windows `sh.exe` executable form, and restored compatible Bubble Tea and Ultraviolet dependency versions.

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
