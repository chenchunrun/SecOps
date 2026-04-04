# Validation Report (2026-03-25)

## Scope
- Key persistence across restart/reload.
- High-risk permission gate + bypass-intent audit alert.
- Audit persistence to file store + integration reconcile path.

## Commands Executed
```bash
cd /Users/newmba/Downloads/SecOpsCode/crush-main
GOCACHE=$(pwd)/.gocache go test ./internal/config ./internal/permission ./internal/audit ./internal/integration \
  -run 'TestConfigStore_SetProviderAPIKey_PersistsAcrossReload|TestPermissionService_HighRiskCannotBypassGuards|TestPermissionService_BypassIntentEmitsAuditAlert|TestFileAuditStore_PersistsAndReloads|TestConfigKeyPersistenceAndAuditSIEMReconcile_EndToEnd|TestPermissionRiskToolAuditSIEM_EndToEnd' \
  -count=1
```

## Results
- PASS: `internal/config` (key persistence coverage)
- PASS: `internal/permission` (high-risk no-bypass + bypass-intent audit alert)
- PASS: `internal/audit` (file store persist/reload)
- PASS: `internal/integration` (permission-risk-tool-audit-siem e2e + key persistence reconcile)

## Notes
- Running the integration subset inside strict sandbox failed due local test server port bind restriction (`httptest` listener permission).
- Re-running the exact same command with elevated permissions succeeded fully.

## Evidence Summary
- No failed tests in the targeted security/reliability validation subset.
- Current branch head during validation: `b29c886`.

## Next Suggested Gate
1. Add agent mode switching regression test (`ops -> security -> ops`) to prevent recurrence.
2. Run full `go test ./... -count=1` as pre-release gate.
3. Build artifacts smoke check in both light/dark terminal themes.

## Full Regression Gate
- Command:
```bash
cd /Users/newmba/Downloads/SecOpsCode/crush-main
GOCACHE=$(pwd)/.gocache go test ./... -count=1
```
- Result: PASS (full repo test suite)
- Notable long suites:
  - `internal/agent/tools/secops` ~139s
  - `internal/audit` ~56s
  - `internal/sandbox` ~23s

## Additional Hardening in This Iteration
- Avoid duplicate upstream requests when `fast` gets 429 and fast/deep resolve to same provider+model.
- Added explicit unit coverage:
  - `TestSameProviderModel`
  - `TestShouldFallbackToDeepOnRateLimit`

## Key Persistence Regression (Master Key File)
- New test: `TestEncryptDecrypt_UsesMasterKeyFileAcrossIdentityChanges`
- File: `internal/config/load_test.go`
- Coverage:
  - Creates and reuses `secrets.key`
  - Verifies decrypt still works after `USER/LOGNAME` change (restart-like identity drift)
  - Verifies key file permissions (non-Windows)
- Result: PASS
