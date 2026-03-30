#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

if [[ "${SKIP_FULL:-0}" != "1" ]]; then
  FULL_LABEL="enabled"
else
  FULL_LABEL="skipped"
fi

echo "SecOps release validation"
echo "root: $ROOT_DIR"
echo "gocache: $GOCACHE"
echo "full-suite: $FULL_LABEL"
echo

echo "[1/4] Focused security and reliability subset"
go test ./internal/config ./internal/permission ./internal/audit ./internal/integration \
  -run 'TestConfigStore_SetProviderAPIKey_PersistsAcrossReload|TestPermissionService_HighRiskCannotBypassGuards|TestPermissionService_BypassIntentEmitsAuditAlert|TestFileAuditStore_PersistsAndReloads|TestConfigKeyPersistenceAndAuditSIEMReconcile_EndToEnd|TestPermissionRiskToolAuditSIEM_EndToEnd' \
  -count=1
echo

echo "[2/4] SecOps tools regression suite"
go test ./internal/agent/tools/secops -count=1
echo

echo "[3/4] Integration regression suite"
go test ./internal/integration -count=1
echo

echo "[4/4] Full repository regression suite"
if [[ "${SKIP_FULL:-0}" == "1" ]]; then
  echo "Skipped because SKIP_FULL=1"
else
  go test ./... -count=1
fi
echo

echo "Validation completed."
