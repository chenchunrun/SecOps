#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

: "${GOCACHE:=$ROOT_DIR/.gocache}"

echo "== SecOps Reasoning Demo =="
echo "Workspace: $ROOT_DIR"
echo "GOCACHE:   $GOCACHE"
echo

echo "-- 1. ATT&CK reasoning tools --"
go test ./internal/agent/tools/secops \
  -run 'TestAttackReasonTool|TestIncidentAssessTool' \
  -count=1
echo

echo "-- 2. SecurityExpertAgent runtime workflow selection --"
go test ./internal/agent \
  -run 'TestSecurityExpertAgent_ProcessTask_ThreatAssessment|TestSecurityExpertAgent_ProcessTask_IncidentResponse|TestAgentResponse_RenderSecurityAssessment' \
  -count=1
echo

echo "-- 3. TUI SecOps renderer and session flow --"
go test ./internal/ui/chat \
  -run 'TestSummarizeIncidentAssessResult|TestSummarizeAttackReasonResult|TestNewToolMessageItem_UsesSecOpsRenderer|TestExtractMessageItems_SecOpsToolSessionFlow' \
  -count=1
echo

echo "-- 4. End-to-end security incident integration --"
go test ./internal/integration \
  -run 'TestSecuritySystemIntegration_IncidentResponse' \
  -count=1
echo

echo "Demo complete."
echo "This run validates: incident_assess -> attack_reason -> SecurityExpertAgent -> TUI renderer."
