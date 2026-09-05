#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MINIMUM="${COVERAGE_MINIMUM:-80.0}"
PROFILE="${COVERAGE_FILE:-$ROOT_DIR/coverage-secops.out}"

packages=(
  ./internal/quality
  ./internal/taskruntime
  ./internal/evidence
  ./internal/security/attack
)

go test "${packages[@]}" -coverprofile="$PROFILE" -count=1

total="$({ go tool cover -func="$PROFILE" || true; } | awk '/^total:/ {gsub(/%/, "", $3); print $3}')"
if [[ -z "$total" ]]; then
  echo "Unable to determine SecOps control-plane coverage" >&2
  exit 1
fi

echo "SecOps control-plane coverage: ${total}% (minimum: ${MINIMUM}%)"
awk -v actual="$total" -v minimum="$MINIMUM" 'BEGIN { exit !(actual + 0 >= minimum + 0) }' || {
  echo "Coverage gate failed: ${total}% is below ${MINIMUM}%" >&2
  exit 1
}

# Independent floors prevent a large well-tested package masking a weak gate.
# New adapters start at a measured baseline and should ratchet upward.
guarded_packages=(
  ./internal/security ./internal/permission ./internal/skills
  ./internal/connectors ./internal/investigation/scan
  ./internal/agent/tools/secops ./internal/audit ./internal/sandbox
)
guarded_profile="${PROFILE%.out}-guarded.out"
go test "${guarded_packages[@]}" -coverprofile="$guarded_profile" -count=1
awk '
BEGIN {
  floor["internal/security"]=75
  floor["internal/permission"]=80
  floor["internal/skills"]=80
  floor["internal/connectors"]=70
  floor["internal/investigation/scan"]=70
  floor["internal/agent/tools/secops"]=80
  floor["internal/audit"]=75
  floor["internal/sandbox"]=70
}
NR > 1 {
  package=$1
  sub(/^github.com\/chenchunrun\/SecOps\//,"",package)
  sub("/[^/]+$","",package)
  statements[package]+=$2
  if ($3 > 0) covered[package]+=$2
}
END {
  failed=0
  for (package in floor) {
    actual=statements[package] ? 100*covered[package]/statements[package] : 0
    printf "%s: %.1f%% (minimum %.1f%%)\n", package, actual, floor[package]
    if (actual < floor[package]) failed=1
  }
  exit failed
}' "$guarded_profile"
