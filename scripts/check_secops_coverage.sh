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
