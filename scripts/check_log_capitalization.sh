#!/bin/bash
if grep -rE 'slog\.(Error|Info|Warn|Debug|Fatal|Print|Println|Printf)\(["\"][a-z]' \
  --include="*.go" \
  --exclude-dir=.git \
  --exclude-dir=.gocache \
  --exclude-dir=.gomodcache \
  --exclude-dir=dist \
  . 2>/dev/null; then
  echo "❌ Log messages must start with a capital letter. Found lowercase logs above."
  exit 1
fi
