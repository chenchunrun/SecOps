#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
GOOS_VAL="${GOOS:-$(go env GOOS)}"
GOARCH_VAL="${GOARCH:-$(go env GOARCH)}"
PKG_NAME="crush-secops-${VERSION}-${GOOS_VAL}-${GOARCH_VAL}"
WORK_DIR="${ROOT_DIR}/dist/${PKG_NAME}"
ARCHIVE_PATH="${ROOT_DIR}/dist/${PKG_NAME}.tar.gz"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

echo "[1/4] Building binary..."
CGO_ENABLED=0 GOOS="$GOOS_VAL" GOARCH="$GOARCH_VAL" \
  go build -ldflags "-X github.com/chenchunrun/SecOps/internal/version.Version=${VERSION}" \
  -o "$WORK_DIR/crush" .

cat > "$WORK_DIR/install.sh" <<'INSTALL'
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC="${SCRIPT_DIR}/crush"

if [[ ! -x "$BIN_SRC" ]]; then
  echo "Error: crush binary not found in package directory: $BIN_SRC" >&2
  exit 1
fi

TARGET_DIR="${CRUSH_INSTALL_DIR:-}"
if [[ -z "$TARGET_DIR" ]]; then
  if [[ -w "/usr/local/bin" ]]; then
    TARGET_DIR="/usr/local/bin"
  else
    TARGET_DIR="$HOME/.local/bin"
  fi
fi

mkdir -p "$TARGET_DIR"
install -m 0755 "$BIN_SRC" "$TARGET_DIR/crush"

echo "Installed: $TARGET_DIR/crush"
if ! command -v crush >/dev/null 2>&1 || [[ "$(command -v crush)" != "$TARGET_DIR/crush" ]]; then
  echo "If command not found, add to PATH:"
  echo "  export PATH=\"$TARGET_DIR:\$PATH\""
fi

echo "Run: crush"
INSTALL

cat > "$WORK_DIR/uninstall.sh" <<'UNINSTALL'
#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${CRUSH_INSTALL_DIR:-}"
if [[ -z "$TARGET_DIR" ]]; then
  if [[ -e "/usr/local/bin/crush" ]]; then
    TARGET_DIR="/usr/local/bin"
  else
    TARGET_DIR="$HOME/.local/bin"
  fi
fi

if [[ -e "$TARGET_DIR/crush" ]]; then
  rm -f "$TARGET_DIR/crush"
  echo "Removed: $TARGET_DIR/crush"
else
  echo "Not found: $TARGET_DIR/crush"
fi
UNINSTALL

cat > "$WORK_DIR/INSTALL.md" <<'DOC'
# Crush SecOps One-Click Install

## Quick Start

```bash
chmod +x install.sh
./install.sh
```

## Custom Install Path

```bash
CRUSH_INSTALL_DIR="$HOME/bin" ./install.sh
```

## Uninstall

```bash
chmod +x uninstall.sh
./uninstall.sh
```
DOC

chmod +x "$WORK_DIR/install.sh" "$WORK_DIR/uninstall.sh"

echo "[2/4] Writing checksums..."
(
  cd "$WORK_DIR"
  shasum -a 256 crush > crush.sha256
)

echo "[3/4] Creating archive..."
rm -f "$ARCHIVE_PATH"
tar -C "${ROOT_DIR}/dist" -czf "$ARCHIVE_PATH" "$PKG_NAME"

echo "[4/4] Writing archive checksum..."
shasum -a 256 "$ARCHIVE_PATH" > "${ARCHIVE_PATH}.sha256"

echo "Done."
echo "Package:  $ARCHIVE_PATH"
echo "Checksum: ${ARCHIVE_PATH}.sha256"
