#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
TARGETS="${TARGETS:-darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64 windows/arm64}"
DIST_DIR="${ROOT_DIR}/dist"

mkdir -p "$DIST_DIR"

echo "Version: $VERSION"
echo "Targets: $TARGETS"

for target in $TARGETS; do
  goos="${target%%/*}"
  goarch="${target##*/}"
  pkg_name="crush-secops-${VERSION}-${goos}-${goarch}"
  work_dir="${DIST_DIR}/${pkg_name}"

  rm -rf "$work_dir"
  mkdir -p "$work_dir"

  if [[ "$goos" == "windows" ]]; then
    bin_name="crush.exe"
  else
    bin_name="crush"
  fi

  echo "[build] ${goos}/${goarch}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -ldflags "-X github.com/chenchunrun/SecOps/internal/version.Version=${VERSION}" \
    -o "$work_dir/$bin_name" .

  if command -v shasum >/dev/null 2>&1; then
    (cd "$work_dir" && shasum -a 256 "$bin_name" > "${bin_name}.sha256")
  elif command -v sha256sum >/dev/null 2>&1; then
    (cd "$work_dir" && sha256sum "$bin_name" > "${bin_name}.sha256")
  fi

  if [[ "$goos" == "windows" ]]; then
    cat > "$work_dir/install.ps1" <<'PS1'
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BinSrc = Join-Path $ScriptDir "crush.exe"
if (-not (Test-Path $BinSrc)) {
  throw "crush.exe not found in package directory: $BinSrc"
}

$TargetDir = $env:CRUSH_INSTALL_DIR
if ([string]::IsNullOrWhiteSpace($TargetDir)) {
  $TargetDir = Join-Path $env:LOCALAPPDATA "Programs\crush-secops"
}

New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
Copy-Item $BinSrc (Join-Path $TargetDir "crush.exe") -Force
Write-Host "Installed: $(Join-Path $TargetDir 'crush.exe')"

$currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentUserPath -notlike "*$TargetDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$currentUserPath;$TargetDir", "User")
  Write-Host "Added to user PATH: $TargetDir"
  Write-Host "Please open a new terminal, then run: crush"
} else {
  Write-Host "Run: crush"
}
PS1

    cat > "$work_dir/uninstall.ps1" <<'PS1'
$ErrorActionPreference = "Stop"

$TargetDir = $env:CRUSH_INSTALL_DIR
if ([string]::IsNullOrWhiteSpace($TargetDir)) {
  $TargetDir = Join-Path $env:LOCALAPPDATA "Programs\crush-secops"
}

$BinPath = Join-Path $TargetDir "crush.exe"
if (Test-Path $BinPath) {
  Remove-Item $BinPath -Force
  Write-Host "Removed: $BinPath"
} else {
  Write-Host "Not found: $BinPath"
}
PS1

    cat > "$work_dir/INSTALL.md" <<'DOC'
# Crush SecOps One-Click Install (Windows)

## Install

```powershell
Set-ExecutionPolicy -Scope Process Bypass
./install.ps1
```

## Custom install path

```powershell
$env:CRUSH_INSTALL_DIR="$HOME\\bin"
./install.ps1
```

## Uninstall

```powershell
./uninstall.ps1
```
DOC

    archive_path="${DIST_DIR}/${pkg_name}.zip"
    rm -f "$archive_path"
    (
      cd "$DIST_DIR"
      ditto -c -k --sequesterRsrc --keepParent "$pkg_name" "${pkg_name}.zip"
    )
  else
    cat > "$work_dir/install.sh" <<'SH'
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
SH

    cat > "$work_dir/uninstall.sh" <<'SH'
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
SH

    cat > "$work_dir/INSTALL.md" <<'DOC'
# Crush SecOps One-Click Install (macOS / Linux)

## Install

```bash
chmod +x install.sh
./install.sh
```

## Custom install path

```bash
CRUSH_INSTALL_DIR="$HOME/bin" ./install.sh
```

## Uninstall

```bash
chmod +x uninstall.sh
./uninstall.sh
```
DOC

    chmod +x "$work_dir/install.sh" "$work_dir/uninstall.sh"

    archive_path="${DIST_DIR}/${pkg_name}.tar.gz"
    rm -f "$archive_path"
    tar -C "$DIST_DIR" -czf "$archive_path" "$pkg_name"
  fi

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$archive_path" > "${archive_path}.sha256"
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$archive_path" > "${archive_path}.sha256"
  fi

  echo "[done] ${archive_path}"
done

echo "All packages generated in: $DIST_DIR"
