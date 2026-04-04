#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
PRODUCT_NAME="${PRODUCT_NAME:-SecOps}"
TARGETS="${TARGETS:-darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64 windows/arm64}"
DIST_DIR="${ROOT_DIR}/dist"

mkdir -p "$DIST_DIR"

echo "Version: $VERSION"
echo "Product: $PRODUCT_NAME"
echo "Targets: $TARGETS"

for target in $TARGETS; do
  goos="${target%%/*}"
  goarch="${target##*/}"
  os_label="$goos"
  if [[ "$goos" == "darwin" ]]; then
    os_label="macos"
  fi
  pkg_name="${PRODUCT_NAME}-${VERSION}-${os_label}-${goarch}"
  work_dir="${DIST_DIR}/${pkg_name}"

  rm -rf "$work_dir"
  mkdir -p "$work_dir"

  echo "[build] ${goos}/${goarch}"
  if [[ "$goos" == "windows" ]]; then
    primary_bin="secops-agent.exe"
    compat_bin="crush.exe"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      go build -ldflags "-X github.com/chenchunrun/SecOps/internal/version.Version=${VERSION}" \
      -o "$work_dir/$primary_bin" .
    cp "$work_dir/$primary_bin" "$work_dir/$compat_bin"
  else
    primary_bin="SecOps"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      go build -ldflags "-X github.com/chenchunrun/SecOps/internal/version.Version=${VERSION}" \
      -o "$work_dir/$primary_bin" .
  fi

  if command -v shasum >/dev/null 2>&1; then
    (
      cd "$work_dir"
      shasum -a 256 "$primary_bin" > "${primary_bin}.sha256"
      if [[ "$goos" == "windows" ]]; then
        shasum -a 256 "$compat_bin" > "${compat_bin}.sha256"
      fi
    )
  elif command -v sha256sum >/dev/null 2>&1; then
    (
      cd "$work_dir"
      sha256sum "$primary_bin" > "${primary_bin}.sha256"
      if [[ "$goos" == "windows" ]]; then
        sha256sum "$compat_bin" > "${compat_bin}.sha256"
      fi
    )
  fi

  if [[ "$goos" == "windows" ]]; then
    cat > "$work_dir/install.ps1" <<'PS1'
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PrimaryName = "secops-agent.exe"
$CompatName = "crush.exe"
$BinSrc = Join-Path $ScriptDir $PrimaryName
if (-not (Test-Path $BinSrc)) {
  throw "$PrimaryName not found in package directory: $BinSrc"
}
$CompatSrc = Join-Path $ScriptDir $CompatName
if (-not (Test-Path $CompatSrc)) {
  throw "$CompatName not found in package directory: $CompatSrc"
}

$TargetDir = $env:CRUSH_INSTALL_DIR
if ([string]::IsNullOrWhiteSpace($TargetDir)) {
  $TargetDir = Join-Path $env:LOCALAPPDATA "Programs\SecOps"
}

New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
Copy-Item $BinSrc (Join-Path $TargetDir $PrimaryName) -Force
Copy-Item $CompatSrc (Join-Path $TargetDir $CompatName) -Force
Write-Host "Installed: $(Join-Path $TargetDir $PrimaryName)"
Write-Host "Installed: $(Join-Path $TargetDir $CompatName)"

$currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentUserPath -notlike "*$TargetDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$currentUserPath;$TargetDir", "User")
  Write-Host "Added to user PATH: $TargetDir"
  Write-Host "Please open a new terminal, then run: secops-agent"
  Write-Host "Compatibility alias also available: crush"
} else {
  Write-Host "Run: secops-agent"
  Write-Host "Compatibility alias also available: crush"
}
PS1

    cat > "$work_dir/uninstall.ps1" <<'PS1'
$ErrorActionPreference = "Stop"

$TargetDir = $env:CRUSH_INSTALL_DIR
if ([string]::IsNullOrWhiteSpace($TargetDir)) {
  $TargetDir = Join-Path $env:LOCALAPPDATA "Programs\SecOps"
}

$Names = @("secops-agent.exe", "crush.exe")
foreach ($Name in $Names) {
  $BinPath = Join-Path $TargetDir $Name
  if (Test-Path $BinPath) {
    Remove-Item $BinPath -Force
    Write-Host "Removed: $BinPath"
  }
}
PS1

    cat > "$work_dir/INSTALL.md" <<'DOC'
# SecOps Agent One-Click Install (Windows)

## Install

```powershell
Set-ExecutionPolicy -Scope Process Bypass
./install.ps1
```

After install, you can run:

```powershell
secops-agent
```

Compatibility alias:

```powershell
crush
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
      COPYFILE_DISABLE=1 ditto -c -k --norsrc --keepParent "$pkg_name" "${pkg_name}.zip"
    )
  else
    cat > "$work_dir/install.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC="${SCRIPT_DIR}/SecOps"

if [[ ! -x "$BIN_SRC" ]]; then
  echo "Error: SecOps binary not found in package directory: $BIN_SRC" >&2
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
install -m 0755 "$BIN_SRC" "$TARGET_DIR/SecOps"

echo "Installed: $TARGET_DIR/SecOps"
if ! command -v SecOps >/dev/null 2>&1 || [[ "$(command -v SecOps)" != "$TARGET_DIR/SecOps" ]]; then
  echo "If command not found, add to PATH:"
  echo "  export PATH=\"$TARGET_DIR:\$PATH\""
fi

echo "Run: SecOps"
SH

    cat > "$work_dir/uninstall.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${CRUSH_INSTALL_DIR:-}"
if [[ -z "$TARGET_DIR" ]]; then
  if [[ -e "/usr/local/bin/SecOps" ]]; then
    TARGET_DIR="/usr/local/bin"
  else
    TARGET_DIR="$HOME/.local/bin"
  fi
fi

if [[ -e "$TARGET_DIR/SecOps" ]]; then
  rm -f "$TARGET_DIR/SecOps"
  echo "Removed: $TARGET_DIR/SecOps"
else
  echo "Not found: $TARGET_DIR/SecOps"
fi
SH

    cat > "$work_dir/INSTALL.md" <<'DOC'
# SecOps Agent One-Click Install (macOS / Linux)

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
