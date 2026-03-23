# Crush SecOps 一键安装与跨平台发布说明

本文档对应两个脚本：

- `scripts/package_oneclick.sh`：打当前平台单包（快速本地分发）
- `scripts/package_cross_platform.sh`：一次打多平台发布包（推荐正式发布）

## 1. 维护者：生成跨平台安装包（推荐）

```bash
cd /Users/newmba/Downloads/SecOpsCode/crush-main
./scripts/package_cross_platform.sh
```

默认会生成：

- macOS: `darwin/arm64`, `darwin/amd64`
- Linux: `linux/amd64`, `linux/arm64`
- Windows: `windows/amd64`, `windows/arm64`

每个包都附带 `sha256` 校验文件。

可只打指定平台：

```bash
TARGETS="linux/amd64 windows/amd64" ./scripts/package_cross_platform.sh
```

可自定义版本号：

```bash
VERSION=v0.0.0-secops-rc3 ./scripts/package_cross_platform.sh
```

## 2. 用户安装（macOS / Linux）

```bash
# 1) 解压
mkdir -p /tmp/crush-install && cd /tmp/crush-install
tar -xzf /path/to/crush-secops-<version>-<os>-<arch>.tar.gz
cd crush-secops-<version>-<os>-<arch>

# 2) 一键安装
chmod +x install.sh
./install.sh

# 3) 验证
crush --version
```

默认安装路径：

- `/usr/local/bin/crush`（可写时）
- 否则 `$HOME/.local/bin/crush`

自定义安装目录：

```bash
CRUSH_INSTALL_DIR="$HOME/bin" ./install.sh
```

卸载：

```bash
chmod +x uninstall.sh
./uninstall.sh
```

## 3. 用户安装（Windows）

```powershell
# 1) 解压 zip
# 2) 进入目录后执行
Set-ExecutionPolicy -Scope Process Bypass
./install.ps1

# 3) 验证
crush --version
```

默认安装路径：

- `%LOCALAPPDATA%\Programs\crush-secops\crush.exe`

自定义安装目录：

```powershell
$env:CRUSH_INSTALL_DIR="$HOME\\bin"
./install.ps1
```

卸载：

```powershell
./uninstall.ps1
```

## 4. 完整性校验（推荐）

macOS:

```bash
shasum -a 256 -c crush-secops-<version>-<os>-<arch>.<tar.gz|zip>.sha256
```

Linux:

```bash
sha256sum -c crush-secops-<version>-<os>-<arch>.<tar.gz|zip>.sha256
```

## 5. 发布到 GitHub Releases 的建议

1. 上传各平台包和对应 `.sha256`
2. 在 Release Notes 中分别给出 macOS/Linux/Windows 的安装命令
3. 将 `scripts/package_cross_platform.sh` 作为标准发布打包流程
