#!/usr/bin/env python3
"""
email-osint 环境检测脚本
检测必需和可选依赖是否已安装，优先检测本地内置工具
"""

import sys
import shutil
import subprocess
from pathlib import Path

# 路径设置
SCRIPT_DIR = Path(__file__).parent
SKILL_DIR = SCRIPT_DIR.parent
TOOLS_DIR = SKILL_DIR / "tools"

def check_python_version():
    """检查 Python 版本"""
    version = sys.version_info
    if version >= (3, 8):
        print(f"[+] Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"[-] Python {version.major}.{version.minor} (需要 3.8+)")
        return False

def check_holehe():
    """检查 holehe 是否可用（优先本地）"""
    local_holehe = TOOLS_DIR / "holehe"

    # 1. 优先检查本地内置
    if local_holehe.exists() and (local_holehe / "core.py").exists():
        # 检查依赖是否安装
        try:
            import httpx, trio, bs4, colorama, termcolor, tqdm
            print(f"[+] holehe 已内置: {local_holehe}")
            print(f"   调用: python3 scripts/holehe_run.py <email>")
            return True
        except ImportError as e:
            print(f"[!] holehe 源码已内置，但缺少依赖: {e}")
            print(f"   运行: pip3 install -r requirements.txt")
            return False

    # 2. 检查系统安装
    if shutil.which("holehe"):
        print(f"[+] holehe 已安装 (系统)")
        return True

    print("[-] holehe 未安装")
    print("   运行: bash scripts/setup_tools.sh")
    return False

def check_blackbird():
    """检查 blackbird 是否可用（优先本地）"""
    local_blackbird = TOOLS_DIR / "blackbird" / "blackbird.py"

    # 1. 优先检查本地内置
    if local_blackbird.exists():
        # 检查依赖是否安装
        try:
            import aiohttp, requests, rich
            print(f"[+] blackbird 已内置: {local_blackbird.parent}")
            print(f"   调用: python3 scripts/blackbird_run.py -u <username>")
            return True
        except ImportError as e:
            print(f"[!] blackbird 源码已内置，但缺少依赖: {e}")
            print(f"   运行: pip3 install -r requirements.txt")
            return False

    # 2. 检查外部安装
    common_paths = [
        Path.home() / "pr" / "blackbird",
        Path.home() / "tools" / "blackbird",
        Path.home() / "blackbird",
        Path("/opt/blackbird"),
    ]

    for path in common_paths:
        if (path / "blackbird.py").exists():
            print(f"[+] blackbird 已安装: {path}")
            return True

    if shutil.which("blackbird"):
        print("[+] blackbird 已安装 (PATH)")
        return True

    print("[-] blackbird 未安装")
    print("   运行: bash scripts/setup_tools.sh")
    return False

def check_holehe_deps():
    """检查 holehe 依赖"""
    deps = ['httpx', 'trio', 'bs4', 'colorama', 'termcolor', 'tqdm']
    missing = []
    for dep in deps:
        try:
            __import__(dep)
        except ImportError:
            missing.append(dep)
    return missing

def check_blackbird_deps():
    """检查 blackbird 依赖"""
    deps = ['aiohttp', 'requests', 'rich', 'PIL', 'reportlab']
    missing = []
    for dep in deps:
        try:
            __import__(dep)
        except ImportError:
            missing.append(dep)
    return missing

def check_httpx_socks():
    """检查 httpx socks 支持 (可选)"""
    try:
        import httpx
        try:
            import socksio
            print("[+] httpx[socks] 已安装 (可选，用于代理)")
            return True
        except ImportError:
            print("[!] httpx[socks] 未安装 (可选)")
            print("   安装: pip3 install 'httpx[socks]'")
            return False
    except ImportError:
        print("[!] httpx 未安装")
        return False

def main():
    print("=" * 60)
    print("email-osint 环境检测")
    print("=" * 60)
    print(f"\nSkill 目录: {SKILL_DIR}")
    print(f"工具目录:   {TOOLS_DIR}")
    print()

    print("-" * 60)
    print("核心检查:")
    print("-" * 60)

    results = {
        "Python 3.8+": check_python_version(),
        "holehe": check_holehe(),
        "blackbird": check_blackbird(),
    }

    print()
    print("-" * 60)
    print("可选依赖:")
    print("-" * 60)
    check_httpx_socks()

    print()
    print("=" * 60)

    # 统计结果
    required_ok = all(results.values())

    if required_ok:
        print("[+] 所有必需依赖已就绪")
        print()
        print("快速使用:")
        print(f"  holehe:    python3 {SCRIPT_DIR}/holehe_run.py <email>")
        print(f"  blackbird: python3 {SCRIPT_DIR}/blackbird_run.py -u <username>")
        return 0
    else:
        print("[-] 缺少必需依赖")
        print()
        print("修复方法:")
        print(f"  cd {SKILL_DIR}")
        print("  pip3 install -r requirements.txt")
        return 1

if __name__ == "__main__":
    sys.exit(main())
