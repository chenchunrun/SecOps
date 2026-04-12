#!/usr/bin/env python3
"""
逆向分析环境检查 (跨平台)
用法: python3 check_env.py [--install]
"""

import subprocess
import sys
import platform
from typing import Tuple, List

IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"

TOOLS = {
    # 核心工具
    "radare2": {
        "check": ["r2", "-v"],
        "install": {
            "darwin": "brew install radare2",
            "windows": "下载: https://github.com/radareorg/radare2/releases",
            "linux": "sudo apt install radare2"
        },
        "desc": "逆向分析框架"
    },
    "ghidra": {
        "check": "ghidra_headless",  # 特殊检查
        "install": {
            "darwin": "brew install ghidra",
            "windows": "下载: https://ghidra-sre.org/",
            "linux": "下载: https://ghidra-sre.org/"
        },
        "desc": "反编译器 (无头模式)"
    },
    "frida": {
        "check": ["frida", "--version"],
        "install": {
            "all": "pip install frida-tools"
        },
        "desc": "动态插桩"
    },
    "pwntools": {
        "check": ["pwn", "version"],
        "install": {
            "darwin": "pip install pwntools",
            "linux": "pip install pwntools",
            "windows": "WSL 下安装: pip install pwntools"
        },
        "desc": "漏洞利用"
    },
    "lief": {
        "check": ["python3", "-c", "import lief"],
        "install": {
            "all": "pip install lief"
        },
        "desc": "二进制解析"
    },
    "yara": {
        "check": ["yara", "--version"],
        "install": {
            "darwin": "brew install yara && pip install yara-python",
            "windows": "下载: https://github.com/VirusTotal/yara/releases",
            "linux": "sudo apt install yara && pip install yara-python"
        },
        "desc": "恶意软件检测"
    },
    # 系统工具
    "strings": {
        "check": ["strings", "--version"],
        "install": None,
        "desc": "字符串提取"
    },
    "file": {
        "check": ["file", "--version"],
        "install": None,
        "desc": "文件识别"
    },
}


def check_ghidra_headless() -> bool:
    """检查 Ghidra analyzeHeadless 是否可用"""
    import os
    from pathlib import Path

    # 检查环境变量
    ghidra_home = os.environ.get("GHIDRA_HOME")
    if ghidra_home:
        p = Path(ghidra_home) / "support" / ("analyzeHeadless.bat" if IS_WINDOWS else "analyzeHeadless")
        if p.exists():
            return True

    # 常见路径
    if IS_MACOS:
        # Homebrew
        for base in [Path("/opt/homebrew/Cellar/ghidra"), Path("/usr/local/Cellar/ghidra")]:
            if base.exists():
                for ver in base.iterdir():
                    p = ver / "libexec" / "support" / "analyzeHeadless"
                    if p.exists():
                        return True
    elif IS_WINDOWS:
        for base in [Path("C:/ghidra"), Path("C:/Program Files/ghidra")]:
            if base.exists():
                p = base / "support" / "analyzeHeadless.bat"
                if p.exists():
                    return True
    else:  # Linux
        for base in [Path("/opt/ghidra"), Path("/usr/share/ghidra"), Path("/usr/local/ghidra")]:
            if base.exists():
                p = base / "support" / "analyzeHeadless"
                if p.exists():
                    return True

    return False


def check_tool(name: str, cmd) -> bool:
    # 特殊检查
    if cmd == "ghidra_headless":
        return check_ghidra_headless()

    if not isinstance(cmd, list):
        return False

    try:
        subprocess.run(cmd, capture_output=True, timeout=5)
        return True
    except:
        return True if "import" in ' '.join(cmd) else False


def get_install_cmd(info):
    """获取当前平台的安装命令"""
    install = info.get("install")
    if install is None:
        return None
    if isinstance(install, str):
        return install
    if "all" in install:
        return install["all"]
    plat = platform.system().lower()
    return install.get(plat, install.get("linux", None))


def main():
    print("\n" + "=" * 50)
    print(f"逆向分析工具环境检查 ({platform.system()})")
    print("=" * 50 + "\n")

    missing = []
    for name, info in TOOLS.items():
        ok = check_tool(name, info["check"])
        status = "[+]" if ok else "[-]"
        print(f"{status} {name:10} - {info['desc']}")
        if not ok:
            missing.append(name)

    print(f"\n已安装: {len(TOOLS) - len(missing)}/{len(TOOLS)}")

    if missing:
        print(f"\n缺失: {', '.join(missing)}")
        print("\n安装命令:")
        for name in missing:
            cmd = get_install_cmd(TOOLS[name])
            if cmd:
                print(f"  {name}: {cmd}")

        if "--install" in sys.argv:
            print("\n开始安装...")
            for name in missing:
                cmd = get_install_cmd(TOOLS[name])
                if cmd and not cmd.startswith("下载"):
                    print(f"[*] {name}...")
                    result = subprocess.run(cmd, shell=True, capture_output=True)
                    print("    [+]" if result.returncode == 0 else "    [-]")
                elif cmd:
                    print(f"[!] {name}: 需手动 {cmd}")


if __name__ == "__main__":
    main()
