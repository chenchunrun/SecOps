#!/usr/bin/env python3
"""
traffic-analysis 环境检测脚本

检测 tshark / capinfos / rg 是否可用。
工具发现优先级：环境变量 > shutil.which > 标准路径
"""

import os
import shutil
import platform
from pathlib import Path
from typing import Tuple, Optional

IS_WINDOWS = platform.system() == "Windows"


def _check_tshark() -> Tuple[bool, Optional[str]]:
    """检查 tshark，返回 (是否可用, 路径)"""
    # 1. 环境变量
    env_path = os.environ.get("CYBERSEC_TSHARK_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists() and p.is_file():
            return (True, env_path)

    # 2. shutil.which
    found = shutil.which("tshark")
    if found:
        return (True, found)

    # 3. Windows 标准路径
    if IS_WINDOWS:
        for base in [r"C:\Program Files\Wireshark", r"C:\Program Files (x86)\Wireshark"]:
            p = Path(base) / "tshark.exe"
            if p.exists():
                return (True, str(p))

    return (False, None)


def _check_capinfos() -> Tuple[bool, Optional[str]]:
    """检查 capinfos，返回 (是否可用, 路径)"""
    env_path = os.environ.get("CYBERSEC_CAPINFOS_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists() and p.is_file():
            return (True, env_path)

    found = shutil.which("capinfos")
    if found:
        return (True, found)

    if IS_WINDOWS:
        for base in [r"C:\Program Files\Wireshark", r"C:\Program Files (x86)\Wireshark"]:
            p = Path(base) / "capinfos.exe"
            if p.exists():
                return (True, str(p))

    return (False, None)


def _check_scapy() -> Tuple[bool, Optional[str]]:
    """检查 scapy，返回 (是否可用, 版本)"""
    try:
        import scapy
        version = getattr(scapy, '__version__', 'installed')
        return (True, version)
    except ImportError:
        return (False, None)


def _check_rg() -> Tuple[bool, Optional[str]]:
    """检查 ripgrep，返回 (是否可用, 路径)"""
    found = shutil.which("rg")
    if found:
        return (True, found)

    if IS_WINDOWS:
        # bundled tools
        possible_paths = [
            Path(__file__).parent.parent.parent / "bundled" / "tools" / "rg" / "rg.exe",
            Path(os.environ.get("CODEX_HOME", "")) / "bundled" / "tools" / "rg" / "rg.exe",
        ]
        for p in possible_paths:
            if p.exists():
                return (True, str(p))

    return (False, None)


def _format_path(path: Optional[str]) -> str:
    if path is None:
        return "not found"
    if len(path) > 60:
        return "..." + path[-57:]
    return path


def main():
    print("=" * 60)
    print("traffic-analysis environment check")
    print(f"Platform: {platform.system()} | Python: {platform.python_version()}")
    print("=" * 60)

    tshark_ok, tshark_path = _check_tshark()
    capinfos_ok, capinfos_path = _check_capinfos()
    rg_ok, rg_path = _check_rg()
    scapy_ok, scapy_ver = _check_scapy()

    print()
    print("-" * 60)
    print("Core tools (tshark preferred, scapy fallback):")
    print("-" * 60)

    if tshark_ok:
        source = ""
        if "CYBERSEC" in (tshark_path or ""):
            source = " (CYBERSEC_TSHARK_PATH)"
        elif shutil.which("tshark") != tshark_path:
            source = " (standard path)"
        else:
            source = " (PATH)"
        print(f"[+] tshark     - {_format_path(tshark_path)}{source}")
        print(f"    Purpose: Command-line PCAP analysis (Wireshark CLI)")
        print(f"    Status: FULL FEATURES AVAILABLE")
    else:
        print(f"[-] tshark     - not found")
        print(f"    Status: USING SCAPY FALLBACK")
        if scapy_ok:
            print(f"[+] scapy      - {scapy_ver} (fallback active)")
            print(f"    Purpose: Pure Python PCAP analysis (no native deps)")
            print(f"    Note: Some advanced fields may be unavailable")
        else:
            print(f"[!] scapy      - not found (pip install scapy)")
            print(f"    Status: NO ANALYSIS ENGINE AVAILABLE")
        if capinfos_ok:
            print(f"[+] capinfos   - {_format_path(capinfos_path)}")

    print()
    print("-" * 60)
    print("Auxiliary tools (optional):")
    print("-" * 60)

    status = "[+]" if rg_ok else "[!]"
    print(f"{status} rg         - {_format_path(rg_path)}")
    print(f"    Purpose: Content search within PCAP files (ripgrep)")

    print()
    print("-" * 60)
    print("Environment variables (set by app at runtime):")
    print("-" * 60)
    tshark_env = os.environ.get("CYBERSEC_TSHARK_PATH", "(not set)")
    capinfos_env = os.environ.get("CYBERSEC_CAPINFOS_PATH", "(not set)")
    print(f"    CYBERSEC_TSHARK_PATH   = {tshark_env}")
    print(f"    CYBERSEC_CAPINFOS_PATH = {capinfos_env}")

    print()
    print("=" * 60)

    if tshark_ok:
        print("[+] All core tools available")
        print()
        print("Usage:")
        print("  python3 scripts/pcap_analyze.py capture.pcap")
        print("  python3 scripts/pcap_analyze.py capture.pcap -j  # JSON output")
        return 0
    elif scapy_ok:
        print("[+] scapy fallback available")
        print()
        print("Usage (scapy fallback mode):")
        print("  python3 scripts/pcap_analyze.py capture.pcap")
        print("  python3 scripts/pcap_analyze.py capture.pcap -j  # JSON output")
        print()
        print("[!] Note: scapy fallback is active. For full features, install Wireshark.")
        return 0
    else:
        print("[-] No analysis engine available")
        print()
        if IS_WINDOWS:
            print("[!] Install Wireshark: https://www.wireshark.org/download.html")
        else:
            print("[!] Install Wireshark:")
            print("    macOS: brew install wireshark")
            print("    Linux: sudo apt install wireshark   # Debian/Ubuntu")
        print()
        print("Or install scapy (limited functionality):")
        print("    pip install scapy")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
