#!/usr/bin/env python3
"""
redteam-recon-enterprise 环境检测脚本
检测必需和可选工具是否可用
"""

import sys
import shutil
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
SKILL_DIR = SCRIPT_DIR.parent

def check_python_version():
    """检查 Python 版本"""
    version = sys.version_info
    if version >= (3, 8):
        print(f"[+] Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"[-] Python {version.major}.{version.minor} (需要 3.8+)")
        return False

def check_tool(name, cmd, install_hint):
    """检查工具是否可用"""
    if shutil.which(cmd):
        try:
            result = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=5)
            version = result.stdout.strip().split('\n')[0] if result.stdout else "已安装"
            print(f"[+] {name}: {version}")
            return True
        except:
            print(f"[+] {name}: 已安装")
            return True
    else:
        print(f"[-] {name}: 未安装")
        print(f"   安装: {install_hint}")
        return False

def check_python_module(name, module, install_hint):
    """检查 Python 模块是否可用"""
    try:
        __import__(module)
        print(f"[+] {name}")
        return True
    except ImportError:
        print(f"[-] {name}: 未安装")
        print(f"   安装: {install_hint}")
        return False

def main():
    print("=" * 60)
    print("redteam-recon-enterprise 环境检测")
    print("=" * 60)
    print(f"\nSkill 目录: {SKILL_DIR}")
    print()

    print("-" * 60)
    print("核心依赖 (必需):")
    print("-" * 60)

    results = {
        "Python 3.8+": check_python_version(),
    }

    # Python 依赖
    results["requests"] = check_python_module("requests", "requests", "pip3 install requests")
    results["rich"] = check_python_module("rich (美化输出)", "rich", "pip3 install rich")

    print()
    print("-" * 60)
    print("MCP 工具 (通过 Claude 调用):")
    print("-" * 60)
    print("[i] 以下工具通过 MCP 云服务调用，无需本地安装:")
    print("   - subdomain_discovery: 子域名发现")
    print("   - ops_portscan: 端口扫描")
    print("   - intel_icp_lookup: ICP 备案查询")
    print("   - cyberspace_search: 网络空间搜索")
    print("   - dns_history: DNS 历史记录")

    print()
    print("-" * 60)
    print("可选本地工具:")
    print("-" * 60)

    optional = {
        "subfinder": check_tool("subfinder (子域名枚举)", "subfinder",
                               "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        "httpx": check_tool("httpx (HTTP探测)", "httpx",
                           "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        "nmap": check_tool("nmap (端口扫描)", "nmap", "brew install nmap / apt install nmap"),
        "whatweb": check_tool("whatweb (Web指纹)", "whatweb", "gem install whatweb"),
    }

    print()
    print("=" * 60)

    required_ok = all(results.values())
    optional_count = sum(optional.values())

    if required_ok:
        print("[+] 核心依赖已就绪")
        print(f"[i] 可选工具: {optional_count}/{len(optional)} 已安装")
        print()
        print("使用方式:")
        print("  1. MCP 模式 (推荐): 通过 Claude 调用 MCP 工具")
        print("  2. 本地模式: python3 scripts/enterprise_recon.py -d <domain>")
        return 0
    else:
        print("[-] 缺少核心依赖")
        print()
        print("修复方法:")
        print("  pip3 install requests rich")
        return 1

if __name__ == "__main__":
    sys.exit(main())
