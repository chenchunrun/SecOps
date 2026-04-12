#!/usr/bin/env python3
"""
redteam-recon-person 环境检测脚本
检测必需和可选工具是否可用
"""

import sys
import shutil
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
SKILL_DIR = SCRIPT_DIR.parent
SKILLS_ROOT = SKILL_DIR.parent

# email-osint 技能路径
EMAIL_OSINT_DIR = SKILLS_ROOT / "email-osint"

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

def check_email_osint_skill():
    """检查 email-osint 技能是否可用"""
    print()
    print("-" * 60)
    print("关联技能 (email-osint):")
    print("-" * 60)

    holehe_script = EMAIL_OSINT_DIR / "scripts" / "holehe_run.py"
    blackbird_script = EMAIL_OSINT_DIR / "scripts" / "blackbird_run.py"

    results = {}

    if holehe_script.exists():
        print(f"[+] holehe_run.py: {holehe_script}")
        results["holehe"] = True
    else:
        print(f"[-] holehe_run.py: 未找到")
        print(f"   预期路径: {holehe_script}")
        results["holehe"] = False

    if blackbird_script.exists():
        print(f"[+] blackbird_run.py: {blackbird_script}")
        results["blackbird"] = True
    else:
        print(f"[-] blackbird_run.py: 未找到")
        print(f"   预期路径: {blackbird_script}")
        results["blackbird"] = False

    return results

def main():
    print("=" * 60)
    print("redteam-recon-person 环境检测")
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

    # 检查 email-osint 技能
    email_osint = check_email_osint_skill()

    print()
    print("-" * 60)
    print("可选本地工具:")
    print("-" * 60)

    optional = {
        "sherlock": check_tool("sherlock (用户名搜索)", "sherlock",
                              "pip3 install sherlock-project"),
        "maigret": check_tool("maigret (高级用户名搜索)", "maigret",
                            "pip3 install maigret"),
        "theHarvester": check_tool("theHarvester (信息收集)", "theHarvester",
                                  "pip3 install theHarvester"),
    }

    print()
    print("-" * 60)
    print("MCP 工具 (通过 Claude 调用):")
    print("-" * 60)
    print("[i] 以下工具通过 MCP 云服务调用，无需本地安装:")
    print("   - WebSearch: 网络搜索")
    print("   - WebFetch: 网页抓取")

    print()
    print("=" * 60)

    required_ok = all(results.values())
    email_osint_ok = all(email_osint.values())
    optional_count = sum(optional.values())

    if required_ok:
        print("[+] 核心依赖已就绪")
        if email_osint_ok:
            print("[+] email-osint 技能可用")
        else:
            print("[!] email-osint 技能部分可用")
        print(f"[i] 可选工具: {optional_count}/{len(optional)} 已安装")
        print()
        print("使用方式:")
        print("  python3 scripts/person_recon.py -n <name> [-e <email>] [-u <username>]")
        return 0
    else:
        print("[-] 缺少核心依赖")
        print()
        print("修复方法:")
        print("  pip3 install requests rich")
        return 1

if __name__ == "__main__":
    sys.exit(main())
