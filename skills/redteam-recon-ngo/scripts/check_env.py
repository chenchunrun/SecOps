#!/usr/bin/env python3
"""
redteam-recon-ngo 环境检测脚本
针对 NGO 组织的攻击面侦察环境检测
"""

import sys
import shutil
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
SKILL_DIR = SCRIPT_DIR.parent
SKILLS_ROOT = SKILL_DIR.parent

# 关联技能路径
ENTERPRISE_RECON_DIR = SKILLS_ROOT / "redteam-recon-enterprise"
PERSON_RECON_DIR = SKILLS_ROOT / "redteam-recon-person"
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


def check_command(name, cmd, install_hint):
    """检查命令行工具是否可用"""
    path = shutil.which(cmd)
    if path:
        print(f"[+] {name}: {path}")
        return True
    else:
        print(f"[!] {name}: 未安装 (可选)")
        print(f"   安装: {install_hint}")
        return False


def check_email_collection_tools():
    """检查邮箱收集工具"""
    print()
    print("-" * 60)
    print("邮箱收集工具 (可选，增强功能):")
    print("-" * 60)

    results = {}

    # theHarvester
    results["theHarvester"] = check_command(
        "theHarvester (邮箱/子域名收集)",
        "theHarvester",
        "需要 Python 3.12+，参考: https://github.com/laramies/theHarvester"
    )

    # CrossLinked
    results["CrossLinked"] = check_command(
        "CrossLinked (LinkedIn员工枚举)",
        "crosslinked",
        "pip3 install crosslinked"
    )

    # holehe
    results["holehe"] = check_python_module(
        "holehe (邮箱社交账号验证)",
        "holehe",
        "pip3 install holehe"
    )

    return results


def check_related_skills():
    """检查关联技能"""
    print()
    print("-" * 60)
    print("关联技能 (攻击链):")
    print("-" * 60)

    results = {}

    # 企业侦察
    enterprise_script = ENTERPRISE_RECON_DIR / "scripts" / "enterprise_recon.py"
    if enterprise_script.exists():
        print(f"[+] redteam-recon-enterprise: 深度资产扫描")
        results["enterprise"] = True
    else:
        print(f"[!] redteam-recon-enterprise: 未找到")
        results["enterprise"] = False

    # 人员侦察
    person_script = PERSON_RECON_DIR / "scripts" / "person_recon.py"
    if person_script.exists():
        print(f"[+] redteam-recon-person: 高价值目标画像")
        results["person"] = True
    else:
        print(f"[!] redteam-recon-person: 未找到")
        results["person"] = False

    # 邮箱情报
    holehe_script = EMAIL_OSINT_DIR / "scripts" / "holehe_run.py"
    if holehe_script.exists():
        print(f"[+] email-osint: 邮箱深度关联分析")
        results["email"] = True
    else:
        print(f"[!] email-osint: 未找到")
        results["email"] = False

    return results


def main():
    print("=" * 60)
    print("redteam-recon-ngo 环境检测")
    print("=" * 60)
    print(f"\nSkill 目录: {SKILL_DIR}")
    print()

    print("-" * 60)
    print("核心依赖 (必需):")
    print("-" * 60)

    results = {
        "Python 3.8+": check_python_version(),
    }

    results["requests"] = check_python_module(
        "requests (HTTP请求)", "requests", "pip3 install requests"
    )
    results["rich"] = check_python_module(
        "rich (美化输出)", "rich", "pip3 install rich"
    )

    # 检查邮箱收集工具
    email_tools = check_email_collection_tools()

    # 检查关联技能
    related = check_related_skills()

    print()
    print("-" * 60)
    print("数据源说明:")
    print("-" * 60)
    print("[i] 脚本使用以下免费数据源 (无需 API Key):")
    print("   - crt.sh: 证书透明度日志")
    print("   - theHarvester: crtsh, dnsdumpster, bing, baidu, anubis 等")
    print("   - CrossLinked: Google/Bing LinkedIn 员工搜索")
    print("   - holehe: 邮箱社交账号关联")

    print()
    print("=" * 60)

    required_ok = all(results.values())
    email_tools_count = sum(1 for v in email_tools.values() if v)

    if required_ok:
        print("[+] 核心依赖已就绪")
        if email_tools_count == 0:
            print("[!] 邮箱收集工具未安装，功能受限")
            print("   安装: pip3 install theHarvester crosslinked holehe")
        elif email_tools_count < 3:
            print(f"[i] 已安装 {email_tools_count}/3 个邮箱收集工具")
        else:
            print("[+] 全部邮箱收集工具已就绪")
        print()
        print("使用方式:")
        print("  python3 scripts/ngo_recon.py -n <org_name> -d <domain>")
        print("  python3 scripts/ngo_recon.py -n \"Human Rights Org\" -d hrorg.org --type human_rights")
        print()
        print("跳过特定工具:")
        print("  --skip-harvester   跳过 theHarvester")
        print("  --skip-crosslinked 跳过 CrossLinked")
        print("  --skip-holehe      跳过 holehe 验证")
        return 0
    else:
        print("[-] 缺少核心依赖")
        print("修复: pip3 install requests rich")
        return 1


if __name__ == "__main__":
    sys.exit(main())
