#!/usr/bin/env python3
"""
redteam-recon-person 个人情报收集脚本
整合多种 OSINT 工具进行人物画像分析
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError as e:
    print(f"错误: 缺少依赖 - {e}")
    print("请运行: pip3 install requests rich")
    sys.exit(1)

# 路径设置
SCRIPT_DIR = Path(__file__).parent
SKILL_DIR = SCRIPT_DIR.parent
SKILLS_ROOT = SKILL_DIR.parent

# 关联技能路径
EMAIL_OSINT_DIR = SKILLS_ROOT / "email-osint"
HOLEHE_SCRIPT = EMAIL_OSINT_DIR / "scripts" / "holehe_run.py"
BLACKBIRD_SCRIPT = EMAIL_OSINT_DIR / "scripts" / "blackbird_run.py"

console = Console()


class PersonRecon:
    """个人目标情报收集"""

    def __init__(self, name: str, email: Optional[str] = None,
                 username: Optional[str] = None, company: Optional[str] = None,
                 verbose: bool = False):
        self.name = name
        self.email = email
        self.username = username
        self.company = company
        self.verbose = verbose

        # 结果存储
        self.results: Dict[str, Any] = {
            "target": {
                "name": name,
                "email": email,
                "username": username,
                "company": company,
            },
            "scan_time": datetime.now().isoformat(),
            "email_accounts": [],
            "username_accounts": [],
            "social_profiles": [],
            "data_breaches": [],
            "inferred_usernames": [],
            "profile_summary": {},
        }

    def log(self, message: str):
        """详细日志输出"""
        if self.verbose:
            console.print(f"[dim]{message}[/dim]")

    def infer_usernames(self) -> List[str]:
        """从姓名推断可能的用户名"""
        usernames = set()

        if self.username:
            usernames.add(self.username)

        # 基于姓名生成变体
        name_parts = self.name.lower().split()

        if len(name_parts) >= 2:
            first = name_parts[0]
            last = name_parts[-1]

            # 常见模式
            patterns = [
                f"{first}{last}",           # johndoe
                f"{first}.{last}",          # john.doe
                f"{first}_{last}",          # john_doe
                f"{first[0]}{last}",        # jdoe
                f"{first}{last[0]}",        # johnd
                f"{last}{first}",           # doejohn
                f"{last}.{first}",          # doe.john
                f"{first}{last}123",        # johndoe123
                f"{first[0]}{last}123",     # jdoe123
            ]
            usernames.update(patterns)

        # 基于邮箱提取
        if self.email:
            email_prefix = self.email.split('@')[0]
            usernames.add(email_prefix)

        self.results["inferred_usernames"] = list(usernames)
        return list(usernames)

    def run_holehe(self, email: str) -> List[Dict]:
        """运行 holehe 检测邮箱注册情况"""
        if not HOLEHE_SCRIPT.exists():
            self.log(f"holehe 脚本不存在: {HOLEHE_SCRIPT}")
            return []

        self.log(f"运行 holehe 检测: {email}")

        try:
            result = subprocess.run(
                [sys.executable, str(HOLEHE_SCRIPT), email],
                capture_output=True,
                text=True,
                timeout=120,  # 2分钟超时
                cwd=str(EMAIL_OSINT_DIR / "scripts")
            )

            accounts = []
            # 解析 holehe 输出 (简化解析，实际输出格式可能不同)
            for line in result.stdout.split('\n'):
                line = line.strip()
                if '[+]' in line:
                    # 提取平台名称
                    accounts.append({
                        "platform": line,
                        "email": email,
                        "status": "registered"
                    })

            self.log(f"holehe 发现 {len(accounts)} 个账号")
            return accounts

        except subprocess.TimeoutExpired:
            self.log("holehe 执行超时")
            return []
        except Exception as e:
            self.log(f"holehe 执行错误: {e}")
            return []

    def run_blackbird(self, username: str) -> List[Dict]:
        """运行 blackbird 搜索用户名"""
        if not BLACKBIRD_SCRIPT.exists():
            self.log(f"blackbird 脚本不存在: {BLACKBIRD_SCRIPT}")
            return []

        self.log(f"运行 blackbird 搜索: {username}")

        try:
            result = subprocess.run(
                [sys.executable, str(BLACKBIRD_SCRIPT), "-u", username, "--no-update"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(EMAIL_OSINT_DIR / "scripts")
            )

            accounts = []
            # 解析 blackbird 输出
            for line in result.stdout.split('\n'):
                line = line.strip()
                if 'http' in line.lower() and username.lower() in line.lower():
                    accounts.append({
                        "platform": "unknown",
                        "username": username,
                        "url": line,
                        "status": "found"
                    })

            self.log(f"blackbird 发现 {len(accounts)} 个账号")
            return accounts

        except subprocess.TimeoutExpired:
            self.log("blackbird 执行超时")
            return []
        except Exception as e:
            self.log(f"blackbird 执行错误: {e}")
            return []

    def check_haveibeenpwned(self, email: str) -> List[Dict]:
        """检查邮箱是否出现在数据泄露中 (无 API 版本)"""
        self.log(f"检查数据泄露: {email}")

        # 注意: HIBP API 需要付费 API key
        # 这里返回提示信息
        return [{
            "email": email,
            "note": "需要手动检查 haveibeenpwned.com 或使用 API key",
            "url": f"https://haveibeenpwned.com/account/{email}"
        }]

    def search_social_google(self, name: str, platform: str) -> str:
        """生成 Google Dork 搜索语句"""
        dorks = {
            "linkedin": f'"{name}" site:linkedin.com/in',
            "twitter": f'"{name}" site:twitter.com OR site:x.com',
            "facebook": f'"{name}" site:facebook.com',
            "github": f'"{name}" site:github.com',
            "instagram": f'"{name}" site:instagram.com',
            "weibo": f'"{name}" site:weibo.com',
            "zhihu": f'"{name}" site:zhihu.com',
        }
        return dorks.get(platform, f'"{name}" site:{platform}')

    def generate_google_dorks(self) -> List[Dict]:
        """生成多平台搜索语句"""
        platforms = ["linkedin", "twitter", "github", "facebook", "weibo", "zhihu"]
        dorks = []

        for platform in platforms:
            dork = self.search_social_google(self.name, platform)
            dorks.append({
                "platform": platform,
                "dork": dork,
                "url": f"https://www.google.com/search?q={requests.utils.quote(dork)}"
            })

        # 基于邮箱的搜索
        if self.email:
            dorks.append({
                "platform": "email",
                "dork": f'"{self.email}"',
                "url": f"https://www.google.com/search?q={requests.utils.quote(self.email)}"
            })

        return dorks

    def analyze_profile(self) -> Dict:
        """分析人物画像"""
        profile = {
            "privacy_level": "unknown",
            "tech_level": "unknown",
            "social_activity": "unknown",
            "risk_assessment": [],
        }

        # 基于发现的账号数量评估隐私意识
        total_accounts = (len(self.results["email_accounts"]) +
                        len(self.results["username_accounts"]))

        if total_accounts > 10:
            profile["privacy_level"] = "低 (大量公开账号)"
            profile["risk_assessment"].append("高社工风险 - 信息暴露面广")
        elif total_accounts > 5:
            profile["privacy_level"] = "中"
            profile["risk_assessment"].append("中等社工风险")
        else:
            profile["privacy_level"] = "高或信息有限"
            profile["risk_assessment"].append("需要更多信息收集")

        # 检查技术相关平台
        tech_platforms = ["github", "stackoverflow", "gitlab", "bitbucket"]
        tech_count = sum(1 for acc in self.results.get("username_accounts", [])
                        if any(p in str(acc).lower() for p in tech_platforms))

        if tech_count > 0:
            profile["tech_level"] = "技术背景"
            profile["risk_assessment"].append("可能有较强安全意识")

        self.results["profile_summary"] = profile
        return profile

    def run_scan(self) -> Dict:
        """执行完整扫描"""
        console.print(Panel(f"[bold]目标: {self.name}[/bold]", title="个人情报收集"))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:

            # Phase 1: 推断用户名
            task = progress.add_task("推断可能的用户名...", total=None)
            usernames = self.infer_usernames()
            progress.remove_task(task)
            console.print(f"[green][+][/green] 生成 {len(usernames)} 个候选用户名")

            # Phase 2: 邮箱账号检测
            if self.email:
                task = progress.add_task(f"检测邮箱注册情况: {self.email}...", total=None)
                email_accounts = self.run_holehe(self.email)
                self.results["email_accounts"] = email_accounts
                progress.remove_task(task)
                console.print(f"[green][+][/green] holehe 发现 {len(email_accounts)} 个关联账号")

            # Phase 3: 用户名搜索
            if self.username or usernames:
                target_username = self.username or usernames[0]
                task = progress.add_task(f"搜索用户名: {target_username}...", total=None)
                username_accounts = self.run_blackbird(target_username)
                self.results["username_accounts"] = username_accounts
                progress.remove_task(task)
                console.print(f"[green][+][/green] blackbird 发现 {len(username_accounts)} 个账号")

            # Phase 4: 数据泄露检查
            if self.email:
                task = progress.add_task("检查数据泄露...", total=None)
                breaches = self.check_haveibeenpwned(self.email)
                self.results["data_breaches"] = breaches
                progress.remove_task(task)
                console.print(f"[yellow]![/yellow] 数据泄露检查需手动完成")

            # Phase 5: 生成搜索语句
            task = progress.add_task("生成社交媒体搜索语句...", total=None)
            dorks = self.generate_google_dorks()
            self.results["social_profiles"] = dorks
            progress.remove_task(task)
            console.print(f"[green][+][/green] 生成 {len(dorks)} 个搜索语句")

            # Phase 6: 画像分析
            task = progress.add_task("分析人物画像...", total=None)
            self.analyze_profile()
            progress.remove_task(task)
            console.print(f"[green][+][/green] 画像分析完成")

        return self.results

    def print_report(self):
        """打印报告"""
        console.print()
        console.print(Panel("[bold]侦察报告[/bold]", title="个人目标情报"))

        # 基本信息
        info_table = Table(title="目标信息", show_header=True)
        info_table.add_column("字段", style="cyan")
        info_table.add_column("值", style="white")

        info_table.add_row("姓名", self.name)
        if self.email:
            info_table.add_row("邮箱", self.email)
        if self.username:
            info_table.add_row("用户名", self.username)
        if self.company:
            info_table.add_row("公司", self.company)

        console.print(info_table)
        console.print()

        # 候选用户名
        if self.results["inferred_usernames"]:
            console.print("[bold]候选用户名:[/bold]")
            for u in self.results["inferred_usernames"][:10]:
                console.print(f"  • {u}")
            console.print()

        # 邮箱关联账号
        if self.results["email_accounts"]:
            acc_table = Table(title="邮箱关联账号 (holehe)", show_header=True)
            acc_table.add_column("平台", style="cyan")
            acc_table.add_column("状态", style="green")

            for acc in self.results["email_accounts"][:20]:
                acc_table.add_row(acc.get("platform", "unknown"), acc.get("status", ""))

            console.print(acc_table)
            console.print()

        # 用户名关联账号
        if self.results["username_accounts"]:
            usr_table = Table(title="用户名关联账号 (blackbird)", show_header=True)
            usr_table.add_column("URL", style="cyan")
            usr_table.add_column("状态", style="green")

            for acc in self.results["username_accounts"][:20]:
                usr_table.add_row(acc.get("url", "unknown")[:60], acc.get("status", ""))

            console.print(usr_table)
            console.print()

        # 搜索语句
        console.print("[bold]社交媒体搜索语句:[/bold]")
        for dork in self.results["social_profiles"]:
            console.print(f"  [{dork['platform']}] {dork['dork']}")
        console.print()

        # 画像分析
        profile = self.results.get("profile_summary", {})
        if profile:
            profile_table = Table(title="画像分析", show_header=True)
            profile_table.add_column("维度", style="cyan")
            profile_table.add_column("评估", style="white")

            profile_table.add_row("隐私意识", profile.get("privacy_level", "未知"))
            profile_table.add_row("技术水平", profile.get("tech_level", "未知"))
            profile_table.add_row("社交活跃度", profile.get("social_activity", "未知"))

            console.print(profile_table)
            console.print()

            if profile.get("risk_assessment"):
                console.print("[bold]风险评估:[/bold]")
                for risk in profile["risk_assessment"]:
                    console.print(f"  • {risk}")

    def generate_markdown_report(self) -> str:
        """生成 Markdown 报告"""
        lines = [
            f"# 个人目标情报报告",
            f"",
            f"**生成时间**: {self.results['scan_time']}",
            f"",
            f"## 目标信息",
            f"",
            f"| 字段 | 值 |",
            f"|------|-----|",
            f"| 姓名 | {self.name} |",
        ]

        if self.email:
            lines.append(f"| 邮箱 | {self.email} |")
        if self.username:
            lines.append(f"| 用户名 | {self.username} |")
        if self.company:
            lines.append(f"| 公司 | {self.company} |")

        lines.extend([
            f"",
            f"## 候选用户名",
            f"",
        ])

        for u in self.results["inferred_usernames"][:10]:
            lines.append(f"- `{u}`")

        if self.results["email_accounts"]:
            lines.extend([
                f"",
                f"## 邮箱关联账号",
                f"",
                f"| 平台 | 状态 |",
                f"|------|------|",
            ])
            for acc in self.results["email_accounts"][:20]:
                lines.append(f"| {acc.get('platform', '')} | {acc.get('status', '')} |")

        if self.results["username_accounts"]:
            lines.extend([
                f"",
                f"## 用户名关联账号",
                f"",
                f"| URL | 状态 |",
                f"|-----|------|",
            ])
            for acc in self.results["username_accounts"][:20]:
                lines.append(f"| {acc.get('url', '')[:50]} | {acc.get('status', '')} |")

        lines.extend([
            f"",
            f"## 社交媒体搜索",
            f"",
        ])

        for dork in self.results["social_profiles"]:
            lines.append(f"- **{dork['platform']}**: `{dork['dork']}`")

        profile = self.results.get("profile_summary", {})
        if profile:
            lines.extend([
                f"",
                f"## 画像分析",
                f"",
                f"| 维度 | 评估 |",
                f"|------|------|",
                f"| 隐私意识 | {profile.get('privacy_level', '未知')} |",
                f"| 技术水平 | {profile.get('tech_level', '未知')} |",
                f"",
                f"### 风险评估",
                f"",
            ])
            for risk in profile.get("risk_assessment", []):
                lines.append(f"- {risk}")

        lines.extend([
            f"",
            f"## 下一步建议",
            f"",
            f"1. 使用搜索语句在各平台深入调查",
            f"2. 检查 haveibeenpwned.com 了解数据泄露情况",
            f"3. 关联分析发现的社交账号",
            f"4. 如需深入分析邮箱，使用 `/email-osint`",
            f"5. 如需企业关联分析，使用 `/redteam-recon-enterprise`",
        ])

        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="个人目标情报收集",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 person_recon.py -n "John Doe"
  python3 person_recon.py -n "John Doe" -e john@example.com
  python3 person_recon.py -n "John Doe" -u johndoe -c "Target Corp"
  python3 person_recon.py -n "John Doe" --json -o report.json
        """
    )

    parser.add_argument("-n", "--name", required=True, help="目标姓名")
    parser.add_argument("-e", "--email", help="目标邮箱")
    parser.add_argument("-u", "--username", help="已知用户名")
    parser.add_argument("-c", "--company", help="所属公司")
    parser.add_argument("--json", action="store_true", help="输出 JSON 格式")
    parser.add_argument("-o", "--output", help="输出文件路径")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--markdown", action="store_true", help="输出 Markdown 报告")

    args = parser.parse_args()

    recon = PersonRecon(
        name=args.name,
        email=args.email,
        username=args.username,
        company=args.company,
        verbose=args.verbose
    )

    results = recon.run_scan()

    if args.json:
        output = json.dumps(results, indent=2, ensure_ascii=False, default=str)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            console.print(f"[green][+][/green] JSON 报告已保存到: {args.output}")
        else:
            print(output)
    elif args.markdown:
        output = recon.generate_markdown_report()
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            console.print(f"[green][+][/green] Markdown 报告已保存到: {args.output}")
        else:
            print(output)
    else:
        recon.print_report()

        if args.output:
            output = recon.generate_markdown_report()
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            console.print(f"\n[green][+][/green] 报告已保存到: {args.output}")


if __name__ == "__main__":
    main()
