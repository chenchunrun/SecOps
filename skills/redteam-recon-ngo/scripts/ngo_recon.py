#!/usr/bin/env python3
"""
redteam-recon-ngo NGO组织攻击面侦察脚本
针对 NGO 组织特点进行攻击面测绘和社工预研
集成 theHarvester、CrossLinked、holehe 进行邮箱收集和验证
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Set

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

console = Console()

# theHarvester 免费数据源（无需 API Key）
THEHARVESTER_FREE_SOURCES = [
    "crtsh",
    "dnsdumpster",
    "duckduckgo",
    "bing",
    "baidu",
    "anubis",
    "hackertarget",
    "rapiddns",
    "urlscan",
]

# NGO 组织类型及其攻击特点
NGO_TYPES = {
    "human_rights": {
        "name": "人权组织",
        "attack_vectors": ["国家级APT", "商业间谍软件", "针对性钓鱼"],
        "high_value_targets": ["调查人员", "律师", "发言人"],
        "phishing_themes": ["媒体采访", "国际会议邀请", "受害者求助", "捐赠者联系"],
    },
    "media": {
        "name": "新闻媒体",
        "attack_vectors": ["国家级APT", "信源钓鱼", "水坑攻击"],
        "high_value_targets": ["调查记者", "编辑", "信源管理员"],
        "phishing_themes": ["独家爆料", "匿名信源", "同行交流", "新闻线索"],
    },
    "environmental": {
        "name": "环保组织",
        "attack_vectors": ["企业间谍", "监控软件", "法律施压"],
        "high_value_targets": ["活动组织者", "科研人员", "法务"],
        "phishing_themes": ["企业合作", "学术交流", "政府咨询", "媒体采访"],
    },
    "humanitarian": {
        "name": "人道援助",
        "attack_vectors": ["网络犯罪", "供应链攻击", "内部威胁"],
        "high_value_targets": ["财务人员", "物流协调", "现场负责人"],
        "phishing_themes": ["紧急物资", "捐赠确认", "合作方沟通", "政府审批"],
    },
    "political": {
        "name": "政治异见",
        "attack_vectors": ["国家级APT", "零日漏洞", "物理监控配合"],
        "high_value_targets": ["领导层", "联络员", "技术支持"],
        "phishing_themes": ["安全警告", "同盟联系", "国际支持", "媒体采访"],
    },
}

# NGO 常见攻击入口
NGO_ATTACK_SURFACES = {
    "donation_system": {
        "name": "捐赠系统",
        "risk": "高",
        "attack_methods": ["支付劫持", "钓鱼页面", "XSS注入"],
    },
    "volunteer_portal": {
        "name": "志愿者门户",
        "risk": "高",
        "attack_methods": ["账号枚举", "弱口令", "信息泄露"],
    },
    "member_database": {
        "name": "成员数据库",
        "risk": "极高",
        "attack_methods": ["SQL注入", "未授权访问", "备份泄露"],
    },
    "collaboration_tools": {
        "name": "协作平台",
        "risk": "中",
        "attack_methods": ["OAuth钓鱼", "文档钓鱼", "共享链接"],
    },
    "email_system": {
        "name": "邮件系统",
        "risk": "高",
        "attack_methods": ["凭证钓鱼", "BEC攻击", "邮件劫持"],
    },
}


class NGORecon:
    """NGO 组织攻击面侦察"""

    def __init__(self, name: str, domain: str, ngo_type: str = "human_rights",
                 verbose: bool = False, skip_harvester: bool = False,
                 skip_crosslinked: bool = False, skip_holehe: bool = False):
        self.name = name
        self.domain = domain
        self.ngo_type = ngo_type
        self.ngo_profile = NGO_TYPES.get(ngo_type, NGO_TYPES["human_rights"])
        self.verbose = verbose
        self.skip_harvester = skip_harvester
        self.skip_crosslinked = skip_crosslinked
        self.skip_holehe = skip_holehe

        self.results: Dict[str, Any] = {
            "target": {
                "name": name,
                "domain": domain,
                "type": ngo_type,
                "type_name": self.ngo_profile["name"],
            },
            "scan_time": datetime.now().isoformat(),
            "subdomains": [],
            "collected_emails": [],      # theHarvester 收集的邮箱
            "linkedin_employees": [],    # CrossLinked 收集的员工
            "generated_emails": [],      # 生成的邮箱列表
            "verified_emails": [],       # holehe 验证结果
            "attack_surfaces": [],
            "high_value_targets": [],
            "social_engineering": {},
            "recommended_attacks": [],
        }

    def log(self, message: str):
        """详细日志"""
        if self.verbose:
            console.print(f"[dim]{message}[/dim]")

    def check_tool(self, tool_name: str) -> bool:
        """检查工具是否可用"""
        return shutil.which(tool_name) is not None

    def discover_subdomains_crtsh(self) -> Set[str]:
        """通过 crt.sh 发现子域名"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and "*" not in sub:
                            subdomains.add(sub)
        except Exception as e:
            self.log(f"crt.sh 查询失败: {e}")
        return subdomains

    def run_theharvester(self) -> Dict[str, List[str]]:
        """运行 theHarvester 收集邮箱和子域名（仅免费源）"""
        result = {"emails": [], "subdomains": [], "hosts": []}

        if not self.check_tool("theHarvester"):
            self.log("theHarvester 未安装，跳过")
            return result

        # 使用免费数据源
        sources = ",".join(THEHARVESTER_FREE_SOURCES)

        try:
            self.log(f"运行 theHarvester -d {self.domain} -b {sources}")
            proc = subprocess.run(
                ["theHarvester", "-d", self.domain, "-b", sources],
                capture_output=True,
                text=True,
                timeout=300,  # 5分钟超时
            )

            output = proc.stdout + proc.stderr

            # 解析邮箱
            email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
            emails = set(re.findall(email_pattern, output.lower()))
            # 过滤只保留目标域名的邮箱
            result["emails"] = [e for e in emails if self.domain.lower() in e]

            # 解析子域名（从输出中提取）
            subdomain_pattern = rf'[\w\.-]+\.{re.escape(self.domain)}'
            subdomains = set(re.findall(subdomain_pattern, output.lower()))
            result["subdomains"] = list(subdomains)

            self.log(f"theHarvester 发现 {len(result['emails'])} 个邮箱, {len(result['subdomains'])} 个子域名")

        except subprocess.TimeoutExpired:
            self.log("theHarvester 执行超时")
        except Exception as e:
            self.log(f"theHarvester 执行错误: {e}")

        return result

    def run_crosslinked(self) -> List[Dict]:
        """运行 CrossLinked 从 LinkedIn 收集员工"""
        employees = []

        if not self.check_tool("crosslinked"):
            self.log("crosslinked 未安装，跳过")
            return employees

        # 创建临时输出目录
        output_dir = Path("/tmp/crosslinked_output")
        output_dir.mkdir(exist_ok=True)

        try:
            self.log(f"运行 crosslinked '{self.name}'")
            proc = subprocess.run(
                [
                    "crosslinked",
                    "-f", f"{{first}}.{{last}}@{self.domain}",
                    self.name,
                ],
                capture_output=True,
                text=True,
                timeout=180,  # 3分钟超时
                cwd=str(output_dir),
            )

            # 读取生成的 names.csv（如果存在）
            csv_file = output_dir / "names.csv"
            if csv_file.exists():
                import csv
                with open(csv_file, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        employees.append({
                            "name": row.get("name", ""),
                            "title": row.get("title", ""),
                            "url": row.get("url", ""),
                            "email": f"{row.get('name', '').lower().replace(' ', '.')}@{self.domain}",
                        })

            # 也读取 names.txt
            txt_file = output_dir / "names.txt"
            if txt_file.exists() and not employees:
                with open(txt_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        email = line.strip()
                        if email and '@' in email:
                            employees.append({
                                "name": email.split('@')[0].replace('.', ' ').title(),
                                "title": "",
                                "url": "",
                                "email": email,
                            })

            self.log(f"CrossLinked 发现 {len(employees)} 个员工")

        except subprocess.TimeoutExpired:
            self.log("CrossLinked 执行超时")
        except Exception as e:
            self.log(f"CrossLinked 执行错误: {e}")

        return employees

    def run_holehe(self, emails: List[str], max_emails: int = 10) -> List[Dict]:
        """运行 holehe 验证邮箱"""
        verified = []

        if not HOLEHE_SCRIPT.exists():
            self.log(f"holehe 脚本不存在: {HOLEHE_SCRIPT}")
            return verified

        # 限制检测数量
        emails_to_check = emails[:max_emails]

        for email in emails_to_check:
            try:
                self.log(f"holehe 检测: {email}")
                proc = subprocess.run(
                    [sys.executable, str(HOLEHE_SCRIPT), email],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    cwd=str(EMAIL_OSINT_DIR / "scripts"),
                )

                # 解析输出，找出注册的平台
                output = proc.stdout
                platforms = []

                for line in output.split('\n'):
                    # holehe 输出格式可能包含 [+] 表示已注册
                    if '[+]' in line or 'registered' in line.lower():
                        platforms.append(line.strip())

                verified.append({
                    "email": email,
                    "registered_platforms": platforms,
                    "platform_count": len(platforms),
                })

            except subprocess.TimeoutExpired:
                self.log(f"holehe 检测 {email} 超时")
            except Exception as e:
                self.log(f"holehe 检测 {email} 错误: {e}")

        return verified

    def identify_attack_surfaces(self, subdomains: List[str]) -> List[Dict]:
        """识别 NGO 特有攻击面"""
        surfaces = []

        ngo_keywords = {
            "donate": ("donation_system", "捐赠入口"),
            "donation": ("donation_system", "捐赠入口"),
            "give": ("donation_system", "捐赠入口"),
            "support": ("donation_system", "支持/捐赠"),
            "volunteer": ("volunteer_portal", "志愿者门户"),
            "join": ("volunteer_portal", "加入入口"),
            "member": ("member_database", "成员系统"),
            "portal": ("member_database", "门户系统"),
            "login": ("member_database", "登录入口"),
            "intranet": ("member_database", "内网入口"),
            "staff": ("member_database", "员工系统"),
            "mail": ("email_system", "邮件系统"),
            "webmail": ("email_system", "Webmail"),
            "owa": ("email_system", "Outlook Web"),
            "docs": ("collaboration_tools", "文档协作"),
            "drive": ("collaboration_tools", "网盘"),
            "wiki": ("collaboration_tools", "Wiki"),
            "slack": ("collaboration_tools", "Slack"),
            "api": ("api_endpoint", "API 接口"),
            "dev": ("dev_environment", "开发环境"),
            "test": ("dev_environment", "测试环境"),
            "staging": ("dev_environment", "预发布环境"),
        }

        for subdomain in subdomains:
            for keyword, (surface_type, desc) in ngo_keywords.items():
                if keyword in subdomain.lower():
                    surface_info = NGO_ATTACK_SURFACES.get(surface_type, {})
                    surfaces.append({
                        "subdomain": subdomain,
                        "type": surface_type,
                        "description": desc,
                        "risk": surface_info.get("risk", "中"),
                        "attack_methods": surface_info.get("attack_methods", []),
                    })
                    break

        return surfaces

    def generate_email_formats(self, employees: List[Dict]) -> List[str]:
        """基于员工姓名生成多种邮箱格式"""
        emails = set()

        for emp in employees:
            name = emp.get("name", "").strip()
            if not name:
                continue

            parts = name.lower().split()
            if len(parts) >= 2:
                first = parts[0]
                last = parts[-1]

                # 常见格式
                formats = [
                    f"{first}.{last}@{self.domain}",
                    f"{first}{last}@{self.domain}",
                    f"{first[0]}{last}@{self.domain}",
                    f"{first}_{last}@{self.domain}",
                    f"{last}.{first}@{self.domain}",
                    f"{first[0]}.{last}@{self.domain}",
                ]
                emails.update(formats)

        return list(emails)

    def infer_staff_emails(self) -> List[Dict]:
        """推断员工邮箱格式和高价值目标"""
        targets = []
        high_value_roles = self.ngo_profile["high_value_targets"]

        common_roles = [
            ("director", "总监/主任", "决策层"),
            ("executive", "执行官", "决策层"),
            ("coordinator", "协调员", "运营层"),
            ("manager", "经理", "管理层"),
            ("officer", "专员", "执行层"),
            ("researcher", "研究员", "调查层"),
            ("analyst", "分析师", "调查层"),
            ("communications", "传播", "公关层"),
            ("fundraising", "筹款", "财务层"),
            ("finance", "财务", "财务层"),
            ("it", "IT", "技术层"),
            ("admin", "管理员", "技术层"),
        ]

        for role, title, level in common_roles:
            is_high_value = any(hv in title for hv in high_value_roles)
            targets.append({
                "role": role,
                "title": title,
                "level": level,
                "email_guess": f"{role}@{self.domain}",
                "high_value": is_high_value,
                "priority": "高" if is_high_value else "中",
            })

        return targets

    def generate_phishing_scenarios(self) -> Dict:
        """生成针对 NGO 的钓鱼场景"""
        scenarios = {
            "themes": self.ngo_profile["phishing_themes"],
            "scenarios": [],
        }

        base_scenarios = [
            {
                "name": "媒体采访请求",
                "pretext": f"我是 [知名媒体] 的记者，希望就 {self.ngo_profile['name']} 的工作进行专访",
                "target": "发言人/传播负责人",
                "payload": "访谈提纲.docx (恶意文档)",
                "success_rate": "高",
            },
            {
                "name": "国际会议邀请",
                "pretext": "诚邀贵组织参加 [国际论坛]，请查收会议议程",
                "target": "领导层/项目负责人",
                "payload": "会议议程.pdf (恶意PDF/链接)",
                "success_rate": "高",
            },
            {
                "name": "大额捐赠意向",
                "pretext": "我代表 [基金会] 希望了解捐赠流程，附上我们的捐赠意向书",
                "target": "筹款/财务人员",
                "payload": "捐赠意向书.xlsx (恶意宏)",
                "success_rate": "中",
            },
            {
                "name": "合作方紧急通知",
                "pretext": "我们的共享文档权限需要更新，请点击链接重新授权",
                "target": "全员",
                "payload": "OAuth 钓鱼链接",
                "success_rate": "中",
            },
            {
                "name": "IT 安全更新",
                "pretext": "检测到您的账号异常登录，请立即验证身份",
                "target": "全员",
                "payload": "凭证钓鱼页面",
                "success_rate": "中",
            },
        ]

        type_specific = {
            "human_rights": {
                "name": "受害者求助",
                "pretext": "我是 [国家] 的受害者，附上我的证词文档，请帮助",
                "target": "案例工作人员",
                "payload": "证词.docx (恶意文档)",
                "success_rate": "高",
            },
            "media": {
                "name": "独家爆料",
                "pretext": "我有关于 [热点事件] 的独家资料，通过安全渠道发送",
                "target": "调查记者",
                "payload": "资料包.zip (恶意压缩包)",
                "success_rate": "高",
            },
            "environmental": {
                "name": "企业内部泄露",
                "pretext": "我是 [污染企业] 内部人员，有重要证据要提供",
                "target": "调查人员",
                "payload": "内部文件.pdf (恶意PDF)",
                "success_rate": "高",
            },
            "humanitarian": {
                "name": "紧急物资需求",
                "pretext": "[灾区] 急需物资，请确认采购清单并审批",
                "target": "物流/采购人员",
                "payload": "采购清单.xlsx (恶意宏)",
                "success_rate": "中",
            },
            "political": {
                "name": "安全警告",
                "pretext": "我们发现针对贵组织的监控活动，请查看详情",
                "target": "领导层/安全负责人",
                "payload": "威胁报告.pdf (恶意PDF)",
                "success_rate": "高",
            },
        }

        scenarios["scenarios"] = base_scenarios
        if self.ngo_type in type_specific:
            scenarios["scenarios"].insert(0, type_specific[self.ngo_type])

        return scenarios

    def generate_attack_plan(self) -> List[Dict]:
        """生成攻击计划建议"""
        attacks = []

        for surface in self.results.get("attack_surfaces", []):
            if surface["risk"] in ["高", "极高"]:
                attacks.append({
                    "target": surface["subdomain"],
                    "type": surface["type"],
                    "methods": surface["attack_methods"],
                    "priority": "高" if surface["risk"] == "极高" else "中",
                })

        for vector in self.ngo_profile["attack_vectors"]:
            attacks.append({
                "target": "组织整体",
                "type": "战术",
                "methods": [vector],
                "priority": "参考",
            })

        return attacks

    def run_scan(self) -> Dict:
        """执行完整扫描"""
        console.print(Panel(
            f"[bold]目标: {self.name}[/bold]\n"
            f"域名: {self.domain}\n"
            f"类型: {self.ngo_profile['name']}",
            title="NGO 攻击面侦察"
        ))

        all_emails = set()
        all_subdomains = set()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:

            # Phase 1: 子域名发现 (crt.sh)
            task = progress.add_task("crt.sh 子域名发现...", total=None)
            crtsh_subdomains = self.discover_subdomains_crtsh()
            all_subdomains.update(crtsh_subdomains)
            progress.remove_task(task)
            console.print(f"[green][+][/green] crt.sh 发现 {len(crtsh_subdomains)} 个子域名")

            # Phase 2: theHarvester 邮箱收集
            if not self.skip_harvester:
                task = progress.add_task("theHarvester 邮箱收集...", total=None)
                harvester_result = self.run_theharvester()
                all_emails.update(harvester_result["emails"])
                all_subdomains.update(harvester_result["subdomains"])
                self.results["collected_emails"] = harvester_result["emails"]
                progress.remove_task(task)
                console.print(f"[green][+][/green] theHarvester 发现 {len(harvester_result['emails'])} 个邮箱")
            else:
                console.print(f"[yellow]![/yellow] 跳过 theHarvester")

            # Phase 3: CrossLinked LinkedIn 员工收集
            if not self.skip_crosslinked:
                task = progress.add_task("CrossLinked LinkedIn 员工收集...", total=None)
                employees = self.run_crosslinked()
                self.results["linkedin_employees"] = employees
                # 生成邮箱格式
                generated = self.generate_email_formats(employees)
                all_emails.update(generated)
                self.results["generated_emails"] = generated
                progress.remove_task(task)
                console.print(f"[green][+][/green] CrossLinked 发现 {len(employees)} 个员工, 生成 {len(generated)} 个邮箱")
            else:
                console.print(f"[yellow]![/yellow] 跳过 CrossLinked")

            # Phase 4: holehe 邮箱验证
            if not self.skip_holehe and all_emails:
                task = progress.add_task("holehe 邮箱验证...", total=None)
                verified = self.run_holehe(list(all_emails), max_emails=10)
                self.results["verified_emails"] = verified
                progress.remove_task(task)
                active_count = sum(1 for v in verified if v["platform_count"] > 0)
                console.print(f"[green][+][/green] holehe 验证 {len(verified)} 个邮箱, {active_count} 个有注册记录")
            else:
                if self.skip_holehe:
                    console.print(f"[yellow]![/yellow] 跳过 holehe 验证")

            # Phase 5: 汇总子域名和攻击面
            self.results["subdomains"] = list(all_subdomains)

            task = progress.add_task("识别 NGO 特有攻击面...", total=None)
            surfaces = self.identify_attack_surfaces(list(all_subdomains))
            self.results["attack_surfaces"] = surfaces
            progress.remove_task(task)
            console.print(f"[green][+][/green] 识别 {len(surfaces)} 个攻击入口")

            # Phase 6: 推断高价值目标
            task = progress.add_task("推断高价值目标...", total=None)
            targets = self.infer_staff_emails()
            self.results["high_value_targets"] = targets
            progress.remove_task(task)
            high_value_count = sum(1 for t in targets if t["high_value"])
            console.print(f"[green][+][/green] 识别 {high_value_count} 个高价值目标")

            # Phase 7: 生成钓鱼场景
            task = progress.add_task("生成钓鱼场景...", total=None)
            phishing = self.generate_phishing_scenarios()
            self.results["social_engineering"] = phishing
            progress.remove_task(task)
            console.print(f"[green][+][/green] 生成 {len(phishing['scenarios'])} 个钓鱼场景")

            # Phase 8: 生成攻击计划
            task = progress.add_task("生成攻击计划...", total=None)
            attacks = self.generate_attack_plan()
            self.results["recommended_attacks"] = attacks
            progress.remove_task(task)
            console.print(f"[green][+][/green] 攻击计划生成完成")

        return self.results

    def print_report(self):
        """打印报告"""
        console.print()
        console.print(Panel("[bold]侦察报告[/bold]", title="NGO 攻击面"))

        # 目标信息
        info_table = Table(title="目标信息", show_header=True)
        info_table.add_column("字段", style="cyan")
        info_table.add_column("值", style="white")
        info_table.add_row("组织名称", self.name)
        info_table.add_row("域名", self.domain)
        info_table.add_row("组织类型", self.ngo_profile["name"])
        info_table.add_row("预期威胁", ", ".join(self.ngo_profile["attack_vectors"]))
        console.print(info_table)
        console.print()

        # 收集统计
        stats_table = Table(title="收集统计", show_header=True)
        stats_table.add_column("类型", style="cyan")
        stats_table.add_column("数量", style="green")
        stats_table.add_row("子域名", str(len(self.results["subdomains"])))
        stats_table.add_row("收集的邮箱 (theHarvester)", str(len(self.results["collected_emails"])))
        stats_table.add_row("LinkedIn 员工", str(len(self.results["linkedin_employees"])))
        stats_table.add_row("生成的邮箱", str(len(self.results["generated_emails"])))
        stats_table.add_row("验证的邮箱", str(len(self.results["verified_emails"])))
        console.print(stats_table)
        console.print()

        # 收集的邮箱
        all_emails = set(self.results["collected_emails"]) | set(self.results["generated_emails"])
        if all_emails:
            email_table = Table(title="收集的邮箱", show_header=True)
            email_table.add_column("邮箱", style="cyan")
            email_table.add_column("来源", style="white")

            for email in list(all_emails)[:20]:
                source = "theHarvester" if email in self.results["collected_emails"] else "CrossLinked"
                email_table.add_row(email, source)

            if len(all_emails) > 20:
                email_table.add_row(f"... 还有 {len(all_emails) - 20} 个", "")

            console.print(email_table)
            console.print()

        # holehe 验证结果
        if self.results["verified_emails"]:
            verified_table = Table(title="邮箱验证结果 (holehe)", show_header=True)
            verified_table.add_column("邮箱", style="cyan")
            verified_table.add_column("注册平台数", style="green")

            for v in self.results["verified_emails"]:
                verified_table.add_row(v["email"], str(v["platform_count"]))

            console.print(verified_table)
            console.print()

        # 攻击面
        if self.results["attack_surfaces"]:
            surface_table = Table(title="攻击入口", show_header=True)
            surface_table.add_column("子域名", style="cyan")
            surface_table.add_column("类型", style="white")
            surface_table.add_column("风险", style="red")
            surface_table.add_column("攻击方法", style="yellow")

            for s in self.results["attack_surfaces"]:
                risk_color = "red" if s["risk"] in ["高", "极高"] else "yellow"
                surface_table.add_row(
                    s["subdomain"],
                    s["description"],
                    f"[{risk_color}]{s['risk']}[/{risk_color}]",
                    ", ".join(s["attack_methods"][:2])
                )
            console.print(surface_table)
            console.print()

        # 钓鱼场景
        scenarios = self.results.get("social_engineering", {}).get("scenarios", [])
        if scenarios:
            console.print("[bold]推荐钓鱼场景:[/bold]")
            for i, s in enumerate(scenarios[:5], 1):
                console.print(f"\n[cyan]{i}. {s['name']}[/cyan]")
                console.print(f"   话术: {s['pretext'][:50]}...")
                console.print(f"   目标: {s['target']}")
                console.print(f"   载荷: {s['payload']}")
                console.print(f"   成功率: {s['success_rate']}")

    def generate_markdown_report(self) -> str:
        """生成 Markdown 报告"""
        all_emails = set(self.results["collected_emails"]) | set(self.results["generated_emails"])

        lines = [
            f"# NGO 攻击面侦察报告",
            f"",
            f"**目标组织**: {self.name}",
            f"**目标域名**: {self.domain}",
            f"**组织类型**: {self.ngo_profile['name']}",
            f"**扫描时间**: {self.results['scan_time']}",
            f"",
            f"## 执行摘要",
            f"",
            f"- 发现子域名: {len(self.results['subdomains'])} 个",
            f"- 收集邮箱 (theHarvester): {len(self.results['collected_emails'])} 个",
            f"- LinkedIn 员工: {len(self.results['linkedin_employees'])} 个",
            f"- 生成邮箱: {len(self.results['generated_emails'])} 个",
            f"- 验证邮箱: {len(self.results['verified_emails'])} 个",
            f"- 攻击入口: {len(self.results['attack_surfaces'])} 个",
            f"- 预期威胁: {', '.join(self.ngo_profile['attack_vectors'])}",
            f"",
            f"## 收集的邮箱",
            f"",
            f"| 邮箱 | 来源 |",
            f"|------|------|",
        ]

        for email in list(all_emails)[:30]:
            source = "theHarvester" if email in self.results["collected_emails"] else "CrossLinked"
            lines.append(f"| {email} | {source} |")

        if self.results["verified_emails"]:
            lines.extend([
                f"",
                f"## 邮箱验证结果",
                f"",
                f"| 邮箱 | 注册平台数 |",
                f"|------|-----------|",
            ])
            for v in self.results["verified_emails"]:
                lines.append(f"| {v['email']} | {v['platform_count']} |")

        lines.extend([
            f"",
            f"## 攻击入口",
            f"",
            f"| 子域名 | 类型 | 风险 | 攻击方法 |",
            f"|--------|------|------|----------|",
        ])

        for s in self.results["attack_surfaces"]:
            methods = ", ".join(s["attack_methods"][:2])
            lines.append(f"| {s['subdomain']} | {s['description']} | {s['risk']} | {methods} |")

        lines.extend([
            f"",
            f"## 钓鱼场景",
            f"",
        ])

        for s in self.results.get("social_engineering", {}).get("scenarios", [])[:5]:
            lines.extend([
                f"### {s['name']}",
                f"",
                f"- **话术**: {s['pretext']}",
                f"- **目标**: {s['target']}",
                f"- **载荷**: {s['payload']}",
                f"- **成功率**: {s['success_rate']}",
                f"",
            ])

        lines.extend([
            f"## 下一步建议",
            f"",
            f"1. 使用 `/redteam-recon-enterprise` 深度扫描组织资产",
            f"2. 使用 `/redteam-recon-person` 对高价值目标进行人员画像",
            f"3. 使用 `/email-osint` 深入验证邮箱有效性",
            f"4. 使用 `/redteam-socialeng` 准备钓鱼攻击",
            f"5. 使用 `/redteam-vulnscan` 扫描发现的攻击入口",
        ])

        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="NGO 组织攻击面侦察（集成 theHarvester + CrossLinked + holehe）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 ngo_recon.py -n "Target NGO" -d target-ngo.org
  python3 ngo_recon.py -n "Human Rights Org" -d hrorg.org --type human_rights
  python3 ngo_recon.py -n "News Media" -d newsmedia.com --type media --json
  python3 ngo_recon.py -n "Target" -d target.org --skip-crosslinked  # 跳过 LinkedIn

组织类型 (--type):
  human_rights  - 人权组织
  media         - 新闻媒体
  environmental - 环保组织
  humanitarian  - 人道援助
  political     - 政治异见

工具依赖:
  - theHarvester: pip3 install theHarvester (邮箱收集)
  - crosslinked:  pip3 install crosslinked (LinkedIn 员工)
  - holehe:       email-osint 技能 (邮箱验证)
        """
    )

    parser.add_argument("-n", "--name", required=True, help="组织名称")
    parser.add_argument("-d", "--domain", required=True, help="目标域名")
    parser.add_argument("--type", default="human_rights",
                       choices=list(NGO_TYPES.keys()),
                       help="组织类型")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("-o", "--output", help="输出文件路径")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--skip-harvester", action="store_true", help="跳过 theHarvester")
    parser.add_argument("--skip-crosslinked", action="store_true", help="跳过 CrossLinked")
    parser.add_argument("--skip-holehe", action="store_true", help="跳过 holehe 验证")

    args = parser.parse_args()

    recon = NGORecon(
        name=args.name,
        domain=args.domain,
        ngo_type=args.type,
        verbose=args.verbose,
        skip_harvester=args.skip_harvester,
        skip_crosslinked=args.skip_crosslinked,
        skip_holehe=args.skip_holehe,
    )

    results = recon.run_scan()

    if args.json:
        output = json.dumps(results, indent=2, ensure_ascii=False, default=str)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            console.print(f"[green][+][/green] JSON 已保存到: {args.output}")
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
