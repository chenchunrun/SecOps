#!/usr/bin/env python3
"""
企业级目标侦察自动化脚本
整合多种信息收集工具，输出结构化报告
"""

import sys
import json
import argparse
import subprocess
import socket
import ssl
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("提示: 安装 rich 可获得更好的输出效果: pip3 install rich")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

SCRIPT_DIR = Path(__file__).parent
SKILL_DIR = SCRIPT_DIR.parent
OUTPUT_DIR = SKILL_DIR / "output"


class EnterpriseRecon:
    """企业侦察类"""

    def __init__(self, domain: str, verbose: bool = False):
        self.domain = domain
        self.verbose = verbose
        self.results = {
            "target": domain,
            "scan_time": datetime.now().isoformat(),
            "subdomains": [],
            "ips": [],
            "ports": [],
            "technologies": [],
            "certificates": [],
            "dns_records": [],
            "whois": {},
            "icp": {},
        }
        self.console = Console() if RICH_AVAILABLE else None

    def log(self, message: str, style: str = None):
        """输出日志"""
        if RICH_AVAILABLE and self.console:
            self.console.print(message, style=style)
        else:
            print(message)

    def run_command(self, cmd: List[str], timeout: int = 60) -> Optional[str]:
        """执行命令并返回输出"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout if result.returncode == 0 else None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    # ========== Phase 1: DNS 枚举 ==========

    def dns_lookup(self) -> Dict:
        """基础 DNS 查询"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

        for rtype in record_types:
            try:
                output = self.run_command(['dig', '+short', rtype, self.domain], timeout=10)
                if output:
                    records[rtype] = [r.strip() for r in output.strip().split('\n') if r.strip()]
            except:
                pass

        self.results["dns_records"] = records
        return records

    def get_a_records(self) -> List[str]:
        """获取 A 记录"""
        try:
            ips = socket.gethostbyname_ex(self.domain)[2]
            self.results["ips"].extend(ips)
            return ips
        except socket.gaierror:
            return []

    # ========== Phase 2: 子域名枚举 ==========

    def subdomain_enum_crtsh(self) -> List[str]:
        """通过 crt.sh 被动枚举子域名"""
        if not REQUESTS_AVAILABLE:
            return []

        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and '*' not in sub:
                            subdomains.add(sub)
        except Exception as e:
            if self.verbose:
                self.log(f"[!] crt.sh 查询失败: {e}", "yellow")

        return list(subdomains)

    def subdomain_enum_subfinder(self) -> List[str]:
        """使用 subfinder 枚举子域名"""
        output = self.run_command(['subfinder', '-d', self.domain, '-silent'], timeout=120)
        if output:
            return [s.strip() for s in output.strip().split('\n') if s.strip()]
        return []

    def enumerate_subdomains(self) -> List[str]:
        """综合子域名枚举"""
        all_subdomains = set()

        # crt.sh (被动)
        self.log("[*] 通过 crt.sh 枚举子域名...", "cyan")
        crtsh_subs = self.subdomain_enum_crtsh()
        all_subdomains.update(crtsh_subs)
        self.log(f"    发现 {len(crtsh_subs)} 个子域名", "green")

        # subfinder (如果可用)
        if subprocess.run(['which', 'subfinder'], capture_output=True).returncode == 0:
            self.log("[*] 通过 subfinder 枚举子域名...", "cyan")
            subfinder_subs = self.subdomain_enum_subfinder()
            all_subdomains.update(subfinder_subs)
            self.log(f"    发现 {len(subfinder_subs)} 个子域名", "green")

        self.results["subdomains"] = sorted(list(all_subdomains))
        return self.results["subdomains"]

    # ========== Phase 3: 端口扫描 ==========

    def port_scan_socket(self, host: str, ports: List[int] = None) -> List[Dict]:
        """使用 socket 进行快速端口扫描"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                     1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]

        open_ports = []

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return {"port": port, "state": "open", "host": host}
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        return open_ports

    def scan_ports(self, hosts: List[str] = None) -> List[Dict]:
        """扫描端口"""
        if hosts is None:
            hosts = self.results.get("ips", [])
            if not hosts:
                hosts = self.get_a_records()

        all_ports = []
        for host in hosts[:5]:  # 限制扫描数量
            self.log(f"[*] 扫描 {host} 端口...", "cyan")
            ports = self.port_scan_socket(host)
            all_ports.extend(ports)
            self.log(f"    发现 {len(ports)} 个开放端口", "green")

        self.results["ports"] = all_ports
        return all_ports

    # ========== Phase 4: SSL/TLS 证书 ==========

    def get_certificate(self, host: str, port: int = 443) -> Optional[Dict]:
        """获取 SSL 证书信息"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        # 尝试获取二进制证书
                        cert_bin = ssock.getpeercert(binary_form=True)
                        if cert_bin:
                            return {
                                "host": host,
                                "port": port,
                                "has_cert": True
                            }
                    else:
                        return {
                            "host": host,
                            "port": port,
                            "subject": dict(x[0] for x in cert.get('subject', [])),
                            "issuer": dict(x[0] for x in cert.get('issuer', [])),
                            "notBefore": cert.get('notBefore'),
                            "notAfter": cert.get('notAfter'),
                            "san": cert.get('subjectAltName', [])
                        }
        except Exception as e:
            if self.verbose:
                self.log(f"[!] 证书获取失败 {host}:{port}: {e}", "yellow")
        return None

    def check_certificates(self) -> List[Dict]:
        """检查证书"""
        hosts = [self.domain] + self.results.get("subdomains", [])[:10]
        certs = []

        for host in hosts:
            cert = self.get_certificate(host)
            if cert:
                certs.append(cert)

        self.results["certificates"] = certs
        return certs

    # ========== Phase 5: Web 指纹 ==========

    def detect_web_tech(self, url: str) -> Dict:
        """检测 Web 技术栈"""
        if not REQUESTS_AVAILABLE:
            return {}

        tech = {
            "url": url,
            "server": None,
            "technologies": [],
            "headers": {}
        }

        try:
            resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            tech["status_code"] = resp.status_code
            tech["headers"] = dict(resp.headers)

            # Server header
            if 'Server' in resp.headers:
                tech["server"] = resp.headers['Server']

            # X-Powered-By
            if 'X-Powered-By' in resp.headers:
                tech["technologies"].append(resp.headers['X-Powered-By'])

            # 检测常见框架
            body = resp.text.lower()
            patterns = {
                'WordPress': ['wp-content', 'wp-includes'],
                'Drupal': ['drupal', 'sites/default'],
                'Joomla': ['joomla', '/components/'],
                'Django': ['csrfmiddlewaretoken', '__admin__'],
                'Laravel': ['laravel_session'],
                'React': ['react', '_reactroot'],
                'Vue.js': ['vue', 'v-if', 'v-for'],
                'Angular': ['ng-app', 'angular'],
                'jQuery': ['jquery'],
                'Bootstrap': ['bootstrap'],
            }

            for framework, keywords in patterns.items():
                if any(kw in body for kw in keywords):
                    tech["technologies"].append(framework)

        except Exception as e:
            if self.verbose:
                self.log(f"[!] Web 检测失败 {url}: {e}", "yellow")

        return tech

    def scan_web_tech(self) -> List[Dict]:
        """扫描 Web 技术"""
        urls = [f"https://{self.domain}", f"http://{self.domain}"]
        for sub in self.results.get("subdomains", [])[:5]:
            urls.append(f"https://{sub}")

        technologies = []
        for url in urls:
            self.log(f"[*] 检测 {url}...", "cyan")
            tech = self.detect_web_tech(url)
            if tech.get("status_code"):
                technologies.append(tech)

        self.results["technologies"] = technologies
        return technologies

    # ========== 报告生成 ==========

    def generate_report(self) -> str:
        """生成 Markdown 报告"""
        report = []
        report.append(f"# 企业侦察报告: {self.domain}")
        report.append(f"\n**扫描时间**: {self.results['scan_time']}")
        report.append("")

        # 子域名
        report.append("## 子域名发现")
        report.append(f"\n共发现 **{len(self.results['subdomains'])}** 个子域名:\n")
        if self.results['subdomains']:
            report.append("| 子域名 | 类型 |")
            report.append("|--------|------|")
            for sub in self.results['subdomains'][:50]:
                sub_type = self._classify_subdomain(sub)
                report.append(f"| {sub} | {sub_type} |")
            if len(self.results['subdomains']) > 50:
                report.append(f"\n*... 还有 {len(self.results['subdomains']) - 50} 个子域名*")
        report.append("")

        # IP 地址
        report.append("## IP 地址")
        if self.results['ips']:
            report.append("\n| IP | 说明 |")
            report.append("|-----|------|")
            for ip in set(self.results['ips']):
                report.append(f"| {ip} | - |")
        report.append("")

        # 开放端口
        report.append("## 开放端口")
        if self.results['ports']:
            report.append("\n| 主机 | 端口 | 状态 |")
            report.append("|------|------|------|")
            for p in self.results['ports']:
                report.append(f"| {p['host']} | {p['port']} | {p['state']} |")
        report.append("")

        # 技术栈
        report.append("## 技术栈识别")
        if self.results['technologies']:
            for tech in self.results['technologies']:
                report.append(f"\n### {tech.get('url', 'Unknown')}")
                report.append(f"- **状态码**: {tech.get('status_code', 'N/A')}")
                report.append(f"- **服务器**: {tech.get('server', 'N/A')}")
                if tech.get('technologies'):
                    report.append(f"- **框架**: {', '.join(tech['technologies'])}")
        report.append("")

        # DNS 记录
        report.append("## DNS 记录")
        if self.results['dns_records']:
            for rtype, records in self.results['dns_records'].items():
                if records:
                    report.append(f"\n**{rtype}**: {', '.join(records[:5])}")
        report.append("")

        # 攻击面评估
        report.append("## 攻击面评估")
        report.append("\n| 入口点 | 风险等级 | 说明 |")
        report.append("|--------|---------|------|")
        attack_surface = self._assess_attack_surface()
        for entry in attack_surface:
            report.append(f"| {entry['point']} | {entry['risk']} | {entry['note']} |")

        return "\n".join(report)

    def _classify_subdomain(self, subdomain: str) -> str:
        """分类子域名"""
        patterns = {
            "邮件": ["mail", "smtp", "imap", "pop", "webmail", "owa", "exchange"],
            "VPN": ["vpn", "remote", "ssl", "gateway"],
            "API": ["api", "rest", "graphql", "ws"],
            "开发": ["dev", "test", "staging", "uat", "qa"],
            "管理": ["admin", "portal", "cms", "manage", "console"],
            "CDN": ["cdn", "static", "assets", "img"],
            "数据库": ["db", "mysql", "postgres", "mongo", "redis"],
        }

        sub_lower = subdomain.lower()
        for category, keywords in patterns.items():
            if any(kw in sub_lower for kw in keywords):
                return category
        return "通用"

    def _assess_attack_surface(self) -> List[Dict]:
        """评估攻击面"""
        surface = []

        # 检查开发环境
        dev_subs = [s for s in self.results['subdomains']
                    if any(kw in s.lower() for kw in ['dev', 'test', 'staging'])]
        if dev_subs:
            surface.append({
                "point": f"开发环境 ({len(dev_subs)}个)",
                "risk": "[!] 高",
                "note": "可能存在弱配置或测试账号"
            })

        # 检查 VPN
        vpn_subs = [s for s in self.results['subdomains']
                    if any(kw in s.lower() for kw in ['vpn', 'remote'])]
        if vpn_subs:
            surface.append({
                "point": f"VPN 入口 ({len(vpn_subs)}个)",
                "risk": "[*] 中",
                "note": "远程访问入口，可尝试凭证爆破"
            })

        # 检查敏感端口
        sensitive_ports = [p for p in self.results['ports']
                          if p['port'] in [22, 3389, 3306, 5432, 6379]]
        if sensitive_ports:
            surface.append({
                "point": f"敏感端口 ({len(sensitive_ports)}个)",
                "risk": "[!] 高",
                "note": "SSH/RDP/数据库端口暴露"
            })

        # 默认
        if not surface:
            surface.append({
                "point": "Web 应用",
                "risk": "[*] 中",
                "note": "标准 Web 攻击面"
            })

        return surface

    def run_full_scan(self):
        """执行完整扫描"""
        self.log(Panel(f"[bold]目标: {self.domain}[/bold]", title="企业侦察"),
                 style="cyan") if RICH_AVAILABLE else self.log(f"\n=== 目标: {self.domain} ===\n")

        # Phase 1: DNS
        self.log("\n[Phase 1] DNS 枚举", "bold cyan")
        self.dns_lookup()
        self.get_a_records()

        # Phase 2: 子域名
        self.log("\n[Phase 2] 子域名枚举", "bold cyan")
        self.enumerate_subdomains()

        # Phase 3: 端口扫描
        self.log("\n[Phase 3] 端口扫描", "bold cyan")
        self.scan_ports()

        # Phase 4: SSL 证书
        self.log("\n[Phase 4] SSL 证书检查", "bold cyan")
        self.check_certificates()

        # Phase 5: Web 技术
        self.log("\n[Phase 5] Web 技术识别", "bold cyan")
        self.scan_web_tech()

        return self.results


def main():
    parser = argparse.ArgumentParser(description="企业级目标侦察")
    parser.add_argument("-d", "--domain", required=True, help="目标域名")
    parser.add_argument("-o", "--output", help="输出文件路径")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--json", action="store_true", help="输出 JSON 格式")

    args = parser.parse_args()

    recon = EnterpriseRecon(args.domain, verbose=args.verbose)
    results = recon.run_full_scan()

    # 输出结果
    if args.json:
        output = json.dumps(results, indent=2, ensure_ascii=False)
    else:
        output = recon.generate_report()

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding='utf-8')
        print(f"\n报告已保存至: {output_path}")
    else:
        print(output)


if __name__ == "__main__":
    main()
