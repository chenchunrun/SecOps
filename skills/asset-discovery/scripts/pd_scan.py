#!/usr/bin/env python3
"""
ProjectDiscovery 工具链扫描脚本
基于 subfinder → dnsx → naabu → httpx → tlsx 流程

使用方法:
    python3 pd_scan.py --domain example.com --mode quick
    python3 pd_scan.py --domain example.com --mode standard --output ./output
    python3 pd_scan.py --domain example.com --mode full
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse


class PDScanner:
    """ProjectDiscovery 工具链扫描器"""

    def __init__(self, domain: str, output_dir: str, mode: str = "standard"):
        self.domain = domain
        self.output_dir = Path(output_dir)
        self.mode = mode
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Go bin path
        self.go_bin = os.path.expanduser("~/go/bin")
        os.environ["PATH"] = f"{self.go_bin}:{os.environ.get('PATH', '')}"

        # 统计数据
        self.stats = {
            "domain": domain,
            "scan_time": datetime.now().isoformat(),
            "mode": mode,
            "subdomains": 0,
            "alive_domains": 0,
            "unique_ips": 0,
            "open_ports": 0,
            "http_services": 0,
            "tls_certs": 0,
        }

    def log(self, msg: str):
        """打印日志"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def run_cmd(self, cmd: str, timeout: int = 300) -> tuple:
        """运行命令并返回结果"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", -1
        except Exception as e:
            return "", str(e), -1

    def step1_subfinder(self) -> int:
        """Step 1: 子域名发现"""
        self.log("Step 1: subfinder - 子域名发现")
        output_file = self.output_dir / "1_subdomains.txt"

        cmd = f"subfinder -d {self.domain} -all -recursive -silent -o {output_file}"
        stdout, stderr, code = self.run_cmd(cmd, timeout=600)

        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                count = sum(1 for _ in f)
            self.stats["subdomains"] = count
            self.log(f"  发现 {count} 个子域名")
            return count
        return 0

    def step2_dnsx(self) -> int:
        """Step 2: DNS 解析验证"""
        self.log("Step 2: dnsx - DNS 解析验证")
        input_file = self.output_dir / "1_subdomains.txt"
        output_file = self.output_dir / "2_resolved.txt"
        alive_file = self.output_dir / "2_alive.txt"

        if not input_file.exists():
            self.log("  跳过: 无子域名输入")
            return 0

        cmd = f"dnsx -l {input_file} -a -aaaa -cname -resp -silent -o {output_file}"
        stdout, stderr, code = self.run_cmd(cmd, timeout=600)

        # 提取存活域名
        if output_file.exists():
            domains = set()
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parts = line.strip().split()
                    if parts:
                        domains.add(parts[0])

            with open(alive_file, 'w', encoding='utf-8') as f:
                for d in sorted(domains):
                    f.write(d + '\n')

            self.stats["alive_domains"] = len(domains)
            self.log(f"  存活 {len(domains)} 个域名")
            return len(domains)
        return 0

    def step3_naabu(self) -> int:
        """Step 3: 端口扫描"""
        if self.mode == "quick":
            self.log("Step 3: naabu - 跳过 (quick 模式)")
            return 0

        self.log("Step 3: naabu - 端口扫描")
        input_file = self.output_dir / "2_alive.txt"
        output_file = self.output_dir / "3_ports.txt"

        if not input_file.exists():
            self.log("  跳过: 无存活域名")
            return 0

        # 使用常用端口
        ports = "80,443,8080,8443,22,21,3389,3306,5432,6379,27017"
        cmd = f"naabu -l {input_file} -p {ports} -c 25 -rate 100 -silent -o {output_file}"
        stdout, stderr, code = self.run_cmd(cmd, timeout=600)

        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                count = sum(1 for _ in f)
            self.stats["open_ports"] = count
            self.log(f"  发现 {count} 个开放端口")
            return count
        return 0

    def step4_httpx(self) -> int:
        """Step 4: HTTP 探测"""
        self.log("Step 4: httpx - HTTP 探测")

        # 准备输入
        if self.mode == "quick":
            input_file = self.output_dir / "2_alive.txt"
        else:
            input_file = self.output_dir / "3_ports.txt"
            if not input_file.exists():
                input_file = self.output_dir / "2_alive.txt"

        output_file = self.output_dir / "4_http.json"

        if not input_file.exists():
            self.log("  跳过: 无输入")
            return 0

        cmd = f"httpx -l {input_file} -title -status-code -tech-detect -ip -cdn -server -json -silent -o {output_file}"
        stdout, stderr, code = self.run_cmd(cmd, timeout=600)

        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                count = sum(1 for _ in f)
            self.stats["http_services"] = count
            self.log(f"  发现 {count} 个 HTTP 服务")
            return count
        return 0

    def step5_tlsx(self) -> int:
        """Step 5: TLS 证书分析"""
        if self.mode == "quick":
            self.log("Step 5: tlsx - 跳过 (quick 模式)")
            return 0

        self.log("Step 5: tlsx - TLS 证书分析")
        http_file = self.output_dir / "4_http.json"
        hosts_file = self.output_dir / "5_https_hosts.txt"
        output_file = self.output_dir / "5_tls.json"

        if not http_file.exists():
            self.log("  跳过: 无 HTTP 数据")
            return 0

        # 提取 HTTPS 主机
        hosts = set()
        with open(http_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if data.get('scheme') == 'https':
                        hosts.add(data.get('host', ''))
                except:
                    pass

        if not hosts:
            self.log("  跳过: 无 HTTPS 主机")
            return 0

        with open(hosts_file, 'w', encoding='utf-8') as f:
            for h in hosts:
                if h:
                    f.write(h + '\n')

        cmd = f"tlsx -l {hosts_file} -json -silent -o {output_file}"
        stdout, stderr, code = self.run_cmd(cmd, timeout=300)

        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                count = sum(1 for _ in f)
            self.stats["tls_certs"] = count
            self.log(f"  分析 {count} 个证书")
            return count
        return 0

    def import_to_sqlite(self):
        """导入数据到 SQLite"""
        self.log("导入数据到 SQLite...")
        db_path = self.output_dir / "assets.db"
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # 创建表
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                source TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                record_type TEXT,
                value TEXT,
                UNIQUE(domain, record_type, value)
            );

            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                UNIQUE(host, port)
            );

            CREATE TABLE IF NOT EXISTS http_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                host TEXT,
                port INTEGER,
                scheme TEXT,
                status_code INTEGER,
                title TEXT,
                server TEXT,
                technologies TEXT,
                ip TEXT
            );

            CREATE TABLE IF NOT EXISTS tls_certs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 443,
                subject_cn TEXT,
                issuer_cn TEXT,
                tls_version TEXT,
                not_after TIMESTAMP,
                wildcard BOOLEAN
            );

            CREATE INDEX IF NOT EXISTS idx_http_host ON http_services(host);
            CREATE INDEX IF NOT EXISTS idx_http_status ON http_services(status_code);
        """)
        conn.commit()

        # 导入子域名
        subdomains_file = self.output_dir / "1_subdomains.txt"
        if subdomains_file.exists():
            with open(subdomains_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        try:
                            cursor.execute(
                                "INSERT OR IGNORE INTO subdomains (domain, source) VALUES (?, ?)",
                                (domain, 'subfinder')
                            )
                        except:
                            pass
            conn.commit()

        # 导入端口
        ports_file = self.output_dir / "3_ports.txt"
        if ports_file.exists():
            with open(ports_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        parts = line.rsplit(':', 1)
                        if len(parts) == 2:
                            try:
                                cursor.execute(
                                    "INSERT OR IGNORE INTO ports (host, port) VALUES (?, ?)",
                                    (parts[0], int(parts[1]))
                                )
                            except:
                                pass
            conn.commit()

        # 导入 HTTP 服务
        http_file = self.output_dir / "4_http.json"
        if http_file.exists():
            with open(http_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        parsed = urlparse(data.get('url', ''))
                        cursor.execute("""
                            INSERT OR REPLACE INTO http_services
                            (url, host, port, scheme, status_code, title, server, technologies, ip)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            data.get('url'),
                            parsed.hostname,
                            parsed.port or (443 if parsed.scheme == 'https' else 80),
                            parsed.scheme,
                            data.get('status_code'),
                            data.get('title'),
                            data.get('webserver'),
                            json.dumps(data.get('tech', [])),
                            data.get('host_ip')
                        ))
                    except:
                        pass
            conn.commit()

        # 导入 TLS
        tls_file = self.output_dir / "5_tls.json"
        if tls_file.exists():
            with open(tls_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        cursor.execute("""
                            INSERT OR REPLACE INTO tls_certs
                            (host, port, subject_cn, issuer_cn, tls_version, not_after, wildcard)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (
                            data.get('host'),
                            data.get('port', 443),
                            data.get('subject_cn'),
                            data.get('issuer_cn'),
                            data.get('tls_version'),
                            data.get('not_after'),
                            data.get('wildcard_certificate', False)
                        ))
                    except:
                        pass
            conn.commit()

        conn.close()
        self.log(f"  数据库: {db_path}")

    def analyze_results(self) -> dict:
        """分析扫描结果"""
        self.log("分析扫描结果...")

        analysis = {
            "high_value_targets": {
                "login_pages": [],
                "api_endpoints": [],
                "admin_panels": [],
                "test_environments": []
            },
            "technology_stack": {
                "web_servers": defaultdict(int),
                "frameworks": defaultdict(int),
                "tls_versions": defaultdict(int)
            },
            "subdomain_patterns": defaultdict(int),
            "status_codes": defaultdict(int)
        }

        # 分析 HTTP 服务
        http_file = self.output_dir / "4_http.json"
        if http_file.exists():
            with open(http_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        url = data.get('url', '').lower()
                        title = (data.get('title') or '').lower()
                        status = data.get('status_code', 0)

                        analysis["status_codes"][status] += 1

                        # 服务器
                        server = data.get('webserver')
                        if server:
                            analysis["technology_stack"]["web_servers"][server] += 1

                        # 技术栈
                        for tech in data.get('tech', []):
                            analysis["technology_stack"]["frameworks"][tech] += 1

                        if status == 200:
                            # 登录页面
                            if any(kw in url or kw in title for kw in ['login', '登录', 'signin', 'auth', 'sso']):
                                analysis["high_value_targets"]["login_pages"].append({
                                    "url": data.get('url'),
                                    "title": data.get('title')
                                })

                            # API 端点
                            if any(kw in url for kw in ['api', 'gateway', 'openapi']):
                                analysis["high_value_targets"]["api_endpoints"].append({
                                    "url": data.get('url'),
                                    "title": data.get('title')
                                })

                            # 管理后台
                            if any(kw in url or kw in title for kw in ['admin', '管理', 'console', 'dashboard']):
                                analysis["high_value_targets"]["admin_panels"].append({
                                    "url": data.get('url'),
                                    "title": data.get('title')
                                })

                            # 测试环境
                            if any(kw in url for kw in ['test', 'tst', 'uat', 'dev', 'staging', 'gray']):
                                analysis["high_value_targets"]["test_environments"].append({
                                    "url": data.get('url'),
                                    "title": data.get('title')
                                })
                    except:
                        pass

        # 分析子域名模式
        subdomains_file = self.output_dir / "1_subdomains.txt"
        if subdomains_file.exists():
            with open(subdomains_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    domain = line.strip()
                    parts = domain.split('.')
                    if len(parts) > 2:
                        pattern = parts[-3]
                        analysis["subdomain_patterns"][pattern] += 1

        # 分析 TLS
        tls_file = self.output_dir / "5_tls.json"
        if tls_file.exists():
            with open(tls_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        tls_ver = data.get('tls_version', 'unknown')
                        analysis["technology_stack"]["tls_versions"][tls_ver] += 1
                    except:
                        pass

        return analysis

    def generate_summary(self, analysis: dict):
        """生成摘要 JSON"""
        summary = {
            "target": self.domain,
            "scan_time": self.stats["scan_time"],
            "mode": self.mode,
            "statistics": {
                "subdomains": self.stats["subdomains"],
                "alive_domains": self.stats["alive_domains"],
                "open_ports": self.stats["open_ports"],
                "http_services": self.stats["http_services"],
                "tls_certs": self.stats["tls_certs"]
            },
            "high_value_targets": {
                "login_pages": len(analysis["high_value_targets"]["login_pages"]),
                "api_endpoints": len(analysis["high_value_targets"]["api_endpoints"]),
                "admin_panels": len(analysis["high_value_targets"]["admin_panels"]),
                "test_environments": len(analysis["high_value_targets"]["test_environments"]),
                "details": analysis["high_value_targets"]
            },
            "technology_stack": {
                "web_servers": dict(sorted(
                    analysis["technology_stack"]["web_servers"].items(),
                    key=lambda x: x[1], reverse=True
                )[:10]),
                "frameworks": dict(sorted(
                    analysis["technology_stack"]["frameworks"].items(),
                    key=lambda x: x[1], reverse=True
                )[:15]),
                "tls_versions": dict(analysis["technology_stack"]["tls_versions"])
            },
            "subdomain_patterns": dict(sorted(
                analysis["subdomain_patterns"].items(),
                key=lambda x: x[1], reverse=True
            )[:20]),
            "status_codes": dict(sorted(
                analysis["status_codes"].items(),
                key=lambda x: x[1], reverse=True
            ))
        }

        summary_file = self.output_dir / "summary.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

        self.log(f"  摘要: {summary_file}")
        return summary

    def print_summary(self, summary: dict):
        """打印扫描摘要"""
        print("\n" + "=" * 60)
        print(f"扫描完成: {self.domain}")
        print("=" * 60)
        print(f"  子域名:     {summary['statistics']['subdomains']}")
        print(f"  存活域名:   {summary['statistics']['alive_domains']}")
        print(f"  开放端口:   {summary['statistics']['open_ports']}")
        print(f"  HTTP服务:   {summary['statistics']['http_services']}")
        print(f"  TLS证书:    {summary['statistics']['tls_certs']}")
        print()
        print("高价值目标:")
        print(f"  登录入口:   {summary['high_value_targets']['login_pages']}")
        print(f"  API端点:    {summary['high_value_targets']['api_endpoints']}")
        print(f"  管理后台:   {summary['high_value_targets']['admin_panels']}")
        print(f"  测试环境:   {summary['high_value_targets']['test_environments']}")
        print()
        print(f"输出目录: {self.output_dir}")
        print("=" * 60)

    def run(self):
        """执行完整扫描流程"""
        print("=" * 60)
        print(f"ProjectDiscovery 扫描: {self.domain}")
        print(f"模式: {self.mode} | 输出: {self.output_dir}")
        print("=" * 60)

        # 执行扫描步骤
        self.step1_subfinder()
        self.step2_dnsx()
        self.step3_naabu()
        self.step4_httpx()
        self.step5_tlsx()

        # 数据处理
        self.import_to_sqlite()
        analysis = self.analyze_results()
        summary = self.generate_summary(analysis)

        # 打印摘要
        self.print_summary(summary)

        return summary


def main():
    parser = argparse.ArgumentParser(description='ProjectDiscovery 工具链扫描')
    parser.add_argument('--domain', '-d', required=True, help='目标域名')
    parser.add_argument('--output', '-o', default='./pd_output', help='输出目录')
    parser.add_argument('--mode', '-m', choices=['quick', 'standard', 'full'],
                       default='standard', help='扫描模式')

    args = parser.parse_args()

    scanner = PDScanner(args.domain, args.output, args.mode)
    scanner.run()


if __name__ == "__main__":
    main()
