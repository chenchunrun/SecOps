#!/usr/bin/env python3
"""
IOC 提取工具 — 从 PCAP 文件中提取网络威胁指标
输出格式: JSON (可被其他安全技能消费)

用法:
    python3 extract_iocs.py <file.pcap> [-o output.json]
    python3 extract_iocs.py <file.pcap> --format ci   # CI 输出 (defanged)

依赖: tshark (优先) 或 scapy (兜底)
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ===== 配置 =====

INTERNAL_RANGES = [
    # IPv4 私有地址段
    (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
    (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),  # 192.168.0.0/16
    (0x7F000000, 0x7FFFFFFF),  # 127.0.0.0/8 (loopback)
    (0xA9FE0000, 0xA9FEFFFF),  # 169.254.0.0/16 (link-local)
]

# 已知恶意 UA 模式
SUSPICIOUS_UA_PATTERNS = [
    re.compile(r'meterpreter', re.I),
    re.compile(r'cobalt.?strike', re.I),
    re.compile(r'metasploit', re.I),
    re.compile(r'nikto', re.I),
    re.compile(r'sqlmap', re.I),
    re.compile(r'nmap', re.I),
    re.compile(r'masscan', re.I),
    re.compile(r'zgrab', re.I),
    re.compile(r'python-requests/\d', re.I),  # 脚本化请求
    re.compile(r'curl/\d', re.I),
    re.compile(r'wget/\d', re.I),
    re.compile(r'^$', re.I),  # 空 UA
]

# C2 URI 模式
C2_URI_PATTERNS = [
    re.compile(r'^/[a-z0-9]{8,}/$'),  # 随机路径
    re.compile(r'^/\w{32,}$'),  # 长随机串
    re.compile(r'\.(php|jsp|asp|aspx)\?[a-z0-9]{20,}', re.I),  # 长参数
    re.compile(r'/api/v\d+/.*[A-Za-z0-9+/]{40,}'),  # Base64 编码 API
]

# DNS 隧道特征
DGA_PATTERNS = [
    re.compile(r'^[a-z0-9]{15,}\.', re.I),  # 超长子域名
    re.compile(r'[a-z]\d[a-z]\d[a-z]\d', re.I),  # 交替字母数字
    re.compile(r'[bcdfghjklmnpqrstvwxz]{8,}', re.I),  # 连续辅音
]


def is_internal_ip(ip_str):
    """检查是否为内网 IP"""
    try:
        parts = ip_str.split('.')
        if len(parts) != 4:
            return True  # IPv6 默认视为内网
        ip_int = (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
                 (int(parts[2]) << 8) + int(parts[3])
        for start, end in INTERNAL_RANGES:
            if start <= ip_int <= end:
                return True
        return False
    except (ValueError, IndexError):
        return True


def defang_ioc(ioc_str):
    """消毒 IOC — 使用 [.] 替换实际的点"""
    return ioc_str.replace('.', '[.]')


def find_tshark():
    """查找 tshark 路径"""
    env_path = os.environ.get('CYBERSEC_TSHARK_PATH')
    if env_path and os.path.isfile(env_path):
        return env_path
    return shutil.which('tshark')


def run_tshark(pcap_file, fields, display_filter=None, extra_args=None):
    """执行 tshark 命令提取字段"""
    tshark = find_tshark()
    if not tshark:
        return []

    cmd = [tshark, '-r', pcap_file, '-T', 'fields']
    for f in fields:
        cmd.extend(['-e', f])
    if display_filter:
        cmd.extend(['-Y', display_filter])
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout.strip().split('\n') if result.stdout.strip() else []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def extract_ips(pcap_file):
    """提取外部 IP 地址"""
    ips = set()

    # 目的 IP
    for line in run_tshark(pcap_file, ['ip.dst']):
        for ip in line.split(','):
            ip = ip.strip()
            if ip and not is_internal_ip(ip):
                ips.add(ip)

    # 源 IP
    for line in run_tshark(pcap_file, ['ip.src']):
        for ip in line.split(','):
            ip = ip.strip()
            if ip and not is_internal_ip(ip):
                ips.add(ip)

    return sorted(ips)


def extract_domains(pcap_file):
    """提取域名（DNS 查询 + TLS SNI）"""
    domains = set()

    # DNS 查询
    for line in run_tshark(pcap_file, ['dns.qry.name']):
        for domain in line.split(','):
            domain = domain.strip().lower()
            if domain and domain != 'root-servers.net':
                # 过滤反向解析
                if not domain.endswith('.in-addr.arpa') and not domain.endswith('.ip6.arpa'):
                    domains.add(domain)

    # TLS SNI
    for line in run_tshark(pcap_file, ['tls.handshake.extensions_server_name']):
        domain = line.strip().lower()
        if domain:
            domains.add(domain)

    return sorted(domains)


def extract_urls(pcap_file):
    """提取 URL"""
    urls = set()
    for line in run_tshark(pcap_file, ['http.host', 'http.request.uri', 'http.request.method']):
        parts = line.split('\t')
        if len(parts) >= 2 and parts[0]:
            host = parts[0]
            uri = parts[1] if len(parts) > 1 else '/'
            method = parts[2] if len(parts) > 2 else 'GET'
            url = f"http://{host}{uri}"
            urls.add((method, url))

    # HTTPS URLs (从 Host + URI 推断)
    for line in run_tshark(pcap_file, ['tls.handshake.extensions_server_name']):
        domain = line.strip()
        if domain and not is_internal_ip(domain):
            urls.add(('TLS', f"https://{domain}/"))

    return [(m, u) for m, u in sorted(urls)]


def extract_user_agents(pcap_file):
    """提取 User-Agent"""
    uas = set()
    for line in run_tshark(pcap_file, ['http.user_agent']):
        ua = line.strip()
        if ua:
            uas.add(ua)
    return sorted(uas)


def extract_ja3(pcap_file):
    """提取 JA3 指纹"""
    ja3s = set()
    for line in run_tshark(pcap_file, ['tls.handshake.ja3']):
        ja3 = line.strip()
        if ja3 and ja3 != '0':
            ja3s.add(ja3)
    return sorted(ja3s)


def extract_dns_records(pcap_file):
    """提取异常 DNS 记录"""
    suspicious = []

    # TXT 记录
    for line in run_tshark(pcap_file, ['dns.qry.name', 'dns.txt'], 'dns.qry.type == 16'):
        parts = line.split('\t')
        domain = parts[0].strip() if parts else ''
        txt = parts[1].strip() if len(parts) > 1 else ''
        if txt:
            suspicious.append({'type': 'TXT', 'domain': domain, 'value': txt})

    # 超长域名（DNS 隧道）
    for line in run_tshark(pcap_file, ['dns.qry.name']):
        for domain in line.split(','):
            domain = domain.strip()
            if len(domain) > 50:
                suspicious.append({'type': 'LONG_DOMAIN', 'domain': domain, 'value': str(len(domain))})

    return suspicious


def assess_suspicious(iocs):
    """评估 IOC 可疑程度"""
    threats = []

    # 可疑 User-Agent
    for ua in iocs.get('user_agents', []):
        for pattern in SUSPICIOUS_UA_PATTERNS:
            if pattern.search(ua):
                threats.append({
                    'category': 'Suspicious User-Agent',
                    'indicator': ua,
                    'severity': 'medium',
                    'reason': f'Matched pattern: {pattern.pattern}'
                })
                break

    # DNS 隧道特征
    for record in iocs.get('dns_anomalies', []):
        if record['type'] == 'LONG_DOMAIN':
            threats.append({
                'category': 'DNS Tunneling',
                'indicator': record['domain'],
                'severity': 'high',
                'reason': f"Domain length {record['value']} exceeds threshold"
            })
        elif record['type'] == 'TXT':
            threats.append({
                'category': 'DNS TXT Exfiltration',
                'indicator': f"{record['domain']} -> {record['value'][:50]}",
                'severity': 'medium',
                'reason': 'Unusual TXT record in DNS query'
            })

    # DGA 域名
    for domain in iocs.get('domains', []):
        for pattern in DGA_PATTERNS:
            if pattern.search(domain):
                threats.append({
                    'category': 'DGA Domain',
                    'indicator': domain,
                    'severity': 'high',
                    'reason': f'Matched DGA pattern: {pattern.pattern}'
                })
                break

    return threats


def main():
    parser = argparse.ArgumentParser(
        description='从 PCAP 文件中提取 IOC（威胁指标）'
    )
    parser.add_argument('pcap', help='PCAP 文件路径')
    parser.add_argument('-o', '--output', help='输出 JSON 文件路径')
    parser.add_argument('--format', choices=['json', 'ci'], default='json',
                       help='json=标准JSON, ci=消毒格式(默认json)')
    parser.add_argument('--summary', action='store_true', help='仅输出摘要')
    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"❌ 文件不存在: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    if not find_tshark():
        print("⚠️  tshark 未安装，仅支持基础分析", file=sys.stderr)

    print(f"🔍 分析 PCAP: {args.pcap}", file=sys.stderr)

    # 提取 IOC
    iocs = {
        'pcap_file': os.path.basename(args.pcap),
        'ips': extract_ips(args.pcap),
        'domains': extract_domains(args.pcap),
        'urls': extract_urls(args.pcap),
        'user_agents': extract_user_agents(args.pcap),
        'ja3_fingerprints': extract_ja3(args.pcap),
        'dns_anomalies': extract_dns_records(args.pcap),
    }

    # 评估可疑程度
    threats = assess_suspicious(iocs)
    iocs['threats'] = threats
    iocs['threat_count'] = len(threats)
    iocs['summary'] = {
        'total_ips': len(iocs['ips']),
        'total_domains': len(iocs['domains']),
        'total_urls': len(iocs['urls']),
        'total_user_agents': len(iocs['user_agents']),
        'total_ja3': len(iocs['ja3_fingerprints']),
        'total_dns_anomalies': len(iocs['dns_anomalies']),
        'total_threats': len(threats),
    }

    # CI 消毒格式
    if args.format == 'ci':
        iocs['ips'] = [defang_ioc(ip) for ip in iocs['ips']]
        iocs['domains'] = [defang_ioc(d) for d in iocs['domains']]
        iocs['urls'] = [(m, defang_ioc(u)) for m, u in iocs['urls']]

    # 输出
    if args.summary:
        print(f"\n📊 IOC 提取摘要")
        print(f"━" * 40)
        print(f"  外部 IP:      {iocs['summary']['total_ips']}")
        print(f"  域名:         {iocs['summary']['total_domains']}")
        print(f"  URL:          {iocs['summary']['total_urls']}")
        print(f"  User-Agent:   {iocs['summary']['total_user_agents']}")
        print(f"  JA3 指纹:     {iocs['summary']['total_ja3']}")
        print(f"  DNS 异常:     {iocs['summary']['total_dns_anomalies']}")
        print(f"  ⚠️ 威胁指标:  {iocs['summary']['total_threats']}")
        if threats:
            print(f"\n🔴 可疑活动:")
            for t in threats:
                print(f"  [{t['severity'].upper()}] {t['category']}: {t['indicator']}")
    else:
        output = json.dumps(iocs, indent=2, ensure_ascii=False, default=str)
        if args.output:
            Path(args.output).write_text(output)
            print(f"✅ IOC 已保存到: {args.output}", file=sys.stderr)
        else:
            print(output)


if __name__ == '__main__':
    main()
