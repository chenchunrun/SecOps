#!/usr/bin/env python3
"""
从 SSL 证书文本中提取关联域名

用法:
    python extract_ssl_domains.py <ssl_text_file>
    echo "<ssl_text>" | python extract_ssl_domains.py -

示例:
    python extract_ssl_domains.py cert.txt
    python extract_ssl_domains.py - < cert.txt
"""

import re
import sys
import json
import argparse
from typing import List, Set, Dict
from dataclasses import dataclass, asdict


@dataclass
class DomainInfo:
    """域名信息"""
    domain: str
    source: str  # "CN" | "SAN"
    valid: bool = True


def extract_domains_from_ssl(ssl_text: str) -> List[DomainInfo]:
    """
    从 SSL 证书文本中提取域名

    Args:
        ssl_text: SSL 证书的文本表示

    Returns:
        提取到的域名列表
    """
    domains: List[DomainInfo] = []
    seen: Set[str] = set()

    # 提取 Subject CN
    cn_patterns = [
        r'Subject:\s*CN=([^\s,\n]+)',
        r'Subject:.*?CN\s*=\s*([^\s,\n]+)',
    ]

    for pattern in cn_patterns:
        cn_match = re.search(pattern, ssl_text, re.IGNORECASE)
        if cn_match:
            domain = cn_match.group(1).strip()
            if domain and domain not in seen and is_valid_domain(domain):
                domains.append(DomainInfo(domain=domain, source="CN"))
                seen.add(domain)
            break

    # 提取 SAN DNS 条目
    san_patterns = [
        r'DNS:([^\s,\n]+)',
        r'Subject Alternative Name:\s*DNS:([^\s,\n]+)',
    ]

    for pattern in san_patterns:
        san_matches = re.findall(pattern, ssl_text, re.IGNORECASE)
        for domain in san_matches:
            domain = domain.strip()
            if domain and domain not in seen and is_valid_domain(domain):
                domains.append(DomainInfo(domain=domain, source="SAN"))
                seen.add(domain)

    return domains


def is_valid_domain(domain: str) -> bool:
    """
    检查是否为有效域名（排除 IP 地址等）

    Args:
        domain: 待检查的字符串

    Returns:
        是否为有效域名
    """
    # 排除 IP 地址
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        return False

    # 排除 localhost
    if domain.lower() in ('localhost', 'localhost.localdomain'):
        return False

    # 基本域名格式检查
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', domain):
        return False

    return True


def extract_cert_validity(ssl_text: str) -> Dict[str, str]:
    """
    提取证书有效期

    Args:
        ssl_text: SSL 证书文本

    Returns:
        包含 not_before 和 not_after 的字典
    """
    validity = {}

    not_before = re.search(r'Not Before:\s*(.+?)(?:\n|UTC)', ssl_text)
    if not_before:
        validity['not_before'] = not_before.group(1).strip()

    not_after = re.search(r'Not After\s*:\s*(.+?)(?:\n|UTC)', ssl_text)
    if not_after:
        validity['not_after'] = not_after.group(1).strip()

    return validity


def process_cyberspace_search_result(result: dict) -> List[Dict]:
    """
    处理 cyberspace-search 返回的结果，提取所有 SSL 证书中的域名

    Args:
        result: cyberspace-search 返回的 JSON 结果

    Returns:
        每个端口的域名信息列表
    """
    extracted = []

    matches = result.get('sources', [{}])[0].get('data', {}).get('matches', [])

    for match in matches:
        ssl_text = match.get('ssl', '')
        if not ssl_text:
            continue

        port = match.get('port', 'unknown')
        ip = match.get('ip', 'unknown')

        domains = extract_domains_from_ssl(ssl_text)
        validity = extract_cert_validity(ssl_text)

        if domains:
            extracted.append({
                'ip': ip,
                'port': port,
                'domains': [asdict(d) for d in domains],
                'validity': validity
            })

    return extracted


def main():
    parser = argparse.ArgumentParser(
        description='从 SSL 证书文本中提取域名',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        'input',
        nargs='?',
        default='-',
        help='输入文件路径，使用 - 表示从 stdin 读取'
    )
    parser.add_argument(
        '-j', '--json',
        action='store_true',
        help='JSON 格式输出'
    )
    parser.add_argument(
        '--cyberspace-result',
        action='store_true',
        help='输入是 cyberspace-search 的 JSON 结果'
    )

    args = parser.parse_args()

    # 读取输入
    if args.input == '-':
        ssl_text = sys.stdin.read()
    else:
        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            ssl_text = f.read()

    # 处理
    if args.cyberspace_result:
        try:
            result = json.loads(ssl_text)
            extracted = process_cyberspace_search_result(result)

            if args.json:
                print(json.dumps(extracted, ensure_ascii=False, indent=2))
            else:
                for item in extracted:
                    print(f"\n[{item['ip']}:{item['port']}]")
                    for d in item['domains']:
                        print(f"  {d['domain']} ({d['source']})")
                    if item['validity']:
                        print(f"  有效期: {item['validity'].get('not_before', '?')} - {item['validity'].get('not_after', '?')}")

        except json.JSONDecodeError as e:
            print(f"JSON 解析错误: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        domains = extract_domains_from_ssl(ssl_text)
        validity = extract_cert_validity(ssl_text)

        if args.json:
            output = {
                'domains': [asdict(d) for d in domains],
                'validity': validity
            }
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            if domains:
                print("提取到的域名:")
                for d in domains:
                    print(f"  {d.domain} ({d.source})")
                if validity:
                    print(f"\n有效期: {validity.get('not_before', '?')} - {validity.get('not_after', '?')}")
            else:
                print("未提取到域名")


if __name__ == '__main__':
    main()
