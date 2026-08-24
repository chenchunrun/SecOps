#!/usr/bin/env python3
"""威胁狩猎脚本 - 基于MITRE ATT&CK框架的IoC搜索和关联分析"""

import argparse
import json
import re
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional, Set
from pathlib import Path

# MITRE ATT&CK 战术映射
ATTACK_TACTICS = {
    'TA0043': '侦察',
    'TA0042': '资源开发',
    'TA0001': '初始访问',
    'TA0002': '执行',
    'TA0003': '持久化',
    'TA0004': '提权',
    'TA0005': '防御绕过',
    'TA0006': '凭证访问',
    'TA0007': '发现',
    'TA0008': '横向移动',
    'TA0009': '收集',
    'TA0011': '命令控制',
    'TA0010': '数据渗出',
    'TA0040': '影响',
}

# 可疑指标模式
IOC_PATTERNS = {
    'ipv4': re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'),
    'ipv4_cidr': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b'),
    'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    'url': re.compile(r'https?://[^\s<>"\']+'),
    'cve': re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
    'c2_pattern': re.compile(r'(?:beacon|callback|c2|command.and.control|exfil)', re.IGNORECASE),
}

def extract_iocs(text: str) -> Dict[str, List[str]]:
    """从文本中提取IoC指标"""
    iocs = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = list(set(pattern.findall(text)))
        if matches:
            iocs[ioc_type] = matches
    return iocs

def check_virustotal(api_key: str, resource: str) -> Optional[Dict]:
    """查询VirusTotal（需要API Key）"""
    try:
        import vt
        client = vt.Client(api_key)
        obj = client.get_object(f'/files/{resource}')
        return {
            'resource': resource,
            'malicious': obj.stats.get('malicious', 0),
            'suspicious': obj.stats.get('suspicious', 0),
            'undetected': obj.stats.get('undetected', 0),
            'total_scans': sum(obj.stats.values()),
        }
    except Exception:
        return None

def check_shodan(api_key: str, query: str) -> Optional[Dict]:
    """查询Shodan"""
    try:
        import shodan
        api = shodan.Shodan(api_key)
        results = api.search(query, limit=5)
        return {
            'total': results.get('total', 0),
            'matches': [{
                'ip': m.get('ip_str', ''),
                'port': m.get('port', 0),
                'org': m.get('org', ''),
                'data': m.get('data', '')[:200],
            } for m in results.get('matches', [])[:5]]
        }
    except Exception:
        return None

def map_to_attack(description: str) -> List[Dict]:
    """将描述映射到MITRE ATT&CK技术"""
    keywords_to_techniques = {
        'spear.phish': {'id': 'T1566', 'name': '钓鱼攻击', 'tactic': 'TA0001'},
        'malware': {'id': 'T1587', 'name': '恶意软件开发', 'tactic': 'TA0042'},
        'powershell': {'id': 'T1059.001', 'name': 'PowerShell', 'tactic': 'TA0002'},
        'wmi': {'id': 'T1047', 'name': 'WMI执行', 'tactic': 'TA0002'},
        'scheduled.task': {'id': 'T1053', 'name': '计划任务', 'tactic': 'TA0003'},
        'registry': {'id': 'T1112', 'name': '注册表修改', 'tactic': 'TA0005'},
        'credential.dumping': {'id': 'T1003', 'name': '凭证转储', 'tactic': 'TA0006'},
        'lateral.movement': {'id': 'T1021', 'name': '远程服务', 'tactic': 'TA0008'},
        'data.exfil': {'id': 'T1041', 'name': '数据渗出', 'tactic': 'TA0010'},
        'dns.tunnel': {'id': 'T1071.004', 'name': 'DNS通信', 'tactic': 'TA0011'},
        'web.shell': {'id': 'T1505.003', 'name': 'Web Shell', 'tactic': 'TA0003'},
        'brute.force': {'id': 'T1110', 'name': '暴力破解', 'tactic': 'TA0006'},
        'exploit.public': {'id': 'T1190', 'name': '利用公开应用', 'tactic': 'TA0001'},
        'supply.chain': {'id': 'T1195', 'name': '供应链攻击', 'tactic': 'TA0001'},
        'ransomware': {'id': 'T1486', 'name': '数据加密', 'tactic': 'TA0040'},
        'backdoor': {'id': 'T1574', 'name': '后门植入', 'tactic': 'TA0003'},
    }

    matched = []
    desc_lower = description.lower()
    for keyword, tech in keywords_to_techniques.items():
        if keyword.replace('.', ' ') in desc_lower or keyword.replace('.', '.') in desc_lower:
            matched.append({
                **tech,
                'tactic_name': ATTACK_TACTICS.get(tech['tactic'], '未知'),
            })
    return matched

def hunt_from_file(filepath: str) -> Dict:
    """从文件中提取并分析IoC"""
    path = Path(filepath)
    if not path.exists():
        return {'error': f'文件不存在: {filepath}'}

    content = path.read_text(errors='ignore')
    iocs = extract_iocs(content)
    attack_mapping = map_to_attack(content)

    return {
        'file': str(path),
        'size': path.stat().st_size,
        'iocs': iocs,
        'ioc_counts': {k: len(v) for k, v in iocs.items()},
        'attack_techniques': attack_mapping,
        'timestamp': datetime.now().isoformat(),
    }

def main():
    parser = argparse.ArgumentParser(description='威胁狩猎脚本 - IoC提取与ATT&CK映射')
    parser.add_argument('-f', '--file', help='从文件提取IoC')
    parser.add_argument('-t', '--text', help='直接分析文本')
    parser.add_argument('--shodan-key', help='Shodan API Key')
    parser.add_argument('--vt-key', help='VirusTotal API Key')
    parser.add_argument('--json', action='store_true', help='JSON输出')
    args = parser.parse_args()

    if not args.file and not args.text:
        parser.print_help()
        sys.exit(1)

    if args.file:
        result = hunt_from_file(args.file)
    else:
        iocs = extract_iocs(args.text)
        attack = map_to_attack(args.text)
        result = {
            'iocs': iocs,
            'ioc_counts': {k: len(v) for k, v in iocs.items()},
            'attack_techniques': attack,
        }

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"{'='*60}")
        print(f"🦅 威胁狩猎分析报告")
        print(f"{'='*60}")

        if 'file' in result:
            print(f"\n📄 文件: {result['file']} ({result['size']} bytes)")

        print(f"\n📊 IoC统计:")
        total = 0
        for ioc_type, count in result.get('ioc_counts', {}).items():
            print(f"  {ioc_type}: {count}")
            total += count
        print(f"  总计: {total} 个IoC")

        if result.get('attack_techniques'):
            print(f"\n🎯 MITRE ATT&CK 映射:")
            for tech in result['attack_techniques']:
                print(f"  [{tech['tactic_name']}] {tech['id']} - {tech['name']}")

        # IoC详情
        for ioc_type, values in result.get('iocs', {}).items():
            if ioc_type in ('ipv4', 'domain', 'md5', 'sha256', 'cve'):
                print(f"\n🔍 {ioc_type.upper()} ({len(values)} 个):")
                for v in values[:20]:
                    print(f"  • {v}")

    return result

if __name__ == '__main__':
    main()
