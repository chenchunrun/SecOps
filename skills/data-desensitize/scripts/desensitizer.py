#!/usr/bin/env python3
"""数据脱敏工具 - 自动检测和脱敏敏感数据"""

import argparse
import json
import os
import re
import sys
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# 敏感数据检测模式
SENSITIVE_PATTERNS = {
    'phone_cn': {
        'pattern': re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)'),
        'label': '中国手机号',
        'severity': '高',
    },
    'id_card_cn': {
        'pattern': re.compile(r'(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)'),
        'label': '中国身份证号',
        'severity': '高',
    },
    'bank_card': {
        'pattern': re.compile(r'(?<!\d)(?:62|4[0-9]|5[1-5])\d{14,17}(?!\d)'),
        'label': '银行卡号',
        'severity': '高',
    },
    'email': {
        'pattern': re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}'),
        'label': '邮箱地址',
        'severity': '中',
    },
    'ipv4': {
        'pattern': re.compile(r'(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?!\d)'),
        'label': 'IP地址',
        'severity': '中',
    },
    'api_key_aws': {
        'pattern': re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}'),
        'label': 'AWS API Key',
        'severity': '高',
    },
    'api_key_generic': {
        'pattern': re.compile(r'(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*["\']?[A-Za-z0-9+/]{20,}["\']?', re.I),
        'label': 'API密钥',
        'severity': '高',
    },
    'password': {
        'pattern': re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']{4,}["\']?', re.I),
        'label': '密码',
        'severity': '高',
    },
    'jwt': {
        'pattern': re.compile(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'),
        'label': 'JWT Token',
        'severity': '高',
    },
    'private_key': {
        'pattern': re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
        'label': '私钥',
        'severity': '高',
    },
    'credit_card': {
        'pattern': re.compile(r'(?<!\d)(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)'),
        'label': '信用卡号',
        'severity': '高',
    },
    'ssn_us': {
        'pattern': re.compile(r'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)'),
        'label': '美国社会安全号',
        'severity': '高',
    },
}

def detect_sensitive_data(text: str) -> List[Dict]:
    """检测文本中的敏感数据"""
    findings = []
    for name, config in SENSITIVE_PATTERNS.items():
        for match in config['pattern'].finditer(text):
            value = match.group()
            findings.append({
                'type': name,
                'label': config['label'],
                'severity': config['severity'],
                'value': value,
                'start': match.start(),
                'end': match.end(),
                'masked': mask_value(value, name),
            })
    return findings

def mask_value(value: str, data_type: str) -> str:
    """脱敏处理"""
    if data_type == 'phone_cn':
        return value[:3] + '****' + value[-4:]
    elif data_type == 'id_card_cn':
        return value[:6] + '********' + value[-4:]
    elif data_type == 'email':
        parts = value.split('@')
        return parts[0][:2] + '***@' + parts[1]
    elif data_type == 'bank_card':
        return value[:4] + '****' + value[-4:]
    elif data_type == 'ipv4':
        parts = value.split('.')
        return parts[0] + '.' + parts[1] + '.*.*'
    elif data_type in ('api_key_generic', 'api_key_aws', 'password'):
        return value[:4] + '*' * (len(value) - 8) + value[-4:] if len(value) > 8 else '****'
    elif data_type == 'jwt':
        parts = value.split('.')
        return parts[0] + '.***.***'
    elif data_type == 'credit_card':
        return '****-****-****-' + value[-4:]
    else:
        return value[:2] + '*' * (len(value) - 2)

def anonymize_text(text: str, findings: List[Dict] = None) -> Tuple[str, List[Dict]]:
    """脱敏文本中的所有敏感数据"""
    if findings is None:
        findings = detect_sensitive_data(text)

    # 按位置倒序替换，避免偏移
    sorted_findings = sorted(findings, key=lambda x: x['start'], reverse=True)
    result = text
    for f in sorted_findings:
        result = result[:f['start']] + f['masked'] + result[f['end']:]
    return result, findings

def scan_file(filepath: str) -> Dict:
    """扫描文件中的敏感数据"""
    content = Path(filepath).read_text(errors='ignore')
    findings = detect_sensitive_data(content)
    return {
        'file': str(filepath),
        'size': len(content),
        'findings_count': len(findings),
        'findings': findings,
        'summary': {},
    }

def main():
    parser = argparse.ArgumentParser(description='数据脱敏工具')
    parser.add_argument('-f', '--file', help='输入文件')
    parser.add_argument('-t', '--text', help='直接输入文本')
    parser.add_argument('-o', '--output', help='输出文件')
    parser.add_argument('--scan-only', action='store_true', help='仅扫描不脱敏')
    parser.add_argument('--json', action='store_true', help='JSON输出')
    args = parser.parse_args()

    content = ''
    if args.file:
        content = Path(args.file).read_text(errors='ignore')
    elif args.text:
        content = args.text
    else:
        parser.print_help()
        sys.exit(1)

    findings = detect_sensitive_data(content)

    # 统计
    summary = {}
    for f in findings:
        key = f['type']
        summary[key] = summary.get(key, 0) + 1

    result = {
        'findings_count': len(findings),
        'summary': summary,
        'findings': findings if args.json else [{'type': f['type'], 'label': f['label'], 'severity': f['severity'], 'value': f['masked']} for f in findings],
    }

    if args.scan_only or args.json:
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"{'='*50}")
            print(f"🔒 敏感数据扫描报告")
            print(f"{'='*50}")
            print(f"发现 {len(findings)} 处敏感数据:\n")
            for f in result['findings']:
                icon = '🔴' if f['severity'] == '高' else '🟡'
                print(f"  {icon} [{f['label']}] {f.get('value', '')}")
    else:
        # 执行脱敏
        anonymized, _ = anonymize_text(content, findings)
        if args.output:
            Path(args.output).write_text(anonymized)
            print(f"✅ 脱敏完成: {args.output} ({len(findings)} 处已脱敏)")
        else:
            print(anonymized)

    return result

if __name__ == '__main__':
    main()
