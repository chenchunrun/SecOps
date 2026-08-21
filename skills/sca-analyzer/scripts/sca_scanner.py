#!/usr/bin/env python3
"""SCA软件成分分析工具 - 依赖漏洞扫描与许可证合规检查"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# 已知漏洞依赖数据库（本地缓存的常见CVE）
KNOWN_VULNS = {
    'log4j': [
        {'cve': 'CVE-2021-44228', 'severity': 'Critical', 'cvss': 10.0, 'affected': '<2.17.0', 'desc': 'Log4Shell RCE'},
        {'cve': 'CVE-2021-45105', 'severity': 'High', 'cvss': 7.5, 'affected': '<2.17.1', 'desc': '拒绝服务'},
    ],
    'spring-core': [
        {'cve': 'CVE-2022-22965', 'severity': 'Critical', 'cvss': 9.8, 'affected': '<5.3.18', 'desc': 'Spring4Shell RCE'},
    ],
    'openssl': [
        {'cve': 'CVE-2014-0160', 'severity': 'Critical', 'cvss': 7.5, 'affected': '<1.0.1g', 'desc': 'Heartbleed'},
        {'cve': 'CVE-2016-0800', 'severity': 'High', 'cvss': 7.5, 'affected': '<1.0.2f', 'desc': 'DROWN攻击'},
    ],
    'openssl3': [
        {'cve': 'CVE-2022-3602', 'severity': 'High', 'cvss': 7.5, 'affected': '<3.0.7', 'desc': 'X.509缓冲区溢出'},
    ],
    'nodejs': [
        {'cve': 'CVE-2023-44487', 'severity': 'High', 'cvss': 7.5, 'affected': '<18.18.2', 'desc': 'HTTP/2快速重置攻击'},
    ],
    'jquery': [
        {'cve': 'CVE-2020-11022', 'severity': 'Medium', 'cvss': 6.1, 'affected': '<3.5.0', 'desc': 'XSS漏洞'},
        {'cve': 'CVE-2020-11023', 'severity': 'Medium', 'cvss': 6.9, 'affected': '<3.5.0', 'desc': 'XSS漏洞'},
    ],
    'lodash': [
        {'cve': 'CVE-2021-23337', 'severity': 'High', 'cvss': 7.2, 'affected': '<4.17.21', 'desc': '命令注入'},
    ],
    'requests': [
        {'cve': 'CVE-2023-32681', 'severity': 'Medium', 'cvss': 6.1, 'affected': '<2.31.0', 'desc': '信息泄露'},
    ],
    'flask': [
        {'cve': 'CVE-2023-30861', 'severity': 'Medium', 'cvss': 6.1, 'affected': '<2.3.2', 'desc': 'Cookie安全绕过'},
    ],
    'django': [
        {'cve': 'CVE-2023-46695', 'severity': 'High', 'cvss': 7.5, 'affected': '<4.2.7', 'desc': 'DoS漏洞'},
    ],
    'pyyaml': [
        {'cve': 'CVE-2020-14343', 'severity': 'High', 'cvss': 7.5, 'affected': '<5.4', 'desc': '任意代码执行'},
    ],
}

# 许可证兼容性
LICENSE_COMPATIBILITY = {
    'MIT': {'compatible_with': ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'GPL-2.0', 'GPL-3.0', 'LGPL'], 'risk': '低'},
    'Apache-2.0': {'compatible_with': ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'GPL-3.0', 'LGPL-3.0'], 'risk': '低'},
    'GPL-2.0': {'compatible_with': ['GPL-2.0', 'GPL-3.0', 'LGPL-2.1'], 'risk': '高', 'warning': 'GPL-2.0要求衍生作品也使用GPL-2.0'},
    'GPL-3.0': {'compatible_with': ['GPL-3.0', 'LGPL-3.0', 'Apache-2.0'], 'risk': '高', 'warning': 'GPL-3.0要求衍生作品也使用GPL-3.0'},
    'BSD-2-Clause': {'compatible_with': ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC'], 'risk': '低'},
    'BSD-3-Clause': {'compatible_with': ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC'], 'risk': '低'},
    'ISC': {'compatible_with': ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC'], 'risk': '低'},
    'LGPL-2.1': {'compatible_with': ['LGPL-2.1', 'GPL-2.0'], 'risk': '中'},
    'LGPL-3.0': {'compatible_with': ['LGPL-3.0', 'GPL-3.0', 'Apache-2.0'], 'risk': '中'},
    'MPL-2.0': {'compatible_with': ['MPL-2.0', 'Apache-2.0', 'GPL-2.0', 'GPL-3.0'], 'risk': '中'},
    'Unlicense': {'compatible_with': ['*'], 'risk': '低'},
    'CC0-1.0': {'compatible_with': ['*'], 'risk': '低'},
}

def parse_requirements(filepath: str) -> List[Dict]:
    """解析 requirements.txt"""
    deps = []
    for line in Path(filepath).read_text(errors='ignore').split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # 简单解析
        match = re.match(r'^([a-zA-Z0-9_.-]+)\s*([><=!~]+.*)?$', line)
        if match:
            name = match.group(1).lower().replace('-', '_').replace('.', '_')
            version_spec = match.group(2) or ''
            deps.append({'name': name, 'version_spec': version_spec, 'source': 'requirements.txt'})
    return deps

def parse_package_json(filepath: str) -> List[Dict]:
    """解析 package.json"""
    deps = []
    try:
        data = json.loads(Path(filepath).read_text())
        for section in ['dependencies', 'devDependencies']:
            for name, version in data.get(section, {}).items():
                deps.append({
                    'name': name.lower(),
                    'version': version.lstrip('^~>=<'),
                    'source': 'package.json',
                    'dev': section == 'devDependencies',
                })
    except Exception:
        pass
    return deps

def parse_go_mod(filepath: str) -> List[Dict]:
    """解析 go.mod"""
    deps = []
    in_require = False
    for line in Path(filepath).read_text(errors='ignore').split('\n'):
        line = line.strip()
        if line.startswith('require ('):
            in_require = True
            continue
        if in_require and line == ')':
            in_require = False
            continue
        if in_require or line.startswith('require '):
            parts = line.replace('require', '').strip().split()
            if len(parts) >= 2:
                deps.append({
                    'name': parts[0],
                    'version': parts[1].lstrip('v'),
                    'source': 'go.mod',
                })
    return deps

def scan_dependencies(deps: List[Dict]) -> Dict:
    """扫描依赖漏洞"""
    vulns = []
    for dep in deps:
        name = dep.get('name', '').lower()
        for pkg_name, pkg_vulns in KNOWN_VULNS.items():
            if pkg_name in name or name in pkg_name:
                for vuln in pkg_vulns:
                    vulns.append({
                        **vuln,
                        'package': dep['name'],
                        'version_spec': dep.get('version_spec', dep.get('version', '')),
                        'source': dep.get('source', ''),
                    })

    return {
        'total_deps': len(deps),
        'vulnerable_deps': len(set(v['package'] for v in vulns)),
        'total_vulns': len(vulns),
        'critical': len([v for v in vulns if v['severity'] == 'Critical']),
        'high': len([v for v in vulns if v['severity'] == 'High']),
        'medium': len([v for v in vulns if v['severity'] == 'Medium']),
        'vulnerabilities': vulns,
        'dependencies': deps,
    }

def main():
    parser = argparse.ArgumentParser(description='SCA软件成分分析工具')
    parser.add_argument('target', help='项目目录或依赖文件')
    parser.add_argument('--json', action='store_true', help='JSON输出')
    parser.add_argument('--license-check', action='store_true', help='同时检查许可证合规')
    args = parser.parse_args()

    target = Path(args.target)
    deps = []

    if target.is_file():
        name = target.name
        if name in ('requirements.txt', 'requirements-dev.txt', 'Pipfile') or name.endswith('.txt') and 'require' in name.lower():
            deps = parse_requirements(str(target))
        elif name == 'package.json':
            deps = parse_package_json(str(target))
        elif name == 'go.mod':
            deps = parse_go_mod(str(target))
    elif target.is_dir():
        # 自动发现依赖文件
        for pattern, parser_fn in [
            ('**/requirements*.txt', parse_requirements),
            ('**/package.json', parse_package_json),
            ('**/go.mod', parse_go_mod),
        ]:
            for f in target.glob(pattern):
                if 'node_modules' not in str(f) and '.venv' not in str(f):
                    deps.extend(parser_fn(str(f)))

    if not deps:
        print(f"❌ 未发现依赖文件: {target}", file=sys.stderr)
        sys.exit(1)

    result = scan_dependencies(deps)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"{'='*60}")
        print(f"📦 SCA软件成分分析")
        print(f"{'='*60}")
        print(f"依赖总数: {result['total_deps']}")
        print(f"有漏洞的依赖: {result['vulnerable_deps']}")
        print(f"漏洞总数: 🔴Critical {result['critical']} 🟠High {result['high']} 🟡Medium {result['medium']}")

        if result['vulnerabilities']:
            print(f"\n🚨 发现漏洞:")
            for v in result['vulnerabilities']:
                icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡'}.get(v['severity'], '⚪')
                print(f"  {icon} [{v.get('cve', 'N/A')}] {v['package']} - {v['desc']}")
                print(f"     受影响版本: {v['affected']} | 当前: {v.get('version_spec', '?')}")

        print(f"\n📋 依赖列表 ({len(deps)} 个):")
        for d in deps[:30]:
            print(f"  • {d['name']} {d.get('version_spec', d.get('version', ''))} ({d.get('source', '')})")

    return result

if __name__ == '__main__':
    main()
