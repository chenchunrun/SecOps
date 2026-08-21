#!/usr/bin/env python3
"""
依赖漏洞扫描器
整合 npm audit / pip-audit / safety，统一输出格式

使用方法:
    python scripts/dep_scanner.py --lang python --path ./requirements.txt
    python scripts/dep_scanner.py --lang javascript --path ./package.json
    python scripts/dep_scanner.py --lang auto --path ./
"""

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional


def detect_language(path: str) -> str:
    """自动检测项目语言"""
    if os.path.exists(os.path.join(path, 'package.json')):
        return 'javascript'
    elif os.path.exists(os.path.join(path, 'requirements.txt')) or \
         os.path.exists(os.path.join(path, 'pyproject.toml')) or \
         os.path.exists(os.path.join(path, 'Pipfile')):
        return 'python'
    elif os.path.exists(os.path.join(path, 'go.mod')):
        return 'go'
    elif os.path.exists(os.path.join(path, 'pom.xml')):
        return 'java'
    elif os.path.exists(os.path.join(path, 'Cargo.toml')):
        return 'rust'
    return 'unknown'


def run_npm_audit(project_path: str) -> List[Dict]:
    """运行 npm audit"""
    original_dir = os.getcwd()
    os.chdir(project_path)

    try:
        result = subprocess.run(
            ['npm', 'audit', '--json'],
            capture_output=True, text=True, timeout=60
        )
        data = json.loads(result.stdout if result.stdout else '{}')
    except json.JSONDecodeError:
        return [{"error": "npm audit 输出解析失败"}]
    except FileNotFoundError:
        return [{"error": "npm 未安装"}]
    except subprocess.TimeoutExpired:
        return [{"error": "npm audit 超时"}]
    finally:
        os.chdir(original_dir)

    vulns = []
    for pkg, info in data.get('vulnerabilities', {}).items():
        cwe_list = []
        for via in info.get('via', []):
            if isinstance(via, dict) and 'cwe' in via:
                cwe_list.extend(via['cwe'] if isinstance(via['cwe'], list) else [via['cwe']])

        vulns.append({
            'package': pkg,
            'severity': info.get('severity', 'unknown'),
            'cwe': list(set(cwe_list)),
            'fix_available': info.get('fixAvailable', False),
            'range': info.get('range', ''),
            'effects': info.get('effects', []),
            'source': 'npm audit',
        })

    return vulns


def run_pip_audit(project_path: str) -> List[Dict]:
    """运行 pip-audit"""
    try:
        result = subprocess.run(
            ['pip-audit', '--format', 'json'],
            capture_output=True, text=True, timeout=120,
            cwd=project_path
        )
        data = json.loads(result.stdout if result.stdout else '{"dependencies": []}')
    except json.JSONDecodeError:
        return [{"error": "pip-audit 输出解析失败"}]
    except FileNotFoundError:
        # 尝试 pip install pip-audit
        return [{"error": "pip-audit 未安装，运行: pip install pip-audit"}]
    except subprocess.TimeoutExpired:
        return [{"error": "pip-audit 超时"}]

    vulns = []
    for dep in data.get('dependencies', []):
        for vuln in dep.get('vulns', []):
            vulns.append({
                'package': dep.get('name', ''),
                'version': dep.get('version', ''),
                'severity': 'high' if vuln.get('cve') else 'medium',
                'cve': vuln.get('cve', ''),
                'cwe': vuln.get('cwe', []),
                'description': vuln.get('description', '')[:200],
                'fix_versions': vuln.get('fix_versions', []),
                'source': 'pip-audit',
            })

    return vulns


def run_safety_check(project_path: str) -> List[Dict]:
    """运行 safety check (备选)"""
    req_file = None
    for name in ['requirements.txt', 'pyproject.toml']:
        path = os.path.join(project_path, name)
        if os.path.exists(path):
            req_file = path
            break

    if not req_file:
        return [{"error": "未找到 requirements.txt 或 pyproject.toml"}]

    try:
        cmd = ['safety', 'check', '--file', req_file, '--json']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        data = json.loads(result.stdout if result.stdout else '[]')
    except (json.JSONDecodeError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        return [{"error": f"safety check 失败: {e}"}]

    vulns = []
    for item in data if isinstance(data, list) else []:
        vulns.append({
            'package': item[0] if len(item) > 0 else '',
            'severity': 'high' if item[1].startswith('Critical') else 'medium',
            'cve': '',
            'description': item[3] if len(item) > 3 else '',
            'source': 'safety',
        })

    return vulns


def classify_severity(vulns: List[Dict]) -> Dict:
    """按严重性分类"""
    severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for v in vulns:
        if 'error' in v:
            continue
        sev = v.get('severity', 'info').lower()
        if sev in severity_count:
            severity_count[sev] += 1
        else:
            severity_count['info'] += 1
    return severity_count


def generate_report(vulns: List[Dict], project_info: Dict) -> str:
    """生成报告"""
    sev = classify_severity(vulns)
    total = sum(sev.values())

    lines = [
        "# 依赖漏洞扫描报告\n",
        f"**项目**: {project_info.get('path', 'N/A')}\n",
        f"**语言**: {project_info.get('language', 'N/A')}\n",
        f"**扫描工具**: {project_info.get('scanner', 'N/A')}\n",
        f"**漏洞总数**: {total}\n",
        f"\n**严重性分布**: ",
        f"🔴 Critical: {sev['critical']} | 🟠 High: {sev['high']} | "
        f"🟡 Medium: {sev['medium']} | 🟢 Low: {sev['low']}\n",
    ]

    real_vulns = [v for v in vulns if 'error' not in v]
    if real_vulns:
        lines.append("\n## 漏洞详情\n")
        lines.append("| # | 包名 | 严重性 | CWE/CVE | 可修复 | 来源 |")
        lines.append("|---|------|--------|---------|--------|------|")
        for i, v in enumerate(real_vulns[:50], 1):
            cwe_cve = ', '.join(v.get('cwe', [])[:3]) or v.get('cve', '') or '-'
            fix = '✅' if v.get('fix_available') or v.get('fix_versions') else '❌'
            lines.append(
                f"| {i} | {v.get('package', '')} | {v.get('severity', '')} | "
                f"{cwe_cve} | {fix} | {v.get('source', '')} |"
            )

    errors = [v for v in vulns if 'error' in v]
    if errors:
        lines.append("\n## 错误信息\n")
        for e in errors:
            lines.append(f"- ⚠️ {e['error']}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description='依赖漏洞扫描器')
    parser.add_argument('--lang', default='auto', choices=['auto', 'python', 'javascript', 'go', 'java'])
    parser.add_argument('--path', default='.', help='项目路径')
    parser.add_argument('--json', action='store_true', help='JSON 输出')
    parser.add_argument('--report', action='store_true', help='Markdown 报告')

    args = parser.parse_args()

    lang = args.lang
    if lang == 'auto':
        lang = detect_language(args.path)

    scanner_map = {
        'javascript': ('npm audit', run_npm_audit),
        'python': ('pip-audit', run_pip_audit),
    }

    if lang not in scanner_map:
        print(f"不支持的语言: {lang}. 支持: {list(scanner_map.keys())}")
        sys.exit(1)

    scanner_name, scanner_func = scanner_map[lang]
    vulns = scanner_func(args.path)
    project_info = {'path': args.path, 'language': lang, 'scanner': scanner_name}

    if args.report:
        print(generate_report(vulns, project_info))
    elif args.json:
        print(json.dumps({'project': project_info, 'vulnerabilities': vulns}, ensure_ascii=False, indent=2))
    else:
        sev = classify_severity(vulns)
        total = sum(sev.values())
        print(f"\n{'='*50}")
        print(f"语言: {lang} | 工具: {scanner_name}")
        print(f"🔴 {sev['critical']} | 🟠 {sev['high']} | 🟡 {sev['medium']} | 🟢 {sev['low']} | 总计: {total}")

        real_vulns = [v for v in vulns if 'error' not in v]
        for i, v in enumerate(real_vulns[:10], 1):
            print(f"  {i}. [{v.get('severity', '?').upper()}] {v.get('package', '')} - {v.get('cve', '') or ', '.join(v.get('cwe', [])[:2])}")

    sys.exit(1 if sev.get('critical', 0) > 0 or sev.get('high', 0) > 0 else 0)


if __name__ == '__main__':
    main()
