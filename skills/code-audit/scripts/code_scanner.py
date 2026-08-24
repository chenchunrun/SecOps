#!/usr/bin/env python3
"""代码安全审计工具 - 自动化代码扫描与漏洞检测"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# 危险函数/模式检测规则
SECURITY_RULES = {
    'python': {
        'sql_injection': [
            (r'execute\s*\(\s*["\'].*%s.*["\']', 'SQL注入风险: 字符串格式化SQL查询'),
            (r'execute\s*\(\s*f["\']', 'SQL注入风险: f-string SQL查询'),
            (r'\.raw\s*\(\s*f["\']', 'SQL注入风险: ORM raw查询使用f-string'),
            (r'cursor\.execute\s*\([^,]*\+', 'SQL注入风险: 字符串拼接SQL'),
        ],
        'command_injection': [
            (r'os\.system\s*\(', '命令注入风险: os.system()'),
            (r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', '命令注入风险: shell=True'),
            (r'os\.popen\s*\(', '命令注入风险: os.popen()'),
            (r'eval\s*\(', '代码注入风险: eval()'),
            (r'exec\s*\(', '代码注入风险: exec()'),
            (r'__import__\s*\(', '动态导入风险'),
        ],
        'crypto': [
            (r'hashlib\.md5\s*\(', '弱哈希: MD5不安全'),
            (r'hashlib\.sha1\s*\(', '弱哈希: SHA1不安全'),
            (r'DES\b', '弱加密: DES已过时'),
            (r'RC[24]\b', '弱加密: RC2/RC4不安全'),
            (r'MODE_ECB', 'ECB模式不安全'),
            (r'random\.random\s*\(', '非密码学安全随机数'),
        ],
        'path_traversal': [
            (r'open\s*\(\s*request\.', '路径遍历风险: 直接打开请求参数'),
            (r'\.read\s*\(\s*\).*request\.', '路径遍历风险: 读取请求参数指定文件'),
        ],
        'secrets': [
            (r'password\s*=\s*["\'][^"\']{4,}["\']', '硬编码密码'),
            (r'api_key\s*=\s*["\'][^"\']{8,}["\']', '硬编码API Key'),
            (r'secret\s*=\s*["\'][^"\']{4,}["\']', '硬编码密钥'),
            (r'token\s*=\s*["\'][^"\']{8,}["\']', '硬编码Token'),
        ],
        'xss': [
            (r'\|safe\b', 'XSS风险: Django |safe 过滤器'),
            (r'mark_safe\s*\(', 'XSS风险: mark_safe()'),
            (r'HttpResponse\s*\([^)]*\+', 'XSS风险: 未转义HTTP响应'),
        ],
        'ssrf': [
            (r'requests\.(get|post)\s*\(\s*request\.', 'SSRF风险: 使用用户输入的URL'),
            (r'urllib\.request\.urlopen\s*\(\s*request\.', 'SSRF风险: urllib打开用户URL'),
        ],
        'deserialization': [
            (r'pickle\.loads?\s*\(', '反序列化风险: pickle不安全'),
            (r'yaml\.load\s*\([^)]*\)', '反序列化风险: yaml.load不安全，使用yaml.safe_load'),
        ],
    },
    'javascript': {
        'injection': [
            (r'eval\s*\(', '代码注入风险: eval()'),
            (r'Function\s*\(', '代码注入风险: Function构造器'),
            (r'setTimeout\s*\(\s*["\']', '代码注入风险: setTimeout字符串参数'),
            (r'new Function\s*\(', '代码注入风险: new Function()'),
        ],
        'xss': [
            (r'dangerouslySetInnerHTML', 'XSS风险: dangerouslySetInnerHTML'),
            (r'innerHTML\s*=', 'XSS风险: innerHTML赋值'),
            (r'document\.write\s*\(', 'XSS风险: document.write()'),
            (r'v-html', 'XSS风险: Vue v-html'),
        ],
        'secrets': [
            (r'password\s*[:=]\s*["\'][^"\']{4,}["\']', '硬编码密码'),
            (r'api[_-]?key\s*[:=]\s*["\'][^"\']{8,}["\']', '硬编码API Key'),
            (r'secret\s*[:=]\s*["\'][^"\']{4,}["\']', '硬编码密钥'),
            (r'Authorization\s*[:=]\s*["\']Bearer\s', '硬编码Bearer Token'),
        ],
        'prototype_pollution': [
            (r'__proto__', '原型污染风险: __proto__'),
            (r'merge\s*\([^)]*\{.*\}', '原型污染风险: 深度合并对象'),
            (r'extend\s*\(\s*\{\},\s*req\.', '原型污染风险: 扩展请求对象'),
        ],
        'crypto': [
            (r'createCipher\s*\(', '弱加密: 使用createCipheriv代替'),
            (r'Math\.random\s*\(\)', '非密码学安全随机数'),
        ],
        'path_traversal': [
            (r'readFileSync\s*\(\s*req\.', '路径遍历风险'),
            (r'createReadStream\s*\(\s*req\.', '路径遍历风险'),
        ],
    },
    'php': {
        'injection': [
            (r'eval\s*\(', '代码注入风险: eval()'),
            (r'assert\s*\(', '代码注入风险: assert()'),
            (r'system\s*\(', '命令注入风险: system()'),
            (r'exec\s*\(', '命令注入风险: exec()'),
            (r'passthru\s*\(', '命令注入风险: passthru()'),
            (r'shell_exec\s*\(', '命令注入风险: shell_exec()'),
            (r'`[^`]*\$', '命令注入风险: 反引号执行'),
        ],
        'sql_injection': [
            (r'mysql_query\s*\([^,]*\$', 'SQL注入风险: 变量直接拼接'),
            (r'\$wpdb->query\s*\([^,]*\$', 'SQL注入风险: WordPress变量拼接'),
        ],
        'xss': [
            (r'echo\s+\$_(GET|POST|REQUEST)', 'XSS风险: 直接输出用户输入'),
            (r'print\s+\$_(GET|POST|REQUEST)', 'XSS风险: 直接输出用户输入'),
        ],
        'file_inclusion': [
            (r'include\s*\(\s*\$_', '文件包含风险: 动态包含'),
            (r'require\s*\(\s*\$_', '文件包含风险: 动态require'),
        ],
        'secrets': [
            (r'\$password\s*=\s*["\'][^"\']{4,}["\']', '硬编码密码'),
            (r'\$db_pass\s*=\s*["\'][^"\']{4,}["\']', '硬编码数据库密码'),
        ],
    },
}

# CWE映射
CWE_MAP = {
    'sql_injection': 'CWE-89',
    'command_injection': 'CWE-78',
    'xss': 'CWE-79',
    'path_traversal': 'CWE-22',
    'secrets': 'CWE-798',
    'crypto': 'CWE-327',
    'ssrf': 'CWE-918',
    'deserialization': 'CWE-502',
    'injection': 'CWE-94',
    'prototype_pollution': 'CWE-1321',
    'file_inclusion': 'CWE-98',
}

def detect_language(filepath: str) -> str:
    """根据文件扩展名检测编程语言"""
    ext_map = {
        '.py': 'python', '.pyw': 'python',
        '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript',
        '.ts': 'javascript', '.tsx': 'javascript',
        '.php': 'php',
    }
    ext = Path(filepath).suffix.lower()
    return ext_map.get(ext, '')

def scan_file(filepath: str) -> List[Dict]:
    """扫描单个文件"""
    lang = detect_language(filepath)
    if not lang or lang not in SECURITY_RULES:
        return []

    findings = []
    try:
        content = Path(filepath).read_text(errors='ignore')
        lines = content.split('\n')

        for category, rules in SECURITY_RULES[lang].items():
            for pattern, description in rules:
                compiled = re.compile(pattern, re.IGNORECASE)
                for line_no, line in enumerate(lines, 1):
                    if compiled.search(line):
                        findings.append({
                            'file': filepath,
                            'line': line_no,
                            'category': category,
                            'cwe': CWE_MAP.get(category, 'CWE-???'),
                            'severity': '高' if category in ('sql_injection', 'command_injection', 'injection') else '中',
                            'description': description,
                            'code': line.strip()[:120],
                        })
    except Exception as e:
        pass

    return findings

def scan_directory(directory: str, exclude_dirs: set = None) -> Dict:
    """扫描整个目录"""
    if exclude_dirs is None:
        exclude_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', '.tox'}

    all_findings = []
    files_scanned = 0
    lang_stats = {}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for f in files:
            filepath = os.path.join(root, f)
            lang = detect_language(filepath)
            if lang:
                files_scanned += 1
                lang_stats[lang] = lang_stats.get(lang, 0) + 1
                findings = scan_file(filepath)
                all_findings.extend(findings)

    # 按严重性排序
    severity_order = {'高': 0, '中': 1, '低': 2}
    all_findings.sort(key=lambda x: severity_order.get(x.get('severity', '低'), 3))

    return {
        'directory': directory,
        'files_scanned': files_scanned,
        'language_stats': lang_stats,
        'total_findings': len(all_findings),
        'findings': all_findings,
        'summary': {
            'high': len([f for f in all_findings if f['severity'] == '高']),
            'medium': len([f for f in all_findings if f['severity'] == '中']),
            'low': len([f for f in all_findings if f['severity'] == '低']),
        },
        'timestamp': datetime.now().isoformat(),
    }

def main():
    parser = argparse.ArgumentParser(description='代码安全审计工具')
    parser.add_argument('target', help='目标文件或目录')
    parser.add_argument('--json', action='store_true', help='JSON输出')
    parser.add_argument('--severity', choices=['高', '中', '低'], help='过滤严重性')
    parser.add_argument('--category', help='过滤类别')
    args = parser.parse_args()

    target = args.target
    if os.path.isfile(target):
        findings = scan_file(target)
        result = {
            'file': target,
            'total_findings': len(findings),
            'findings': findings,
        }
    elif os.path.isdir(target):
        result = scan_directory(target)
    else:
        print(f"目标不存在: {target}", file=sys.stderr)
        sys.exit(1)

    # 过滤
    if args.severity:
        result['findings'] = [f for f in result['findings'] if f.get('severity') == args.severity]
    if args.category:
        result['findings'] = [f for f in result['findings'] if f.get('category') == args.category]

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"{'='*60}")
        print(f"🔒 代码安全审计报告")
        print(f"{'='*60}")
        if 'files_scanned' in result:
            print(f"📁 目录: {result['directory']}")
            print(f"📄 扫描文件: {result['files_scanned']} ({', '.join(f'{k}:{v}' for k,v in result.get('language_stats',{}).items())})")
            print(f"📊 发现: 🔴高危{result['summary']['high']} 🟡中危{result['summary']['medium']} 🔵低危{result['summary']['low']}")
        else:
            print(f"📄 文件: {result['file']}")
            print(f"📊 发现: {result['total_findings']} 个问题")

        for f in result['findings'][:50]:
            icon = {'高': '🔴', '中': '🟡', '低': '🔵'}.get(f.get('severity', ''), '⚪')
            print(f"\n  {icon} [{f.get('cwe','')}] {f['description']}")
            print(f"     {f['file']}:{f['line']}")
            print(f"     {f['code']}")

    return result

if __name__ == '__main__':
    main()
