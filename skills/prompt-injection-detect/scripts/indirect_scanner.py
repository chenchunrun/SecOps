#!/usr/bin/env python3
"""
间接提示注入扫描器
扫描网页、文档、API响应等外部数据源中的隐藏注入指令

使用方法:
    python scripts/indirect_scanner.py --url "https://example.com"
    python scripts/indirect_scanner.py --file document.html
    python scripts/indirect_scanner.py --text "外部内容..."
"""

import argparse
import json
import re
import sys
import os
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse


# 隐藏元素模式 (OWASP LLM01 / ATT&CK T1027 Obfuscated Files)
HIDDEN_CSS_PATTERNS = [
    r'display\s*:\s*none',
    r'visibility\s*:\s*hidden',
    r'font-size\s*:\s*0\s*px?',
    r'color\s*:\s*white.*background.*white',
    r'color\s*:\s*#fff.*background.*#fff',
    r'opacity\s*:\s*0',
    r'position\s*:\s*absolute.*left\s*:\s*-9999',
    r'overflow\s*:\s*hidden.*height\s*:\s*0',
    r'text-indent\s*:\s*-9999',
    r'clip-path\s*:\s*circle\(0',
]

# 元数据注入模式
META_PATTERNS = [
    (r'<meta[^>]*(?:ai-instructions|ai-directive|system-prompt)[^>]*content=["\']([^"\']+)', 'meta_ai_directive'),
    (r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*ignore[^"\']*)', 'meta_injection'),
    (r'<meta[^>]*property=["\']og:description["\'][^>]*content=["\']([^"\']*ignore[^"\']*)', 'og_injection'),
]

# 注入关键词 (复用 detector.py 的模式)
INJECTION_KEYWORDS = [
    r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|guidelines?)',
    r'disregard\s+(all\s+)?(previous|prior)',
    r'you\s+are\s+now\s+(?!going|about)',
    r'(DAN|STAN|DUDE|AIM)\s*(mode)?',
    r'developer\s+mode',
    r'(show|reveal|output)\s+(your|the)\s+(system|initial)\s+(prompt|instructions?)',
    r'bypass\s+(all\s+)?(restrictions?|filters?|safety)',
    r'new\s+instructions?\s*:',
    r'system\s+override',
    r'忽略.*指令',
    r'无视.*规则',
    r'你现在是',
]

# API 响应注入模式
API_INJECTION_PATTERNS = [
    (r'"_ai_directive"\s*:\s*"([^"]+)"', 'api_directive_field'),
    (r'"_system_instruction"\s*:\s*"([^"]+)"', 'api_system_field'),
    (r'"instructions"\s*:\s*"(?:ignore|disregard|bypass)', 'api_instruction_injection'),
    (r'"role"\s*:\s*"system"\s*,\s*"content"\s*:\s*"(ignore|disregard|bypass)', 'api_role_injection'),
]


def scan_html(html_content: str) -> List[Dict]:
    """扫描 HTML 内容中的隐藏注入"""
    findings = []

    # 1. 检测隐藏 CSS 元素
    for pattern in HIDDEN_CSS_PATTERNS:
        matches = re.finditer(pattern, html_content, re.IGNORECASE)
        for match in matches:
            # 提取周围的文本内容
            start = max(0, match.start() - 500)
            end = min(len(html_content), match.end() + 500)
            context = html_content[start:end]

            # 检查周围是否包含注入关键词
            has_injection = any(re.search(kw, context, re.IGNORECASE) for kw in INJECTION_KEYWORDS)

            if has_injection:
                findings.append({
                    "severity": "high",
                    "type": "hidden_element_with_injection",
                    "css_pattern": match.group(0),
                    "position": match.start(),
                    "matched_keywords": [
                        kw for kw in INJECTION_KEYWORDS
                        if re.search(kw, context, re.IGNORECASE)
                    ][:3],
                    "owasp": "LLM01",
                    "attack_id": "T1027",
                    "description": "隐藏HTML元素中包含提示注入指令"
                })

    # 2. 检测恶意 meta 标签
    for pattern, pattern_type in META_PATTERNS:
        matches = re.finditer(pattern, html_content, re.IGNORECASE)
        for match in matches:
            findings.append({
                "severity": "high",
                "type": pattern_type,
                "content": match.group(1)[:200] if match.groups() else "",
                "position": match.start(),
                "owasp": "LLM01",
                "attack_id": "T1204.002",
                "description": f"恶意meta标签: {pattern_type}"
            })

    # 3. 检测 HTML 注释中的注入
    comment_pattern = r'<!--\s*([^]*?)\s*-->'
    for match in re.finditer(comment_pattern, html_content):
        comment_text = match.group(1)
        if any(re.search(kw, comment_text, re.IGNORECASE) for kw in INJECTION_KEYWORDS):
            findings.append({
                "severity": "medium",
                "type": "html_comment_injection",
                "content": comment_text[:200],
                "position": match.start(),
                "owasp": "LLM01",
                "attack_id": "T1027",
                "description": "HTML注释中包含可疑注入内容"
            })

    return findings


def scan_text(text_content: str) -> List[Dict]:
    """扫描纯文本内容中的注入"""
    findings = []

    for kw_pattern in INJECTION_KEYWORDS:
        matches = list(re.finditer(kw_pattern, text_content, re.IGNORECASE))
        if matches:
            for match in matches[:5]:  # 限制每个模式最多5个结果
                start = max(0, match.start() - 50)
                end = min(len(text_content), match.end() + 50)
                context = text_content[start:end]

                findings.append({
                    "severity": "high",
                    "type": "direct_injection_in_text",
                    "pattern": kw_pattern,
                    "matched_text": match.group(0),
                    "context": context,
                    "position": match.start(),
                    "owasp": "LLM01",
                    "attack_id": "T1059",
                    "description": "文本中包含提示注入模式"
                })

    return findings


def scan_api_response(json_content: str) -> List[Dict]:
    """扫描 API JSON 响应中的注入"""
    findings = []

    for pattern, pattern_type in API_INJECTION_PATTERNS:
        matches = re.finditer(pattern, json_content, re.IGNORECASE)
        for match in matches:
            findings.append({
                "severity": "high",
                "type": pattern_type,
                "matched": match.group(0)[:200],
                "extracted": match.group(1)[:200] if match.groups() else "",
                "owasp": "LLM01",
                "attack_id": "T1190",
                "description": f"API响应中包含注入字段: {pattern_type}"
            })

    return findings


def scan_document(file_path: str) -> List[Dict]:
    """扫描文档文件中的隐藏注入"""
    findings = []
    ext = os.path.splitext(file_path)[1].lower()

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return [{"severity": "low", "type": "file_read_error", "error": str(e)}]

    if ext in ['.html', '.htm']:
        findings.extend(scan_html(content))
    elif ext == '.json':
        findings.extend(scan_api_response(content))
        findings.extend(scan_text(content))
    elif ext in ['.txt', '.md', '.csv', '.xml']:
        findings.extend(scan_text(content))
    else:
        # 通用文本扫描
        findings.extend(scan_text(content))

    # 文档特有的隐藏模式
    doc_hidden_patterns = [
        (r'\x00[^\x00]{10,}', 'null_byte_hidden'),  # null 字节后的隐藏内容
        (r'[\x00-\x08\x0e-\x1f]{10,}', 'control_chars'),  # 控制字符
    ]

    for pattern, pattern_type in doc_hidden_patterns:
        if re.search(pattern, content):
            findings.append({
                "severity": "medium",
                "type": pattern_type,
                "owasp": "LLM01",
                "attack_id": "T1027",
                "description": f"文档包含可疑隐藏内容: {pattern_type}"
            })

    return findings


def scan_url(url: str) -> Dict:
    """扫描 URL 指向的网页"""
    parsed = urlparse(url)
    findings = []

    # 尝试获取页面内容
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            findings.extend(scan_html(content))
            findings.extend(scan_text(content))
    except ImportError:
        findings.append({
            "severity": "low",
            "type": "dependency_missing",
            "description": "需要 urllib 模块来获取 URL 内容"
        })
    except Exception as e:
        findings.append({
            "severity": "medium",
            "type": "url_fetch_error",
            "url": url,
            "error": str(e),
            "description": f"无法获取URL内容: {e}"
        })

    return {
        "url": url,
        "domain": parsed.hostname,
        "findings": findings,
        "findings_count": len(findings),
        "risk_level": "high" if any(f.get("severity") == "high" for f in findings) else
                       "medium" if findings else "safe"
    }


def generate_report(results: Dict) -> str:
    """生成 Markdown 报告"""
    lines = [
        "# 间接提示注入扫描报告\n",
        f"**扫描时间**: {results.get('scan_time', 'N/A')}\n",
    ]

    if 'url' in results:
        lines.append(f"**扫描目标**: {results['url']}\n")
    elif 'file' in results:
        lines.append(f"**扫描文件**: {results['file']}\n")

    risk = results.get('risk_level', 'unknown')
    risk_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢", "safe": "✅"}.get(risk, "❓")
    lines.append(f"**风险等级**: {risk_emoji} {risk.upper()}\n")
    lines.append(f"**发现数量**: {results.get('findings_count', 0)}\n")

    findings = results.get('findings', [])
    if findings:
        lines.append("\n## 详细发现\n")
        lines.append("| # | 严重性 | 类型 | OWASP | ATT&CK | 描述 |")
        lines.append("|---|--------|------|-------|--------|------|")
        for i, f in enumerate(findings, 1):
            sev = f.get('severity', 'unknown')
            lines.append(
                f"| {i} | {sev} | {f.get('type', '')} | "
                f"{f.get('owasp', '-')} | {f.get('attack_id', '-')} | "
                f"{f.get('description', '')} |"
            )

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description='间接提示注入扫描器')
    parser.add_argument('--url', help='扫描的 URL')
    parser.add_argument('--file', help='扫描的文件路径')
    parser.add_argument('--text', help='扫描的文本内容')
    parser.add_argument('--json', action='store_true', help='JSON 格式输出')
    parser.add_argument('--report', action='store_true', help='生成 Markdown 报告')

    args = parser.parse_args()

    from datetime import datetime
    scan_time = datetime.now().isoformat()

    if args.url:
        result = scan_url(args.url)
        result['scan_time'] = scan_time
    elif args.file:
        findings = scan_document(args.file)
        result = {
            'file': args.file,
            'scan_time': scan_time,
            'findings': findings,
            'findings_count': len(findings),
            'risk_level': "high" if any(f.get("severity") == "high" for f in findings) else
                          "medium" if findings else "safe"
        }
    elif args.text:
        findings = scan_text(args.text)
        result = {
            'scan_time': scan_time,
            'findings': findings,
            'findings_count': len(findings),
            'risk_level': "high" if any(f.get("severity") == "high" for f in findings) else
                          "medium" if findings else "safe"
        }
    else:
        parser.print_help()
        sys.exit(1)

    if args.report:
        print(generate_report(result))
    elif args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        # 默认简洁输出
        risk = result['risk_level']
        count = result['findings_count']
        emoji = {"high": "🔴", "medium": "🟡", "safe": "✅"}.get(risk, "❓")
        print(f"\n{emoji} 风险等级: {risk.upper()} | 发现: {count} 个")

        if result.get('findings'):
            for i, f in enumerate(result['findings'][:10], 1):
                print(f"  {i}. [{f.get('severity', '?').upper()}] {f.get('type', '')} "
                      f"(OWASP:{f.get('owasp', '-')}, ATT&CK:{f.get('attack_id', '-')})")

    # 退出码：发现高危则返回 1
    sys.exit(1 if result['risk_level'] == 'high' else 0)


if __name__ == '__main__':
    main()
