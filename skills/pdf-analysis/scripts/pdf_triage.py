#!/usr/bin/env python3
"""
PDF 快速分诊脚本 — 安全交互式风险评估

用法:
    python3 pdf_triage.py <pdf_file>
    python3 pdf_triage.py <pdf_file> --json

功能:
    1. 文件类型验证（magic bytes 检测）
    2. PDF 结构快速扫描
    3. 威胁指标提取（JS/URL/嵌入文件/表单/动作）
    4. CVE 特征匹配
    5. 风险评级（LOW/MEDIUM/HIGH/CRITICAL）
    6. IOC 提取（URL/IP/域名/邮箱）
    7. 处置建议输出
"""

import sys
import os
import re
import json
import hashlib
import argparse
from pathlib import Path


# PDF Magic Bytes
PDF_MAGIC = b'%PDF-'

# 威胁指标正则
PATTERNS = {
    'javascript': [
        rb'/JavaScript\s',
        rb'/JS\s',
        rb'/JavaScript\(',
    ],
    'auto_action': [
        rb'/OpenAction',
        rb'/AA\s',
        rb'/AcroForm',
    ],
    'launch': [
        rb'/Launch',
        rb'/Action',
        rb'/URI\s*\(',
    ],
    'embedded_file': [
        rb'/EmbeddedFile',
        rb'/EmbeddedF',
        rb'/FileAttachment',
    ],
    'form': [
        rb'/AcroForm',
        rb'/SubmitForm',
        rb'/NeedAppearances',
    ],
    'obfuscation': [
        rb'/FlateDecode.*?/FlateDecode',
        rb'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}',
        rb'%u[0-9A-Fa-f]{4}%u[0-9A-Fa-f]{4}',
    ],
}

# CVE 特征签名
CVE_SIGNATURES = {
    'CVE-2010-0188': {
        'name': 'JBIG2 解码溢出',
        'pattern': rb'/JBIG2Decode',
        'severity': 'HIGH',
    },
    'CVE-2013-0640': {
        'name': 'XFA TIFF 溢出',
        'pattern': rb'/XFA',
        'severity': 'HIGH',
    },
    'CVE-2018-4990': {
        'name': 'Double Free JBIG2',
        'pattern': rb'/JBIG2Globals',
        'severity': 'CRITICAL',
    },
    'CVE-2017-11882': {
        'name': '公式编辑器 RCE',
        'pattern': rb'Equation\.3|Equation Native',
        'severity': 'CRITICAL',
    },
    'CVE-2021-44711': {
        'name': '字体解析漏洞',
        'pattern': rb'/FontFile[23]?\s.*?/ToUnicode',
        'severity': 'HIGH',
    },
    'CVE-2023-21674': {
        'name': '内存损坏',
        'pattern': rb'/XFA\s.*?/datasets',
        'severity': 'CRITICAL',
    },
}

# IOC 正则
URL_RE = re.compile(rb'https?://[^\s<>"\'\\)>]+', re.IGNORECASE)
IP_RE = re.compile(rb'\b(\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(rb'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b')
EMAIL_RE = re.compile(rb'[\w.+-]+@[\w.-]+\.\w+')


def check_magic(filepath):
    """验证文件是否为 PDF"""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(8)
        if header.startswith(PDF_MAGIC):
            return True, header.decode('ascii', errors='replace')
        # 检查类型伪装
        if header.startswith(b'MZ'):
            return False, 'WARNING: File has PE (EXE) header but PDF extension - TYPE MASQUERADE!'
        if header.startswith(b'PK'):
            return False, 'WARNING: File has ZIP header but PDF extension - TYPE MASQUERADE!'
        return False, f'Not a PDF. Header: {header.hex()}'
    except Exception as e:
        return False, f'Error reading file: {e}'


def extract_pdf_info(filepath):
    """提取 PDF 基本信息"""
    info = {}
    try:
        data = Path(filepath).read_bytes()
        info['size'] = len(data)
        info['sha256'] = hashlib.sha256(data).hexdigest()
        info['md5'] = hashlib.md5(data).hexdigest()

        # PDF 版本
        version_match = re.search(rb'%PDF-(\d\.\d)', data)
        info['pdf_version'] = version_match.group(1).decode() if version_match else 'unknown'

        # 页数（粗略估计）
        page_count = len(re.findall(rb'/Type\s*/Page[^s]', data))
        info['pages'] = page_count

        # 创建者/生产者
        creator = re.search(rb'/Creator\s*\(([^)]+)\)', data)
        producer = re.search(rb'/Producer\s*\(([^)]+)\)', data)
        info['creator'] = creator.group(1).decode('utf-8', errors='replace') if creator else ''
        info['producer'] = producer.group(1).decode('utf-8', errors='replace') if producer else ''

    except Exception as e:
        info['error'] = str(e)
    return info


def scan_threats(filepath):
    """扫描威胁指标"""
    data = Path(filepath).read_bytes()
    indicators = {}

    for category, patterns in PATTERNS.items():
        matches = []
        for pat in patterns:
            found = re.findall(pat, data)
            matches.extend([m.decode('utf-8', errors='replace') if isinstance(m, bytes) else m for m in found])
        if matches:
            indicators[category] = {
                'count': len(matches),
                'samples': matches[:5],
            }

    # CVE 匹配
    cve_matches = []
    for cve_id, sig in CVE_SIGNATURES.items():
        if re.search(sig['pattern'], data):
            cve_matches.append({
                'cve': cve_id,
                'name': sig['name'],
                'severity': sig['severity'],
            })

    return indicators, cve_matches


def extract_iocs(filepath):
    """提取 IOC"""
    data = Path(filepath).read_bytes()

    urls = [u.decode('utf-8', errors='replace') for u in URL_RE.findall(data)]
    ips = [ip.decode() for ip in IP_RE.findall(data)]
    domains = [d.decode('utf-8', errors='replace') for d in DOMAIN_RE.findall(data)]
    emails = [e.decode('utf-8', errors='replace') for e in EMAIL_RE.findall(data)]

    # 去重
    return {
        'urls': list(set(urls))[:20],
        'ips': list(set(ips))[:20],
        'domains': list(set(domains))[:20],
        'emails': list(set(emails))[:10],
    }


def calculate_risk(indicators, cves):
    """计算风险等级"""
    score = 0

    # 威胁指标加权
    weights = {
        'javascript': 25,
        'auto_action': 20,
        'launch': 15,
        'embedded_file': 20,
        'form': 10,
        'obfuscation': 25,
    }

    for cat, info in indicators.items():
        score += weights.get(cat, 5)

    # CVE 加权
    for cve in cves:
        if cve['severity'] == 'CRITICAL':
            score += 40
        elif cve['severity'] == 'HIGH':
            score += 25

    if score >= 70:
        return 'CRITICAL', score
    elif score >= 45:
        return 'HIGH', score
    elif score >= 20:
        return 'MEDIUM', score
    else:
        return 'LOW', score


def get_recommendation(risk_level):
    """获取处置建议"""
    recommendations = {
        'CRITICAL': '🚨 立即隔离！禁止在非沙箱环境打开。提取全部 IOC 上报安全团队。建议在离线沙箱中深度分析。',
        'HIGH': '⚠️ 高危文件。在隔离沙箱中分析，提取载荷和 IOC，关联威胁情报。',
        'MEDIUM': '⚡ 中等风险。深度检查特定指标，验证可疑项，关注 JavaScript 和 URL。',
        'LOW': '✅ 低风险。记录扫描结果，标记为已检查。仍建议定期复检。',
    }
    return recommendations.get(risk_level, '未知风险等级')


def triage(filepath, output_json=False):
    """主分诊函数"""
    # Phase 1: 文件验证
    is_pdf, header_info = check_magic(filepath)
    if not is_pdf:
        result = {
            'status': 'REJECTED',
            'reason': header_info,
            'file': filepath,
        }
        if output_json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"❌ 文件拒绝: {header_info}")
        return result

    # Phase 2: 基本信息
    info = extract_pdf_info(filepath)

    # Phase 3: 威胁扫描
    indicators, cves = scan_threats(filepath)

    # Phase 4: IOC 提取
    iocs = extract_iocs(filepath)

    # Phase 5: 风险评级
    risk_level, risk_score = calculate_risk(indicators, cves)
    recommendation = get_recommendation(risk_level)

    result = {
        'status': 'ANALYZED',
        'file': filepath,
        'file_info': info,
        'risk_level': risk_level,
        'risk_score': risk_score,
        'threat_indicators': indicators,
        'cve_matches': cves,
        'iocs': iocs,
        'recommendation': recommendation,
    }

    if output_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"\n{'='*60}")
        print(f"  PDF 安全分诊报告")
        print(f"{'='*60}")
        print(f"\n📄 文件: {filepath}")
        print(f"   大小: {info.get('size', 0):,} bytes")
        print(f"   SHA256: {info.get('sha256', 'N/A')}")
        print(f"   MD5: {info.get('md5', 'N/A')}")
        print(f"   PDF版本: {info.get('pdf_version', 'unknown')}")
        print(f"   页数: {info.get('pages', 'unknown')}")
        if info.get('creator'):
            print(f"   创建者: {info['creator']}")
        if info.get('producer'):
            print(f"   生产者: {info['producer']}")

        print(f"\n🚨 风险等级: {risk_level} (score: {risk_score})")
        print(f"   {recommendation}")

        if indicators:
            print(f"\n📊 威胁指标:")
            threat_names = {
                'javascript': 'JavaScript (内嵌脚本)',
                'auto_action': 'Auto Action (自动执行)',
                'launch': 'Launch Action (启动动作)',
                'embedded_file': 'Embedded File (嵌入文件)',
                'form': 'Form (表单)',
                'obfuscation': 'Obfuscation (混淆)',
            }
            for cat, data in indicators.items():
                name = threat_names.get(cat, cat)
                print(f"   • {name}: {data['count']} 个")

        if cves:
            print(f"\n🔍 CVE 匹配:")
            for cve in cves:
                print(f"   • {cve['cve']} ({cve['severity']}): {cve['name']}")

        if any(iocs.values()):
            print(f"\n📋 IOC 提取:")
            if iocs['urls']:
                print(f"   URL ({len(iocs['urls'])}):")
                for u in iocs['urls'][:5]:
                    print(f"     - {u}")
            if iocs['ips']:
                print(f"   IP ({len(iocs['ips'])}):")
                for ip in iocs['ips'][:5]:
                    print(f"     - {ip}")
            if iocs['domains']:
                print(f"   域名 ({len(iocs['domains'])}):")
                for d in iocs['domains'][:5]:
                    print(f"     - {d}")
            if iocs['emails']:
                print(f"   邮箱 ({len(iocs['emails'])}):")
                for e in iocs['emails'][:5]:
                    print(f"     - {e}")

        print(f"\n{'='*60}")
        print(f"  分诊完成 — 建议根据风险等级采取对应处置措施")
        print(f"{'='*60}\n")

    return result


def main():
    parser = argparse.ArgumentParser(
        description='PDF 快速分诊脚本 — 安全交互式风险评估',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('pdf_file', help='待分析的 PDF 文件路径')
    parser.add_argument('-j', '--json', action='store_true', help='JSON 输出（适合自动化管道）')
    args = parser.parse_args()

    if not os.path.exists(args.pdf_file):
        print(f"错误: 文件不存在 — {args.pdf_file}", file=sys.stderr)
        sys.exit(1)

    triage(args.pdf_file, output_json=args.json)


if __name__ == '__main__':
    main()
