#!/usr/bin/env python3
"""
邮箱附件安全分诊脚本
对下载的邮箱附件文件进行类型检测、哈希计算、风险评级和 IOC 提取

用法:
    python attachment_triage.py <FILE> [OPTIONS]
    python attachment_triage.py <DIR> --batch [OPTIONS]
"""

import sys
import os
import re
import json
import hashlib
import argparse
from pathlib import Path
from datetime import datetime

# ============================================================
# Magic Bytes 文件类型签名库
# ============================================================

MAGIC_SIGNATURES = {
    # 可执行文件
    b'MZ': ('PE32 executable (MS Windows)', 'executable', 'high'),
    b'\x7fELF': ('ELF executable', 'executable', 'high'),
    b'\xca\xfe\xba\xbe': ('Mach-O binary', 'executable', 'high'),
    # 脚本/宏
    b'PK\x03\x04': ('ZIP archive (可能含 Office Open XML)', 'archive', 'medium'),
    b'\xd0\xcf\x11\xe0': ('OLE2 Compound Document (Office)', 'office', 'medium'),
    b'%PDF': ('PDF document', 'document', 'low'),
    b'Rar!\x1a\x07': ('RAR archive', 'archive', 'medium'),
    b'\x1f\x8b': ('GZIP archive', 'archive', 'low'),
    b'\x50\x4b\x05\x06': ('ZIP empty archive', 'archive', 'low'),
    b'\x37\x7a\xbc\xaf\x27\x1c': ('7z archive', 'archive', 'medium'),
    b'\x49\x54\x53\x46': ('InstallShield installer', 'installer', 'high'),
    b'\x4d\x53\x43\x46': ('Microsoft Cabinet file', 'archive', 'medium'),
    # 脚本
    b'<?xml': ('XML document', 'document', 'low'),
    b'<html': ('HTML document', 'document', 'medium'),
    b'<HTML': ('HTML document', 'document', 'medium'),
    b'<!DOCTYPE': ('HTML document', 'document', 'medium'),
    # 图片
    b'\xff\xd8\xff': ('JPEG image', 'image', 'low'),
    b'\x89PNG': ('PNG image', 'image', 'low'),
    b'GIF8': ('GIF image', 'image', 'low'),
}

# 高风险文件扩展名
HIGH_RISK_EXTENSIONS = {
    '.exe': 'PE 可执行文件',
    '.dll': '动态链接库',
    '.scr': '屏幕保护程序（实为PE）',
    '.bat': '批处理脚本',
    '.cmd': 'Windows命令脚本',
    '.ps1': 'PowerShell脚本',
    '.vbs': 'VBScript',
    '.hta': 'HTML Application',
    '.msi': 'Windows Installer',
    '.jar': 'Java Archive',
    '.lnk': 'Windows Shortcut',
}

# 中风险文件扩展名
MEDIUM_RISK_EXTENSIONS = {
    '.docm': 'Word 宏文档',
    '.xlsm': 'Excel 宏文档',
    '.pptm': 'PowerPoint 宏文档',
    '.doc': 'Word 97-2003 文档',
    '.xls': 'Excel 97-2003 文档',
    '.js': 'JavaScript 文件',
    '.jse': 'JScript Encoded',
    '.wsh': 'Windows Script Host',
    '.iso': '光盘镜像',
    '.img': '磁盘镜像',
    '.vhd': '虚拟硬盘',
}

# 可疑文件名模式
SUSPICIOUS_NAME_PATTERNS = [
    (r'\.pdf\.exe$', '双扩展名伪装: PDF→EXE'),
    (r'\.doc\.exe$', '双扩展名伪装: DOC→EXE'),
    (r'\.xls\.exe$', '双扩展名伪装: XLS→EXE'),
    (r'\.[a-z]{3}\.[a-z]{3}$', '可能的双扩展名'),
    (r'invoice|faktura|factura|rechnung', '钓鱼常用文件名: 发票'),
    (r'password|passwd|credential', '钓鱼常用文件名: 密码'),
    (r'shipping|delivery|parcel|fedex|ups|dhl', '钓鱼常用文件名: 快递'),
    (r'cv|resume|curriculum', '钓鱼常用文件名: 简历'),
    (r'bonus|salary|payment|transfer', '钓鱼常用文件名: 财务'),
]

# URL 提取正则
URL_PATTERNS = [
    re.compile(rb'https?://[^\s<>"\x00-\x1f]{4,}', re.IGNORECASE),
    re.compile(rb'[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\x00-\x1f]*)?', re.IGNORECASE),
]


# ============================================================
# 核心分析函数
# ============================================================

def compute_hashes(filepath):
    """计算文件的 MD5 和 SHA256 哈希"""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            md5.update(data)
            sha256.update(data)
    return md5.hexdigest(), sha256.hexdigest()


def detect_file_type(filepath):
    """通过 magic bytes 检测文件真实类型"""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(16)
    except Exception:
        return ('Unknown', 'unknown', 'unknown')

    for magic, info in MAGIC_SIGNATURES.items():
        if header.startswith(magic):
            return info
    return ('Unknown', 'unknown', 'unknown')


def get_declared_type(filepath):
    """从文件扩展名推断声明类型"""
    ext = Path(filepath).suffix.lower()
    type_map = {
        '.pdf': 'application/pdf',
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.xls': 'application/vnd.ms-excel',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.zip': 'application/zip',
        '.exe': 'application/x-msdownload',
        '.js': 'text/javascript',
        '.html': 'text/html',
        '.txt': 'text/plain',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.json': 'application/json',
    }
    return type_map.get(ext, 'application/octet-stream')


def check_type_mismatch(real_type, declared_type):
    """检查文件类型是否伪装"""
    real_category = real_type[1] if isinstance(real_type, tuple) else 'unknown'
    declared_lower = declared_type.lower()

    # 可执行文件伪装为文档
    if real_category == 'executable':
        if any(x in declared_lower for x in ['pdf', 'word', 'excel', 'powerpoint', 'document', 'image']):
            return True, 'CRITICAL', f'可执行文件伪装为文档 (声称为 {declared_type})'
        return True, 'HIGH', f'可执行文件未声明 (声称为 {declared_type})'

    # Office 文档伪装
    if 'ole2' in str(real_type).lower() and 'pdf' in declared_lower:
        return True, 'MEDIUM', 'Office 文件伪装为 PDF'

    return False, 'LOW', '类型一致'


def extract_urls(filepath, max_urls=50):
    """从文件中提取 URL 和域名"""
    urls = set()
    try:
        with open(filepath, 'rb') as f:
            # 限制读取大小（前 5MB）
            data = f.read(5 * 1024 * 1024)

        for pattern in URL_PATTERNS:
            for match in pattern.findall(data):
                url = match.decode('utf-8', errors='ignore').rstrip('.,;)')
                if len(url) > 4 and not url.startswith(('127.0.0.1', 'localhost', '0.0.0.0')):
                    urls.add(url)
                if len(urls) >= max_urls:
                    break
            if len(urls) >= max_urls:
                break
    except Exception:
        pass

    return sorted(urls)


def check_suspicious_name(filepath):
    """检查文件名是否可疑"""
    filename = os.path.basename(filepath).lower()
    findings = []
    for pattern, desc in SUSPICIOUS_NAME_PATTERNS:
        if re.search(pattern, filename, re.IGNORECASE):
            findings.append(desc)
    return findings


def assess_risk(filepath, real_type_info, type_mismatch, suspicious_name_findings, urls):
    """综合风险评估"""
    risk_score = 0
    risk_reasons = []
    risk_level = 'Low'

    real_category = real_type_info[1] if isinstance(real_type_info, tuple) else 'unknown'
    ext = Path(filepath).suffix.lower()

    # 类型伪装 = Critical
    if type_mismatch[0] and type_mismatch[1] == 'CRITICAL':
        risk_score += 50
        risk_reasons.append(f'🔴 {type_mismatch[2]}')

    # 高风险扩展名
    if ext in HIGH_RISK_EXTENSIONS:
        risk_score += 20
        risk_reasons.append(f'高风险文件类型: {HIGH_RISK_EXTENSIONS[ext]}')
        risk_level = 'High'

    # 中风险扩展名
    if ext in MEDIUM_RISK_EXTENSIONS:
        risk_score += 10
        risk_reasons.append(f'中风险文件类型: {MEDIUM_RISK_EXTENSIONS[ext]}')

    # 可疑文件名
    for finding in suspicious_name_findings:
        risk_score += 8
        risk_reasons.append(f'可疑文件名: {finding}')

    # 嵌入 URL
    suspicious_urls = [u for u in urls if not any(x in u for x in ['microsoft.com', 'google.com', 'adobe.com', 'w3.org'])]
    if suspicious_urls:
        risk_score += min(15, len(suspicious_urls) * 3)
        risk_reasons.append(f'发现 {len(suspicious_urls)} 个嵌入 URL')

    # 可执行文件类别
    if real_category == 'executable':
        risk_score += 15
        risk_reasons.append('文件为可执行格式')

    # 计算最终风险等级
    if risk_score >= 50 or (type_mismatch[0] and type_mismatch[1] == 'CRITICAL'):
        risk_level = 'Critical'
    elif risk_score >= 30:
        risk_level = 'High'
    elif risk_score >= 15:
        risk_level = 'Medium'
    else:
        risk_level = 'Low'

    return risk_level, risk_reasons


def recommend_skill(filepath, real_type_info, risk_level):
    """基于文件类型和风险等级推荐下游分析技能"""
    real_category = real_type_info[1] if isinstance(real_type_info, tuple) else 'unknown'
    ext = Path(filepath).suffix.lower()

    if real_category == 'executable':
        return 'binary-reverse-engineering', '可执行文件逆向分析'
    if real_category == 'office' or ext in ['.docm', '.xlsm', '.pptm', '.doc', '.xls', '.ppt']:
        return 'office-malware-analyzer', 'Office 文档宏分析'
    if ext == '.pdf' or real_type_info[0] == 'PDF document':
        return 'pdf-analysis', 'PDF 文件分析'
    if ext in ['.zip', '.rar', '.7z', '.gz']:
        return '解压后按类型分析', '压缩包需解压后分析'
    if ext in ['.js', '.vbs', '.hta', '.ps1']:
        return 'code-audit', '脚本代码审计'
    if risk_level in ['High', 'Critical']:
        return 'binary-reverse-engineering', '高风险文件深度分析'

    return None, '暂无推荐'


# ============================================================
# 报告生成
# ============================================================

def analyze_file(filepath, extract_urls_flag=True, check_hash_flag=True):
    """分析单个文件"""
    filepath = str(filepath)
    result = {
        'file': filepath,
        'filename': os.path.basename(filepath),
        'size': os.path.getsize(filepath),
        'analyzed_at': datetime.now().isoformat(),
    }

    # 哈希计算
    if check_hash_flag:
        md5, sha256 = compute_hashes(filepath)
        result['md5'] = md5
        result['sha256'] = sha256

    # 文件类型检测
    real_type_info = detect_file_type(filepath)
    declared_type = get_declared_type(filepath)
    type_mismatch = check_type_mismatch(real_type_info, declared_type)

    result['real_type'] = real_type_info[0]
    result['declared_type'] = declared_type
    result['type_match'] = not type_mismatch[0]

    # 文件名检查
    suspicious_names = check_suspicious_name(filepath)
    result['suspicious_name'] = suspicious_names

    # URL 提取
    if extract_urls_flag:
        urls = extract_urls(filepath)
        result['embedded_urls'] = urls
    else:
        urls = []

    # 风险评估
    risk_level, risk_reasons = assess_risk(
        filepath, real_type_info, type_mismatch, suspicious_names, urls
    )
    result['risk_level'] = risk_level
    result['risk_reasons'] = risk_reasons

    # 推荐技能
    skill, skill_desc = recommend_skill(filepath, real_type_info, risk_level)
    result['recommended_skill'] = skill
    result['recommended_action'] = skill_desc

    # ATT&CK 映射提示
    if type_mismatch[0] and type_mismatch[1] == 'CRITICAL':
        result['attack_mapping'] = 'T1036.008 (Masquerade File Type)'
    elif real_type_info[1] == 'executable':
        result['attack_mapping'] = 'T1204.002 (Malicious File), T1105 (Ingress Tool Transfer)'
    elif suspicious_names:
        result['attack_mapping'] = 'T1566.001 (Spearphishing Attachment)'

    return result


def print_report(result, output_format='text'):
    """输出分析报告"""
    if output_format == 'json':
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    filename = result['filename']
    print()
    print("=" * 60)
    print(f"📧 邮箱附件安全分诊报告")
    print("=" * 60)
    print()
    print(f"【文件基本信息】")
    print(f"  文件名: {filename}")
    print(f"  大小: {result['size']:,} bytes ({result['size']/1024:.1f} KB)")
    if result.get('md5'):
        print(f"  MD5: {result['md5']}")
    if result.get('sha256'):
        print(f"  SHA256: {result['sha256']}")
    print()
    print(f"【类型分析】")
    print(f"  声称类型: {result['declared_type']}")
    print(f"  真实类型: {result['real_type']}")
    if not result['type_match']:
        print(f"  ⚠️ 类型伪装! {result.get('risk_reasons', ['类型不一致'])[0]}")
    else:
        print(f"  ✓ 类型一致")
    print()

    # 文件名检查
    if result.get('suspicious_name'):
        print(f"【文件名可疑特征】")
        for s in result['suspicious_name']:
            print(f"  ⚠️ {s}")
        print()

    # URL 提取
    urls = result.get('embedded_urls', [])
    if urls:
        print(f"【嵌入 URL ({len(urls)} 个)】")
        for url in urls[:10]:
            print(f"  → {url}")
        if len(urls) > 10:
            print(f"  ... 还有 {len(urls) - 10} 个")
        print()

    # 风险评估
    risk_emoji = {'Low': '🟢', 'Medium': '🟡', 'High': '🟠', 'Critical': '🔴'}
    print(f"【风险评估】")
    print(f"  风险等级: {risk_emoji.get(result['risk_level'], '?')} {result['risk_level']}")
    for reason in result.get('risk_reasons', []):
        print(f"  - {reason}")
    print()

    # ATT&CK 映射
    if result.get('attack_mapping'):
        print(f"【ATT&CK 映射】")
        print(f"  {result['attack_mapping']}")
        print()

    # 推荐操作
    if result.get('recommended_skill'):
        print(f"【推荐操作】")
        print(f"  → 调用 {result['recommended_skill']}: {result['recommended_action']}")
        if result.get('sha256'):
            print(f"  → 使用 SHA256 查询 VirusTotal")
        print()

    print("=" * 60)


# ============================================================
# 主入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='邮箱附件安全分诊脚本',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('file', help='待分析的文件或目录路径')
    parser.add_argument('--batch', action='store_true', help='批量分析目录下所有文件')
    parser.add_argument('-o', '--output', default='text', choices=['text', 'json'],
                        help='输出格式 (默认: text)')
    parser.add_argument('--extract-urls', action='store_true', default=True,
                        help='从文件中提取可疑 URL (默认开启)')
    parser.add_argument('--no-extract-urls', dest='extract_urls', action='store_false',
                        help='不提取 URL')
    parser.add_argument('--check-hash', action='store_true', default=True,
                        help='计算文件哈希 (默认开启)')
    parser.add_argument('--no-check-hash', dest='check_hash', action='store_false',
                        help='不计算哈希')

    args = parser.parse_args()

    target = Path(args.file)

    if target.is_dir():
        if args.batch:
            # 批量分析
            files = [f for f in target.iterdir() if f.is_file() and not f.name.startswith('.')]
            if args.output == 'json':
                results = []
                for f in files:
                    r = analyze_file(str(f), args.extract_urls, args.check_hash)
                    results.append(r)
                print(json.dumps(results, ensure_ascii=False, indent=2))
            else:
                print(f"\n📁 批量分析: {len(files)} 个文件")
                for f in files:
                    try:
                        r = analyze_file(str(f), args.extract_urls, args.check_hash)
                        print_report(r, 'text')
                    except Exception as e:
                        print(f"\n❌ 分析失败: {f.name} — {e}")
            return
        else:
            print("错误: 目标是目录，请使用 --batch 选项", file=sys.stderr)
            sys.exit(1)

    if not target.exists():
        print(f"错误: 文件不存在 — {target}", file=sys.stderr)
        sys.exit(1)

    try:
        result = analyze_file(str(target), args.extract_urls, args.check_hash)
        print_report(result, args.output)
    except Exception as e:
        print(f"❌ 分析失败: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
