#!/usr/bin/env python3
"""
PDF 安全特征提取工具 v4.0
提取 PDF 文件的安全相关特征，供大模型综合分析判断
不做评分和结论判定，只提供原始信息
"""

import sys
import re
import os
import json
import hashlib
import zlib
from datetime import datetime
from pathlib import Path

# 危险关键字定义
DANGER_KEYWORDS = {
    'critical': [
        (r'/OpenAction', '自动执行动作'),
        (r'/AA\s', '附加动作'),
        (r'/Launch', '启动外部程序'),
        (r'/JavaScript', 'JavaScript 代码'),
        (r'/JS\s', 'JavaScript 引用'),
        (r'/EmbeddedFile', '嵌入文件'),
        (r'/RichMedia', '富媒体内容'),
        (r'/XFA', 'XFA 表单'),
    ],
    'high': [
        (r'/AcroForm', '交互式表单'),
        (r'/SubmitForm', '表单提交'),
        (r'/ImportData', '数据导入'),
        (r'/GoToR', '远程跳转'),
        (r'/GoToE', '嵌入跳转'),
        (r'/URI\s', '外部链接'),
    ],
    'medium': [
        (r'/Encrypt', '加密内容'),
        (r'/ObjStm', '对象流'),
        (r'eval\s*\(', 'JavaScript eval'),
        (r'unescape\s*\(', 'JavaScript unescape'),
    ],
}

# CVE 漏洞特征 (简化版)
CVE_PATTERNS = {
    'CVE-2010-2883': {'patterns': [r'SING', r'uniqueName'], 'desc': 'CoolType SING 表溢出'},
    'CVE-2013-2729': {'patterns': [r'XFA', r'image.*tiff'], 'desc': 'XFA TIFF 图像溢出'},
    'CVE-2010-0188': {'patterns': [r'JBIG2Decode', r'/W\s+\d+'], 'desc': 'JBIG2 解码溢出'},
}


def extract_metadata(content):
    """提取 PDF 元数据"""
    text = content.decode('latin-1', errors='ignore')
    metadata = {}

    patterns = {
        'title': r'/Title\s*\(([^)]*)\)',
        'author': r'/Author\s*\(([^)]*)\)',
        'creator': r'/Creator\s*\(([^)]*)\)',
        'producer': r'/Producer\s*\(([^)]*)\)',
        'creation_date': r'/CreationDate\s*\(([^)]*)\)',
        'mod_date': r'/ModDate\s*\(([^)]*)\)',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        if match:
            metadata[key] = match.group(1).strip()

    # PDF 版本
    version_match = re.search(r'%PDF-(\d\.\d)', text[:100])
    if version_match:
        metadata['pdf_version'] = version_match.group(1)

    return metadata


def extract_keywords(content):
    """提取危险关键字"""
    text = content.decode('latin-1', errors='ignore')
    findings = {'critical': [], 'high': [], 'medium': []}

    for level, patterns in DANGER_KEYWORDS.items():
        for pattern, desc in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                findings[level].append({
                    'keyword': pattern,
                    'description': desc,
                    'count': len(matches)
                })

    return findings


def extract_urls(content):
    """提取所有 URL"""
    text = content.decode('latin-1', errors='ignore')
    url_pattern = r'https?://[^\s<>\"\'\)\]\\]+'
    urls = list(set(re.findall(url_pattern, text, re.IGNORECASE)))

    # 分类
    result = {'all': [], 'executable': [], 'shortened': []}
    exe_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.msi', '.jar']
    shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly']

    for url in urls:
        url_lower = url.lower()
        result['all'].append(url)

        if any(url_lower.endswith(ext) for ext in exe_extensions):
            result['executable'].append(url)
        if any(s in url_lower for s in shorteners):
            result['shortened'].append(url)

    return result


def extract_text_content(content):
    """提取 PDF 文本内容供大模型分析 (限制数量避免超时)"""
    text = content.decode('latin-1', errors='ignore')

    # 限制搜索范围，避免处理时间过长
    if len(text) > 500000:
        text = text[:500000]

    text_parts = []

    # 方法1: 提取 Tj 操作符中的文本 (限制 100 个)
    tj_pattern = r'\(([^)]+)\)\s*Tj'
    for i, match in enumerate(re.finditer(tj_pattern, text)):
        if i >= 100:
            break
        text_parts.append(match.group(1))

    # 方法2: 提取 TJ 数组中的文本 (限制 50 个)
    tj_array_pattern = r'\[(.*?)\]\s*TJ'
    for i, match in enumerate(re.finditer(tj_array_pattern, text, re.DOTALL)):
        if i >= 50:
            break
        array_content = match.group(1)
        strings = re.findall(r'\(([^)]+)\)', array_content)[:10]
        text_parts.extend(strings)

    # 清理：只保留可读文本
    cleaned = []
    for part in text_parts[:200]:  # 限制处理数量
        # 移除 PDF 转义序列
        clean = re.sub(r'\\[0-7]{3}', '', part)
        clean = re.sub(r'\\[nrtbf\\()]', ' ', clean)
        if len(clean) >= 2 and re.search(r'[a-zA-Z\u4e00-\u9fff]', clean):
            cleaned.append(clean.strip())

    unique_text = list(dict.fromkeys(cleaned))
    return ' '.join(unique_text)[:2000]


def extract_javascript(content):
    """提取 JavaScript 代码片段"""
    text = content.decode('latin-1', errors='ignore')
    js_snippets = []

    # 查找 JavaScript 流
    js_pattern = r'/JavaScript[^>]*>>\s*stream\s*(.*?)\s*endstream'
    for match in re.finditer(js_pattern, text, re.DOTALL | re.IGNORECASE):
        snippet = match.group(1)[:200]  # 截取前 200 字符
        js_snippets.append(snippet)

    # 查找内联 JavaScript
    inline_pattern = r'/JS\s*\(([^)]{10,})\)'
    for match in re.finditer(inline_pattern, text):
        js_snippets.append(match.group(1)[:200])

    return js_snippets


def detect_cve(content):
    """检测 CVE 漏洞特征"""
    text = content.decode('latin-1', errors='ignore')
    detected = []

    for cve_id, info in CVE_PATTERNS.items():
        matched = []
        for pattern in info['patterns']:
            if re.search(pattern, text, re.IGNORECASE):
                matched.append(pattern)

        if len(matched) >= 2:  # 需要匹配多个特征
            detected.append({
                'cve': cve_id,
                'description': info['desc'],
                'matched_patterns': matched
            })

    return detected


def extract_form_fields(content):
    """提取 AcroForm 表单字段 (钓鱼检测)"""
    text = content.decode('latin-1', errors='ignore')
    fields = []

    # 查找表单字段定义
    # /T (Field Name) /V (Value) /FT (Field Type)
    field_pattern = r'/T\s*\(([^)]*)\)[^/]*/FT\s*/([A-Za-z]+)'
    for match in re.finditer(field_pattern, text):
        field_name = match.group(1).strip()
        field_type = match.group(2).strip()

        # 检查是否有初始值
        value_match = re.search(r'/V\s*\(([^)]*)\)', text[match.start():match.start()+500])
        field_value = value_match.group(1).strip() if value_match else None

        # 检查是否有提交动作
        submit_match = re.search(r'/SubmitForm', text[match.start():match.start()+500])
        has_submit = bool(submit_match)

        fields.append({
            'name': field_name,
            'type': field_type,
            'value': field_value,
            'has_submit_action': has_submit
        })

    # 检测钓鱼关键词
    phishing_keywords = ['password', 'credit', 'card', 'ssn', 'social', 'account', 'login',
                         'username', 'email', 'pin', 'cvv', 'banking']

    suspicious_fields = []
    for field in fields:
        field_name_lower = field['name'].lower()
        if any(keyword in field_name_lower for keyword in phishing_keywords):
            suspicious_fields.append(field)

    return {
        'total_fields': len(fields),
        'all_fields': fields[:20],  # 限制返回数量
        'suspicious_fields': suspicious_fields,
        'has_submit_action': any(f['has_submit_action'] for f in fields)
    }


def count_objects(text):
    """统计 PDF 对象"""
    return {
        'obj': len(re.findall(r'\d+\s+\d+\s+obj\b', text)),
        'stream': len(re.findall(r'\bstream\b', text)),
        'endstream': len(re.findall(r'\bendstream\b', text)),
        'javascript': len(re.findall(r'/JavaScript', text, re.IGNORECASE)),
        'openaction': len(re.findall(r'/OpenAction', text, re.IGNORECASE)),
        'launch': len(re.findall(r'/Launch', text, re.IGNORECASE)),
        'embeddedfile': len(re.findall(r'/EmbeddedFile', text, re.IGNORECASE)),
        'acroform': len(re.findall(r'/AcroForm', text, re.IGNORECASE)),
        'xfa': len(re.findall(r'/XFA', text, re.IGNORECASE)),
    }


def decompress_streams(content):
    """解压 FlateDecode 流"""
    decompressed = b''
    stream_pattern = rb'/FlateDecode[^>]*>>\s*stream\r?\n(.*?)\r?\n?endstream'

    for match in re.finditer(stream_pattern, content, re.DOTALL):
        try:
            decompressed += zlib.decompress(match.group(1))
        except:
            pass

    return decompressed


def detect_file_type(content):
    """检测文件真实类型（Magic Number 验证）"""
    if len(content) < 8:
        return {'type': 'unknown', 'signature': None}

    # 文件签名数据库
    signatures = {
        b'%PDF-': {'type': 'pdf', 'name': 'PDF Document'},
        b'PK\x03\x04': {'type': 'zip_ooxml', 'name': 'ZIP/OOXML (Word/Excel/PowerPoint)'},
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': {'type': 'ole2', 'name': 'OLE2 (Legacy Office)'},
        b'{\x5C\x72\x74\x66': {'type': 'rtf', 'name': 'Rich Text Format'},
        b'MZ': {'type': 'pe', 'name': 'PE Executable'},
        b'\x7FELF': {'type': 'elf', 'name': 'ELF Executable'},
    }

    header = content[:8]
    for sig, info in signatures.items():
        if header.startswith(sig):
            return {'type': info['type'], 'name': info['name'], 'signature': sig.hex()}

    return {'type': 'unknown', 'signature': header[:4].hex()}


def scan_pdf(filepath):
    """扫描 PDF 文件，提取安全特征"""
    filepath = Path(filepath)

    if not filepath.exists():
        return {'error': f'文件不存在: {filepath}'}

    try:
        with open(filepath, 'rb') as f:
            content = f.read()
    except Exception as e:
        return {'error': f'读取失败: {e}'}

    # 基本信息
    result = {
        'filename': filepath.name,
        'filepath': str(filepath),
        'size': len(content),
        'sha256': hashlib.sha256(content).hexdigest(),
        'scan_time': datetime.now().isoformat(),
    }

    # 文件类型检测（Magic Number 验证）
    file_type_detection = detect_file_type(content)
    result['file_type'] = file_type_detection

    # 检查扩展名伪装
    extension = filepath.suffix.lower()
    detected_type = file_type_detection['type']

    if extension == '.pdf' and detected_type != 'pdf':
        result['warnings'] = result.get('warnings', [])
        result['warnings'].append({
            'type': 'extension_mismatch',
            'severity': 'high',
            'message': f'文件扩展名伪装: 扩展名为 .pdf 但实际是 {file_type_detection["name"]}',
            'expected': 'pdf',
            'actual': detected_type
        })

    # 如果不是 PDF 文件，提前返回
    if detected_type != 'pdf':
        result['is_pdf'] = False
        result['note'] = f'警告: 此文件不是真实的 PDF，而是 {file_type_detection["name"]}'
        return result

    result['is_pdf'] = True

    # 解压流内容
    decompressed = decompress_streams(content)
    combined = content + decompressed

    if decompressed:
        result['decompressed_size'] = len(decompressed)

    # 提取各项特征
    text = content.decode('latin-1', errors='ignore')
    combined_text = text + decompressed.decode('latin-1', errors='ignore') if decompressed else text

    result['metadata'] = extract_metadata(content)
    result['keywords'] = extract_keywords(content + decompressed)
    result['urls'] = extract_urls(content + decompressed)
    result['javascript'] = extract_javascript(content + decompressed)
    result['cve_detected'] = detect_cve(content + decompressed)
    result['object_counts'] = count_objects(text)
    result['text_content'] = extract_text_content(content + decompressed)
    result['form_fields'] = extract_form_fields(content + decompressed)

    # 统计摘要
    result['summary'] = {
        'has_javascript': len(result['javascript']) > 0,
        'has_executable_urls': len(result['urls']['executable']) > 0,
        'has_cve': len(result['cve_detected']) > 0,
        'critical_keywords': len(result['keywords']['critical']),
        'high_keywords': len(result['keywords']['high']),
        'total_urls': len(result['urls']['all']),
        'has_text': len(result['text_content']) > 0,
    }

    return result


def print_report(result):
    """打印简洁报告"""
    if 'error' in result:
        print(f"错误: {result['error']}")
        return

    print("=" * 60)
    print("PDF 特征提取报告 v4.1")
    print("=" * 60)
    print(f"文件: {result['filename']}")
    print(f"大小: {result['size']:,} 字节")
    print(f"SHA256: {result['sha256']}")

    # 文件类型检测
    if 'file_type' in result:
        ft = result['file_type']
        print(f"文件类型: {ft.get('name', 'Unknown')} (Magic: {ft.get('signature', 'N/A')})")

    # 警告信息
    if 'warnings' in result and result['warnings']:
        print("\n[!] 警告:")
        for warn in result['warnings']:
            print(f"  [{warn['severity'].upper()}] {warn['message']}")

    # 如果不是 PDF 文件，显示提示后返回
    if result.get('is_pdf') is False:
        print(f"\n{result.get('note', '')}")
        print("\n建议: 使用对应的分析工具 (office-malware-analyzer) 进行分析")
        print("=" * 60)
        return

    if result.get('decompressed_size'):
        print(f"解压后: {result['decompressed_size']:,} 字节")

    # 元数据
    meta = result['metadata']
    if meta:
        print("\n--- 元数据 ---")
        for k, v in meta.items():
            if v:
                print(f"  {k}: {v}")

    # 对象统计
    counts = result['object_counts']
    notable = {k: v for k, v in counts.items() if v > 0 and k != 'obj'}
    if notable:
        print("\n--- 对象统计 ---")
        for k, v in notable.items():
            print(f"  {k}: {v}")

    # 危险关键字
    keywords = result['keywords']
    if any(keywords.values()):
        print("\n--- 检测到的关键字 ---")
        for level in ['critical', 'high', 'medium']:
            for item in keywords[level]:
                print(f"  [{level.upper()}] {item['description']} ({item['count']}x)")

    # CVE
    if result['cve_detected']:
        print("\n--- CVE 漏洞特征 ---")
        for cve in result['cve_detected']:
            print(f"  {cve['cve']}: {cve['description']}")

    # JavaScript
    if result['javascript']:
        print(f"\n--- JavaScript ({len(result['javascript'])} 段) ---")
        for i, js in enumerate(result['javascript'][:3]):
            print(f"  [{i+1}] {js[:80]}...")

    # 表单字段 (钓鱼检测)
    if 'form_fields' in result and result['form_fields']['total_fields'] > 0:
        form_data = result['form_fields']
        print(f"\n--- 交互式表单字段 ({form_data['total_fields']} 个) ---")

        if form_data['suspicious_fields']:
            print(f"  [!] 发现 {len(form_data['suspicious_fields'])} 个可疑字段 (钓鱼风险):")
            for field in form_data['suspicious_fields']:
                print(f"    - {field['name']} ({field['type']})" +
                      (f" = {field['value']}" if field['value'] else ""))

        if form_data['has_submit_action']:
            print("  [!] 包含表单提交动作 (可能外传数据)")

        if form_data['all_fields'] and not form_data['suspicious_fields']:
            print("  字段列表:")
            for field in form_data['all_fields'][:10]:
                print(f"    - {field['name']} ({field['type']})")

    # URL
    urls = result['urls']
    if urls['executable']:
        print("\n--- 可执行文件 URL ---")
        for url in urls['executable']:
            print(f"  {url}")
    if urls['shortened']:
        print("\n--- 短链接 ---")
        for url in urls['shortened']:
            print(f"  {url}")

    # 文本内容 (供大模型分析)
    if result.get('text_content'):
        print("\n--- 文本内容 (供分析) ---")
        text = result['text_content']
        # 显示前 500 字符
        if len(text) > 500:
            print(f"  {text[:500]}...")
            print(f"  [共 {len(text)} 字符]")
        else:
            print(f"  {text}")

    print("\n" + "=" * 60)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='PDF 特征提取工具 v4.0')
    parser.add_argument('files', nargs='+', help='PDF 文件路径')
    parser.add_argument('-j', '--json', action='store_true', help='输出 JSON 格式')
    parser.add_argument('-o', '--output', help='保存 JSON 到文件')
    args = parser.parse_args()

    results = []
    for filepath in args.files:
        result = scan_pdf(filepath)
        results.append(result)

        if not args.json:
            print_report(result)

    # JSON 输出
    if args.json:
        output = results[0] if len(results) == 1 else results
        print(json.dumps(output, ensure_ascii=False, indent=2))

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"已保存到: {args.output}")


if __name__ == '__main__':
    main()
