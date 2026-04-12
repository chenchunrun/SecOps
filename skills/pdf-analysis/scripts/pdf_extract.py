#!/usr/bin/env python3
"""
PDF 内容提取工具
提取 PDF 中的嵌入文件、图像、文本
用法: python3 pdf_extract.py sample.pdf [--files] [--images] [--text] [--qr]
"""

import sys
import os
import re
import json
import hashlib
import zlib
import struct
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# 危险文件扩展名（提取时重命名）
DANGEROUS_EXTENSIONS = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.com', '.pif', '.msi'}

# 可选依赖
try:
    import fitz  # PyMuPDF
    HAS_PYMUPDF = True
except ImportError:
    HAS_PYMUPDF = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from pyzbar.pyzbar import decode as decode_qr
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False


def safe_filename(name: str) -> str:
    """生成安全文件名，危险扩展名追加 _"""
    ext = Path(name).suffix.lower()
    if ext in DANGEROUS_EXTENSIONS:
        return name + "_"
    return name


def extract_with_pymupdf(filepath: str, output_dir: Path, options: dict) -> Dict[str, Any]:
    """使用 PyMuPDF 提取内容"""
    result = {
        'embedded_files': [],
        'images': [],
        'text': '',
        'qr_codes': [],
        'pages': 0,
    }

    doc = fitz.open(filepath)
    result['pages'] = len(doc)

    # 提取嵌入文件
    if options.get('files') or options.get('all'):
        files_dir = output_dir / 'files'
        files_dir.mkdir(exist_ok=True)

        # 方法1: 从 EmbeddedFiles 名称树提取
        try:
            if doc.embfile_count() > 0:
                for i in range(doc.embfile_count()):
                    info = doc.embfile_info(i)
                    name = info.get('name', f'embedded_{i}')
                    data = doc.embfile_get(i)

                    safe_name = safe_filename(name)
                    file_path = files_dir / safe_name
                    file_path.write_bytes(data)

                    result['embedded_files'].append({
                        'name': name,
                        'saved_as': safe_name,
                        'size': len(data),
                        'sha256': hashlib.sha256(data).hexdigest(),
                    })
        except Exception as e:
            result['embedded_files_error'] = str(e)

        # 方法2: 从附件提取
        try:
            for page in doc:
                annots = page.annots()
                if annots:
                    for annot in annots:
                        if annot.type[0] == 17:  # FileAttachment
                            file_info = annot.file_info
                            if file_info:
                                name = file_info.get('filename', f'attachment_{len(result["embedded_files"])}')
                                data = annot.file_get()

                                safe_name = safe_filename(name)
                                file_path = files_dir / safe_name
                                file_path.write_bytes(data)

                                result['embedded_files'].append({
                                    'name': name,
                                    'saved_as': safe_name,
                                    'size': len(data),
                                    'sha256': hashlib.sha256(data).hexdigest(),
                                    'source': 'annotation',
                                })
        except Exception as e:
            pass  # 注释提取失败不影响其他功能

    # 提取图像
    if options.get('images') or options.get('all'):
        images_dir = output_dir / 'images'
        images_dir.mkdir(exist_ok=True)

        img_count = 0
        for page_num, page in enumerate(doc):
            image_list = page.get_images()
            for img_index, img in enumerate(image_list):
                xref = img[0]
                try:
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]
                    image_ext = base_image["ext"]

                    img_name = f"page{page_num + 1}_img{img_index + 1}.{image_ext}"
                    img_path = images_dir / img_name
                    img_path.write_bytes(image_bytes)

                    result['images'].append({
                        'name': img_name,
                        'page': page_num + 1,
                        'size': len(image_bytes),
                        'format': image_ext,
                        'sha256': hashlib.sha256(image_bytes).hexdigest(),
                    })
                    img_count += 1
                except Exception as e:
                    pass

        # 二维码检测
        if (options.get('qr') or options.get('all')) and HAS_PYZBAR and HAS_PIL:
            for img_info in result['images']:
                img_path = images_dir / img_info['name']
                try:
                    img = Image.open(img_path)
                    qr_codes = decode_qr(img)
                    for qr in qr_codes:
                        result['qr_codes'].append({
                            'image': img_info['name'],
                            'type': qr.type,
                            'data': qr.data.decode('utf-8', errors='ignore'),
                        })
                except Exception as e:
                    pass

    # 提取文本
    if options.get('text') or options.get('all'):
        text_parts = []
        for page in doc:
            text_parts.append(page.get_text())
        result['text'] = '\n'.join(text_parts)

        # 保存文本
        text_file = output_dir / 'text_content.txt'
        text_file.write_text(result['text'], encoding='utf-8')

    doc.close()
    return result


def extract_without_pymupdf(filepath: str, output_dir: Path, options: dict) -> Dict[str, Any]:
    """不依赖 PyMuPDF 的提取方法（有限功能）"""
    result = {
        'embedded_files': [],
        'images': [],
        'text': '',
        'qr_codes': [],
        'warning': '未安装 PyMuPDF，功能受限。建议: pip install PyMuPDF',
    }

    with open(filepath, 'rb') as f:
        content = f.read()

    text = content.decode('latin-1', errors='ignore')

    # 提取嵌入文件（基础方法：搜索 EmbeddedFile 对象）
    if options.get('files') or options.get('all'):
        files_dir = output_dir / 'files'
        files_dir.mkdir(exist_ok=True)

        # 查找嵌入文件流
        # 这是简化版，可能无法提取所有嵌入文件
        embfile_pattern = rb'/EmbeddedFile[^>]*>>\s*stream\r?\n(.*?)\r?\n?endstream'
        for i, match in enumerate(re.finditer(embfile_pattern, content, re.DOTALL)):
            try:
                data = match.group(1)
                # 尝试解压
                try:
                    data = zlib.decompress(data)
                except:
                    pass

                # 检测文件类型
                ext = '.bin'
                if data[:4] == b'PK\x03\x04':
                    ext = '.zip'
                elif data[:2] == b'MZ':
                    ext = '.exe_'  # 危险文件
                elif data[:4] == b'\xd0\xcf\x11\xe0':
                    ext = '.ole'
                elif data[:5] == b'%PDF-':
                    ext = '.pdf'

                name = f'embedded_{i}{ext}'
                file_path = files_dir / name
                file_path.write_bytes(data)

                result['embedded_files'].append({
                    'name': name,
                    'size': len(data),
                    'sha256': hashlib.sha256(data).hexdigest(),
                    'note': '基础提取，可能不完整',
                })
            except Exception as e:
                pass

    # 提取图像（基础方法）
    if options.get('images') or options.get('all'):
        images_dir = output_dir / 'images'
        images_dir.mkdir(exist_ok=True)

        # 查找 JPEG 图像（搜索 JPEG 魔数）
        jpeg_starts = []
        for m in re.finditer(b'\xff\xd8\xff', content):
            jpeg_starts.append(m.start())

        for i, start in enumerate(jpeg_starts[:50]):  # 限制数量
            # 查找 JPEG 结束标记
            end = content.find(b'\xff\xd9', start)
            if end > start and end - start < 10 * 1024 * 1024:  # 限制 10MB
                img_data = content[start:end + 2]
                name = f'image_{i}.jpg'
                img_path = images_dir / name
                img_path.write_bytes(img_data)

                result['images'].append({
                    'name': name,
                    'size': len(img_data),
                    'format': 'jpg',
                    'sha256': hashlib.sha256(img_data).hexdigest(),
                    'note': '基础提取',
                })

        # 二维码检测
        if (options.get('qr') or options.get('all')) and HAS_PYZBAR and HAS_PIL:
            for img_info in result['images']:
                img_path = images_dir / img_info['name']
                try:
                    img = Image.open(img_path)
                    qr_codes = decode_qr(img)
                    for qr in qr_codes:
                        result['qr_codes'].append({
                            'image': img_info['name'],
                            'type': qr.type,
                            'data': qr.data.decode('utf-8', errors='ignore'),
                        })
                except Exception as e:
                    pass

    # 提取文本（基础方法）
    if options.get('text') or options.get('all'):
        text_parts = []

        # 解压 FlateDecode 流
        stream_pattern = rb'/FlateDecode[^>]*>>\s*stream\r?\n(.*?)\r?\n?endstream'
        for match in re.finditer(stream_pattern, content, re.DOTALL):
            try:
                decompressed = zlib.decompress(match.group(1))
                decoded = decompressed.decode('utf-8', errors='ignore')

                # 提取 Tj/TJ 文本
                for text_match in re.finditer(r'\(([^)]+)\)\s*Tj', decoded):
                    text_parts.append(text_match.group(1))
            except:
                pass

        result['text'] = ' '.join(text_parts)

        # 保存文本
        if result['text']:
            text_file = output_dir / 'text_content.txt'
            text_file.write_text(result['text'], encoding='utf-8')

    return result


def extract_pdf(filepath: str, output_dir: Optional[str] = None, options: dict = None) -> Dict[str, Any]:
    """主提取函数"""
    filepath = Path(filepath)
    if not filepath.exists():
        return {'error': f'文件不存在: {filepath}'}

    if options is None:
        options = {'all': True}

    # 创建输出目录
    if output_dir:
        out_path = Path(output_dir)
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        out_path = Path('./extracted') / f"{timestamp}_{filepath.stem}"

    out_path.mkdir(parents=True, exist_ok=True)

    # 选择提取方法
    if HAS_PYMUPDF:
        result = extract_with_pymupdf(str(filepath), out_path, options)
    else:
        result = extract_without_pymupdf(str(filepath), out_path, options)

    result['source_file'] = str(filepath)
    result['output_dir'] = str(out_path)
    result['extract_time'] = datetime.now().isoformat()

    # 保存 JSON 报告
    report_file = out_path / 'extract_report.json'
    with open(report_file, 'w', encoding='utf-8') as f:
        # 不保存完整文本到 JSON（太大）
        result_copy = result.copy()
        if len(result_copy.get('text', '')) > 1000:
            result_copy['text'] = result_copy['text'][:1000] + f'... [共 {len(result["text"])} 字符，完整内容见 text_content.txt]'
        json.dump(result_copy, f, ensure_ascii=False, indent=2)

    return result


def print_result(result: Dict[str, Any]):
    """打印结果"""
    if 'error' in result:
        print(f"错误: {result['error']}")
        return

    print("=" * 60)
    print("PDF 内容提取报告")
    print("=" * 60)
    print(f"源文件: {result.get('source_file', 'N/A')}")
    print(f"输出目录: {result.get('output_dir', 'N/A')}")
    print(f"页数: {result.get('pages', 'N/A')}")

    if result.get('warning'):
        print(f"\n[!] {result['warning']}")

    # 嵌入文件
    files = result.get('embedded_files', [])
    if files:
        print(f"\n--- 嵌入文件 ({len(files)} 个) ---")
        for f in files:
            status = "[!] 已重命名" if f.get('saved_as', f['name']) != f['name'] else ""
            print(f"  {f['name']} ({f['size']:,} bytes) {status}")
            print(f"    SHA256: {f['sha256'][:32]}...")

    # 图像
    images = result.get('images', [])
    if images:
        print(f"\n--- 图像 ({len(images)} 个) ---")
        for img in images[:10]:  # 只显示前 10 个
            print(f"  {img['name']} ({img['format']}, {img['size']:,} bytes)")
        if len(images) > 10:
            print(f"  ... 还有 {len(images) - 10} 个")

    # 二维码
    qr_codes = result.get('qr_codes', [])
    if qr_codes:
        print(f"\n--- 二维码 ({len(qr_codes)} 个) ---")
        for qr in qr_codes:
            print(f"  [{qr['type']}] {qr['data'][:100]}")

    # 文本
    text = result.get('text', '')
    if text:
        print(f"\n--- 文本内容 ({len(text)} 字符) ---")
        preview = text[:500].replace('\n', ' ')
        print(f"  {preview}...")
        print(f"  [完整内容见 text_content.txt]")

    print("\n" + "=" * 60)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='PDF 内容提取工具')
    parser.add_argument('file', help='PDF 文件路径')
    parser.add_argument('-o', '--output', help='输出目录')
    parser.add_argument('--all', action='store_true', help='提取全部内容')
    parser.add_argument('--files', action='store_true', help='提取嵌入文件')
    parser.add_argument('--images', action='store_true', help='提取图像')
    parser.add_argument('--text', action='store_true', help='提取文本')
    parser.add_argument('--qr', action='store_true', help='检测二维码')
    parser.add_argument('-j', '--json', action='store_true', help='输出 JSON')

    args = parser.parse_args()

    # 如果没有指定任何选项，默认提取全部
    options = {
        'all': args.all or not (args.files or args.images or args.text or args.qr),
        'files': args.files,
        'images': args.images,
        'text': args.text,
        'qr': args.qr,
    }

    result = extract_pdf(args.file, args.output, options)

    if args.json:
        # JSON 输出时不包含完整文本
        result_copy = result.copy()
        if len(result_copy.get('text', '')) > 1000:
            result_copy['text'] = f"[{len(result['text'])} 字符，见 text_content.txt]"
        print(json.dumps(result_copy, ensure_ascii=False, indent=2))
    else:
        print_result(result)


if __name__ == '__main__':
    main()
