#!/usr/bin/env python3
"""
嵌入式 PE/Shellcode 提取工具
用法:
    python3 extract_embedded.py <binary>
    python3 extract_embedded.py <binary> --output ./extracted/
    python3 extract_embedded.py <binary> --shellcode
"""

import argparse
import hashlib
import math
import os
import re
import struct
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


class EmbeddedExtractor:
    """嵌入式内容提取器"""

    # PE 签名
    MZ_SIGNATURE = b'MZ'
    PE_SIGNATURE = b'PE\x00\x00'

    # 常见 shellcode 特征 - 使用更严格的模式避免误报
    SHELLCODE_PATTERNS = [
        # x86 经典 shellcode 开头
        (b'\xfc\xe8', 'x86 CLD + CALL'),
        (b'\x60\xe8', 'x86 PUSHAD + CALL'),
        (b'\xe8\x00\x00\x00\x00', 'x86 CALL $+5 (GetPC)'),
        # x64 shellcode 特征
        (b'\x48\x31\xc9\x48\x81\xe9', 'x64 XOR RCX + SUB'),
        (b'\x48\x31\xd2\x65\x48', 'x64 XOR RDX + GS'),
        # PEB 访问 - 真正的 shellcode 特征
        (b'\x65\x48\x8b\x04\x25\x60\x00\x00\x00', 'x64 PEB access'),
        (b'\x64\xa1\x30\x00\x00\x00', 'x86 PEB access'),
        (b'\x64\x8b\x35\x30\x00\x00\x00', 'x86 PEB via FS'),
        # Metasploit/Cobalt Strike 常见开头
        (b'\xfc\x48\x83\xe4\xf0', 'x64 CLD + AND RSP (Metasploit)'),
        (b'\xfc\x48\x89\xce', 'x64 CLD + MOV RSI (CobaltStrike)'),
        # API hashing
        (b'\xb8\x4c\x77\x26\x07', 'API hash kernel32'),
    ]

    def __init__(self, filepath: str):
        self.path = Path(filepath)
        self.data = self.path.read_bytes()
        self.results: List[Dict[str, Any]] = []

    def find_pe_headers(self) -> List[Dict[str, Any]]:
        """查找所有 PE 头"""
        pe_list = []
        offset = 0

        while True:
            # 查找 MZ 签名
            mz_offset = self.data.find(self.MZ_SIGNATURE, offset)
            if mz_offset == -1:
                break

            # 验证 PE 头
            pe_info = self._validate_pe(mz_offset)
            if pe_info:
                pe_list.append(pe_info)

            offset = mz_offset + 1

        return pe_list

    def _validate_pe(self, mz_offset: int) -> Optional[Dict[str, Any]]:
        """验证并解析 PE 头"""
        try:
            # 检查 e_lfanew (PE 头偏移)
            if mz_offset + 0x40 > len(self.data):
                return None

            e_lfanew = struct.unpack('<I', self.data[mz_offset + 0x3c:mz_offset + 0x40])[0]

            # 合理性检查 - 放宽限制
            if e_lfanew > 0x10000 or e_lfanew < 0x20:
                return None

            pe_offset = mz_offset + e_lfanew

            # 检查 PE 签名
            if pe_offset + 4 > len(self.data):
                return None

            if self.data[pe_offset:pe_offset + 4] != self.PE_SIGNATURE:
                return None

            # 解析 COFF 头
            machine = struct.unpack('<H', self.data[pe_offset + 4:pe_offset + 6])[0]
            num_sections = struct.unpack('<H', self.data[pe_offset + 6:pe_offset + 8])[0]
            optional_hdr_size = struct.unpack('<H', self.data[pe_offset + 20:pe_offset + 22])[0]

            # 架构
            arch_map = {
                0x14c: 'x86',
                0x8664: 'x64',
                0x1c0: 'ARM',
                0xaa64: 'ARM64'
            }
            arch = arch_map.get(machine, f'unknown(0x{machine:x})')

            # 计算 PE 大小
            pe_size = self._calculate_pe_size(mz_offset, pe_offset, num_sections, optional_hdr_size)

            # 判断是否加密/混淆
            is_encrypted = self._check_encrypted(mz_offset, pe_size)

            return {
                'offset': mz_offset,
                'pe_offset': pe_offset,
                'arch': arch,
                'machine': machine,
                'sections': num_sections,
                'size': pe_size,
                'encrypted': is_encrypted,
                'type': 'PE'
            }

        except Exception:
            return None

    def _calculate_pe_size(self, mz_offset: int, pe_offset: int,
                           num_sections: int, optional_hdr_size: int) -> int:
        """计算 PE 文件大小"""
        try:
            # 节表偏移
            section_table_offset = pe_offset + 24 + optional_hdr_size

            max_end = 0
            for i in range(num_sections):
                section_offset = section_table_offset + (i * 40)
                if section_offset + 40 > len(self.data):
                    break

                raw_size = struct.unpack('<I', self.data[section_offset + 16:section_offset + 20])[0]
                raw_ptr = struct.unpack('<I', self.data[section_offset + 20:section_offset + 24])[0]

                section_end = raw_ptr + raw_size
                if section_end > max_end:
                    max_end = section_end

            return max_end if max_end > 0 else 0x1000

        except Exception:
            return 0x1000

    def _check_encrypted(self, offset: int, size: int) -> bool:
        """检查是否加密/混淆"""
        if size < 100:
            return True

        # 检查 DOS stub 区域
        dos_stub = self.data[offset + 0x40:offset + min(0x100, size)]
        if dos_stub:
            entropy = self._calculate_entropy(dos_stub)
            if entropy > 7.0:
                return True

        return False

    def _calculate_entropy(self, data: bytes) -> float:
        """计算熵值"""
        if not data:
            return 0.0

        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)

        return entropy

    def find_shellcode(self, min_size: int = 50) -> List[Dict[str, Any]]:
        """查找可能的 shellcode"""
        shellcode_list = []

        for pattern, desc in self.SHELLCODE_PATTERNS:
            offset = 0
            while True:
                found = self.data.find(pattern, offset)
                if found == -1:
                    break

                # 跳过 PE 头部分
                is_in_pe = any(
                    pe['offset'] <= found < pe['offset'] + pe['size']
                    for pe in self.results if pe['type'] == 'PE'
                )

                if not is_in_pe:
                    # 提取周围数据分析
                    chunk = self.data[found:found + 500]
                    entropy = self._calculate_entropy(chunk)

                    # 高熵值且有可执行特征
                    if entropy > 5.0:
                        shellcode_list.append({
                            'offset': found,
                            'pattern': desc,
                            'entropy': round(entropy, 2),
                            'size': self._estimate_shellcode_size(found),
                            'type': 'Shellcode'
                        })

                offset = found + 1

        # 去重（相近偏移）
        return self._deduplicate_shellcode(shellcode_list)

    def _estimate_shellcode_size(self, offset: int) -> int:
        """估算 shellcode 大小"""
        # 简单启发式：查找连续的高熵值区域
        chunk_size = 16
        size = 0

        while offset + size + chunk_size < len(self.data):
            chunk = self.data[offset + size:offset + size + chunk_size]
            entropy = self._calculate_entropy(chunk)

            # 熵值降低可能是 shellcode 结束
            if entropy < 4.0:
                break

            size += chunk_size

            # 限制最大大小
            if size > 0x10000:
                break

        return max(size, 100)

    def _deduplicate_shellcode(self, shellcode_list: List[Dict]) -> List[Dict]:
        """去重相近的 shellcode"""
        if not shellcode_list:
            return []

        sorted_list = sorted(shellcode_list, key=lambda x: x['offset'])
        result = [sorted_list[0]]

        for sc in sorted_list[1:]:
            if sc['offset'] - result[-1]['offset'] > 100:
                result.append(sc)

        return result

    def find_base64_blobs(self, min_len: int = 100) -> List[Dict[str, Any]]:
        """查找 Base64 编码的数据块"""
        b64_pattern = re.compile(rb'[A-Za-z0-9+/]{%d,}={0,2}' % min_len)
        blobs = []

        for match in b64_pattern.finditer(self.data):
            blob_data = match.group()
            offset = match.start()

            # 尝试解码
            try:
                import base64
                decoded = base64.b64decode(blob_data)

                # 检查是否是 PE
                is_pe = decoded[:2] == b'MZ'

                blobs.append({
                    'offset': offset,
                    'encoded_size': len(blob_data),
                    'decoded_size': len(decoded),
                    'is_pe': is_pe,
                    'type': 'Base64'
                })
            except Exception:
                pass

        return blobs[:20]  # 限制数量

    def extract_all(self) -> List[Dict[str, Any]]:
        """提取所有嵌入内容"""
        # 查找 PE
        pe_list = self.find_pe_headers()

        # 跳过主 PE（偏移 0）
        embedded_pe = [pe for pe in pe_list if pe['offset'] > 0]
        self.results.extend(embedded_pe)

        # 查找 shellcode
        shellcode_list = self.find_shellcode()
        self.results.extend(shellcode_list)

        # 查找 Base64
        b64_list = self.find_base64_blobs()
        self.results.extend(b64_list)

        return self.results

    def save_extracted(self, output_dir: Path) -> List[str]:
        """保存提取的内容"""
        output_dir.mkdir(parents=True, exist_ok=True)
        saved_files = []

        for i, item in enumerate(self.results):
            if item['type'] == 'PE':
                # 提取 PE
                start = item['offset']
                size = item['size']
                pe_data = self.data[start:start + size]

                filename = f"embedded_pe_{i}_{item['arch']}_0x{start:x}.bin"
                filepath = output_dir / filename
                filepath.write_bytes(pe_data)
                saved_files.append(str(filepath))

                # 计算哈希
                item['md5'] = hashlib.md5(pe_data).hexdigest()
                item['sha256'] = hashlib.sha256(pe_data).hexdigest()

            elif item['type'] == 'Shellcode':
                # 提取 shellcode
                start = item['offset']
                size = item['size']
                sc_data = self.data[start:start + size]

                filename = f"shellcode_{i}_0x{start:x}.bin"
                filepath = output_dir / filename
                filepath.write_bytes(sc_data)
                saved_files.append(str(filepath))

                item['md5'] = hashlib.md5(sc_data).hexdigest()

        return saved_files


def print_results(extractor: EmbeddedExtractor):
    """打印结果"""
    print("\n" + "=" * 60)
    print("嵌入式内容提取报告")
    print("=" * 60)

    print(f"\n文件: {extractor.path}")
    print(f"大小: {len(extractor.data):,} bytes")

    # 按类型分组
    pe_list = [r for r in extractor.results if r['type'] == 'PE']
    sc_list = [r for r in extractor.results if r['type'] == 'Shellcode']
    b64_list = [r for r in extractor.results if r['type'] == 'Base64']

    if pe_list:
        print(f"\n[嵌入式 PE] 发现 {len(pe_list)} 个")
        for i, pe in enumerate(pe_list):
            status = "加密/混淆" if pe.get('encrypted') else "明文"
            print(f"  #{i+1} 偏移: 0x{pe['offset']:x}")
            print(f"      架构: {pe['arch']}")
            print(f"      大小: {pe['size']:,} bytes")
            print(f"      状态: {status}")
            if pe.get('md5'):
                print(f"      MD5:  {pe['md5']}")

    if sc_list:
        print(f"\n[Shellcode] 发现 {len(sc_list)} 个")
        for i, sc in enumerate(sc_list):
            print(f"  #{i+1} 偏移: 0x{sc['offset']:x}")
            print(f"      特征: {sc['pattern']}")
            print(f"      熵值: {sc['entropy']}")
            print(f"      大小: ~{sc['size']} bytes")

    if b64_list:
        print(f"\n[Base64 数据块] 发现 {len(b64_list)} 个")
        for i, b64 in enumerate(b64_list):
            pe_flag = " (含 PE)" if b64.get('is_pe') else ""
            print(f"  #{i+1} 偏移: 0x{b64['offset']:x}, "
                  f"编码: {b64['encoded_size']} bytes, "
                  f"解码: {b64['decoded_size']} bytes{pe_flag}")

    if not extractor.results:
        print("\n未发现嵌入内容")

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='嵌入式 PE/Shellcode 提取工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s sample.exe
  %(prog)s sample.exe --output ./extracted/
  %(prog)s sample.exe --json
"""
    )

    parser.add_argument('file', help='二进制文件路径')
    parser.add_argument('--output', '-o', help='输出目录（保存提取的文件）')
    parser.add_argument('--json', action='store_true', help='JSON 输出')
    parser.add_argument('--shellcode', action='store_true', help='仅查找 shellcode')

    args = parser.parse_args()

    if not Path(args.file).exists():
        print(f"文件不存在: {args.file}", file=sys.stderr)
        sys.exit(1)

    extractor = EmbeddedExtractor(args.file)

    if args.shellcode:
        results = extractor.find_shellcode()
        extractor.results = results
    else:
        extractor.extract_all()

    if args.json:
        import json
        print(json.dumps(extractor.results, indent=2, default=str))
    else:
        print_results(extractor)

    if args.output:
        output_dir = Path(args.output)
        saved = extractor.save_extracted(output_dir)
        if saved:
            print(f"\n已保存 {len(saved)} 个文件到: {output_dir}")
            for f in saved:
                print(f"  - {f}")


if __name__ == "__main__":
    main()
