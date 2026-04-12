#!/usr/bin/env python3
"""
URL 脱敏/还原工具
将 URL 脱敏为安全格式，或还原脱敏的 URL
"""

import argparse
import json
import re
import sys
from typing import Dict, List


class URLDefanger:
    """URL 脱敏器"""

    def __init__(self):
        pass

    def defang(self, url: str) -> str:
        """
        脱敏 URL

        Args:
            url: 原始 URL

        Returns:
            str: 脱敏后的 URL
        """
        result = url

        # 协议脱敏
        result = re.sub(r'http://', 'hxxp://', result, flags=re.IGNORECASE)
        result = re.sub(r'https://', 'hxxps://', result, flags=re.IGNORECASE)
        result = re.sub(r'ftp://', 'fxp://', result, flags=re.IGNORECASE)

        # 点号脱敏（避免自动链接）
        # 但保留路径中的点号
        parts = result.split('/')
        if len(parts) >= 3:
            # 只脱敏域名部分的点号
            domain_part = parts[2]
            domain_defanged = domain_part.replace('.', '[.]')
            parts[2] = domain_defanged
            result = '/'.join(parts)
        else:
            # 没有协议的情况
            result = result.replace('.', '[.]')

        return result

    def refang(self, url: str) -> str:
        """
        还原脱敏的 URL

        Args:
            url: 脱敏的 URL

        Returns:
            str: 还原后的 URL
        """
        result = url

        # 还原协议
        result = re.sub(r'hxxp://', 'http://', result, flags=re.IGNORECASE)
        result = re.sub(r'hxxps://', 'https://', result, flags=re.IGNORECASE)
        result = re.sub(r'fxp://', 'ftp://', result, flags=re.IGNORECASE)
        result = re.sub(r'h\[tt\]p://', 'http://', result, flags=re.IGNORECASE)
        result = re.sub(r'h\[tt\]ps://', 'https://', result, flags=re.IGNORECASE)

        # 还原点号
        result = result.replace('[.]', '.')
        result = result.replace('[dot]', '.')
        result = result.replace('(dot)', '.')
        result = result.replace(' dot ', '.')

        # 还原 @ 符号
        result = result.replace('[at]', '@')
        result = result.replace('[@]', '@')
        result = result.replace('(at)', '@')

        return result

    def defang_batch(self, urls: List[str]) -> List[str]:
        """批量脱敏"""
        return [self.defang(url) for url in urls]

    def refang_batch(self, urls: List[str]) -> List[str]:
        """批量还原"""
        return [self.refang(url) for url in urls]


class IPDefanger:
    """IP 地址脱敏器"""

    def defang(self, ip: str) -> str:
        """脱敏 IP 地址"""
        return ip.replace('.', '[.]')

    def refang(self, ip: str) -> str:
        """还原脱敏的 IP"""
        result = ip
        result = result.replace('[.]', '.')
        result = result.replace('[dot]', '.')
        result = result.replace('(dot)', '.')
        return result


class DomainDefanger:
    """域名脱敏器"""

    def defang(self, domain: str) -> str:
        """脱敏域名"""
        return domain.replace('.', '[.]')

    def refang(self, domain: str) -> str:
        """还原脱敏的域名"""
        result = domain
        result = result.replace('[.]', '.')
        result = result.replace('[dot]', '.')
        result = result.replace('(dot)', '.')
        return result


class EmailDefanger:
    """邮箱地址脱敏器"""

    def defang(self, email: str) -> str:
        """脱敏邮箱地址"""
        result = email
        result = result.replace('@', '[@]')
        result = result.replace('.', '[.]')
        return result

    def refang(self, email: str) -> str:
        """还原脱敏的邮箱"""
        result = email
        result = result.replace('[@]', '@')
        result = result.replace('[at]', '@')
        result = result.replace('(at)', '@')
        result = result.replace('[.]', '.')
        result = result.replace('[dot]', '.')
        result = result.replace('(dot)', '.')
        return result


def detect_ioc_type(value: str) -> str:
    """检测 IOC 类型"""
    value_clean = value.strip()

    # 检测 URL
    if re.match(r'^(https?|hxxps?|ftp|fxp)://', value_clean, re.IGNORECASE):
        return 'url'

    # 检测邮箱
    if '@' in value_clean or '[@]' in value_clean or '[at]' in value_clean:
        return 'email'

    # 检测 IP
    ip_pattern = r'^(\d{1,3}\.|\d{1,3}\[\.\]){3}\d{1,3}$'
    if re.match(ip_pattern, value_clean.replace('[.]', '.')):
        return 'ip'

    # 默认为域名
    if '.' in value_clean or '[.]' in value_clean:
        return 'domain'

    return 'unknown'


def process_ioc(value: str, action: str) -> Dict:
    """处理单个 IOC"""
    ioc_type = detect_ioc_type(value)

    if ioc_type == 'url':
        defanger = URLDefanger()
    elif ioc_type == 'email':
        defanger = EmailDefanger()
    elif ioc_type == 'ip':
        defanger = IPDefanger()
    elif ioc_type == 'domain':
        defanger = DomainDefanger()
    else:
        # 未知类型，使用通用脱敏
        defanger = DomainDefanger()

    if action == 'defang':
        result = defanger.defang(value)
    else:
        result = defanger.refang(value)

    return {
        'original': value,
        'result': result,
        'type': ioc_type,
        'action': action,
    }


def main():
    parser = argparse.ArgumentParser(
        description='IOC 脱敏/还原工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s "https://evil.com/malware.exe"
  %(prog)s -r "hxxps://evil[.]com/malware.exe"
  %(prog)s "192.168.1.1"
  %(prog)s -f iocs.txt -o json
        '''
    )
    parser.add_argument('ioc', nargs='?', help='要处理的 IOC (URL/域名/IP/邮箱)')
    parser.add_argument('-r', '--refang', action='store_true',
                        help='还原模式（默认为脱敏模式）')
    parser.add_argument('-f', '--file', help='从文件读取 IOC 列表')
    parser.add_argument('-o', '--output', choices=['text', 'json'],
                        default='text', help='输出格式')
    parser.add_argument('-t', '--type', choices=['url', 'domain', 'ip', 'email', 'auto'],
                        default='auto', help='IOC 类型（默认自动检测）')

    args = parser.parse_args()

    if not args.ioc and not args.file:
        parser.print_help()
        sys.exit(1)

    action = 'refang' if args.refang else 'defang'

    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            iocs = [line.strip() for line in f if line.strip()]

        results = [process_ioc(ioc, action) for ioc in iocs]

        if args.output == 'json':
            print(json.dumps(results, ensure_ascii=False, indent=2))
        else:
            for result in results:
                print(result['result'])
    else:
        result = process_ioc(args.ioc, action)

        if args.output == 'json':
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(result['result'])


if __name__ == '__main__':
    main()
