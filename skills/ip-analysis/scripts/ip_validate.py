#!/usr/bin/env python3
"""
IP 地址验证和分类工具
支持 IPv4/IPv6 验证、类型分类、CIDR 解析
"""

import argparse
import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Optional


class IPValidator:
    """IP 地址验证和分类"""

    # 特殊用途 IP 范围
    SPECIAL_RANGES = {
        'private': [
            ('10.0.0.0/8', 'RFC 1918 - 私有网络'),
            ('172.16.0.0/12', 'RFC 1918 - 私有网络'),
            ('192.168.0.0/16', 'RFC 1918 - 私有网络'),
        ],
        'loopback': [
            ('127.0.0.0/8', 'RFC 1122 - 环回地址'),
        ],
        'link_local': [
            ('169.254.0.0/16', 'RFC 3927 - 链路本地'),
        ],
        'multicast': [
            ('224.0.0.0/4', 'RFC 5771 - 组播地址'),
        ],
        'reserved': [
            ('0.0.0.0/8', 'RFC 1122 - 本网络'),
            ('100.64.0.0/10', 'RFC 6598 - 共享地址空间 (CGNAT)'),
            ('192.0.0.0/24', 'RFC 6890 - IETF 协议分配'),
            ('192.0.2.0/24', 'RFC 5737 - 文档示例'),
            ('198.51.100.0/24', 'RFC 5737 - 文档示例'),
            ('203.0.113.0/24', 'RFC 5737 - 文档示例'),
            ('240.0.0.0/4', 'RFC 1112 - 保留地址'),
            ('255.255.255.255/32', 'RFC 919 - 广播地址'),
        ],
        'carrier_grade_nat': [
            ('100.64.0.0/10', 'RFC 6598 - 运营商级 NAT'),
        ],
    }

    def __init__(self):
        pass

    def validate(self, ip_str: str) -> dict:
        """
        验证 IP 地址并返回分类信息

        Args:
            ip_str: IP 地址字符串

        Returns:
            dict: 验证结果
        """
        result = {
            'input': ip_str,
            'valid': False,
            'version': None,
            'type': None,
            'type_detail': None,
            'is_public': False,
            'normalized': None,
            'network': None,
            'error': None,
        }

        try:
            # 尝试解析为 IP 地址或网络
            if '/' in ip_str:
                # CIDR 网段
                network = ipaddress.ip_network(ip_str, strict=False)
                ip = network.network_address
                result['network'] = str(network)
                result['network_size'] = network.num_addresses
            else:
                # 单个 IP
                ip = ipaddress.ip_address(ip_str)

            result['valid'] = True
            result['version'] = ip.version
            result['normalized'] = str(ip)

            # 分类
            if ip.is_private:
                result['type'] = 'private'
                result['type_detail'] = self._get_private_detail(ip)
                result['is_public'] = False
            elif ip.is_loopback:
                result['type'] = 'loopback'
                result['type_detail'] = '环回地址'
                result['is_public'] = False
            elif ip.is_multicast:
                result['type'] = 'multicast'
                result['type_detail'] = '组播地址'
                result['is_public'] = False
            elif ip.is_reserved:
                result['type'] = 'reserved'
                result['type_detail'] = '保留地址'
                result['is_public'] = False
            elif ip.is_link_local:
                result['type'] = 'link_local'
                result['type_detail'] = '链路本地地址'
                result['is_public'] = False
            elif ip.is_unspecified:
                result['type'] = 'unspecified'
                result['type_detail'] = '未指定地址'
                result['is_public'] = False
            else:
                result['type'] = 'public'
                result['type_detail'] = '公网地址'
                result['is_public'] = True

            # 检查是否是 CGNAT
            if ip.version == 4:
                cgnat = ipaddress.ip_network('100.64.0.0/10')
                if ip in cgnat:
                    result['type'] = 'cgnat'
                    result['type_detail'] = '运营商级 NAT 地址 (RFC 6598)'
                    result['is_public'] = False

        except ValueError as e:
            result['error'] = str(e)

        return result

    def _get_private_detail(self, ip) -> str:
        """获取私有地址的详细分类"""
        if ip.version == 4:
            if ip in ipaddress.ip_network('10.0.0.0/8'):
                return 'A 类私有网络 (10.0.0.0/8)'
            elif ip in ipaddress.ip_network('172.16.0.0/12'):
                return 'B 类私有网络 (172.16.0.0/12)'
            elif ip in ipaddress.ip_network('192.168.0.0/16'):
                return 'C 类私有网络 (192.168.0.0/16)'
        return '私有网络'

    def batch_validate(self, ip_list: list) -> list:
        """批量验证 IP 地址"""
        return [self.validate(ip) for ip in ip_list]

    def reverse_dns(self, ip_str: str, timeout: int = 3) -> Optional[str]:
        """
        查询 IP 的 PTR 反向解析记录

        Args:
            ip_str: IP 地址
            timeout: 超时时间（秒）

        Returns:
            PTR 主机名或 None
        """
        def do_lookup():
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            return hostname

        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(do_lookup)
                return future.result(timeout=timeout)
        except (socket.herror, FuturesTimeoutError, OSError):
            return None


def format_result(result: dict, output_format: str = 'text') -> str:
    """格式化输出结果"""
    if output_format == 'json':
        return json.dumps(result, ensure_ascii=False, indent=2)

    # 文本格式
    lines = []
    lines.append(f"IP: {result['input']}")

    if not result['valid']:
        lines.append(f"状态: 无效 - {result['error']}")
        return '\n'.join(lines)

    lines.append(f"状态: 有效")
    lines.append(f"版本: IPv{result['version']}")
    lines.append(f"类型: {result['type']} ({result['type_detail']})")
    lines.append(f"公网: {'是' if result['is_public'] else '否'}")

    if result['normalized'] != result['input']:
        lines.append(f"标准化: {result['normalized']}")

    if result.get('network'):
        lines.append(f"网段: {result['network']} ({result['network_size']} 个地址)")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='IP 地址验证和分类工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s 192.168.1.1
  %(prog)s 8.8.8.8 -o json
  %(prog)s 10.0.0.0/8
  %(prog)s -f ip_list.txt
        '''
    )
    parser.add_argument('ip', nargs='?', help='要验证的 IP 地址')
    parser.add_argument('-f', '--file', help='从文件读取 IP 列表')
    parser.add_argument('-o', '--output', choices=['text', 'json'],
                        default='text', help='输出格式')

    args = parser.parse_args()

    if not args.ip and not args.file:
        parser.print_help()
        sys.exit(1)

    validator = IPValidator()

    if args.file:
        # 批量处理
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            ips = [line.strip() for line in f if line.strip()]
        results = validator.batch_validate(ips)

        if args.output == 'json':
            print(json.dumps(results, ensure_ascii=False, indent=2))
        else:
            for result in results:
                print(format_result(result, args.output))
                print('-' * 40)
    else:
        # 单个 IP
        result = validator.validate(args.ip)
        print(format_result(result, args.output))

        # PTR 查询（公网 IP 默认查询）
        if result['valid'] and result['is_public']:
            print("")
            ptr = validator.reverse_dns(args.ip)
            if ptr:
                print(f"PTR: {ptr}")
            else:
                print("PTR: 无")

        # 返回码: 0=公网, 1=非公网, 2=无效
        if not result['valid']:
            sys.exit(2)
        elif not result['is_public']:
            sys.exit(1)
        else:
            sys.exit(0)


if __name__ == '__main__':
    main()
