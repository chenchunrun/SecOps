#!/usr/bin/env python3
"""
DNS 记录查询工具
查询域名的各类 DNS 记录

优化：并行查询 + 快速超时，确保 10 秒内返回结果
"""

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import Dict, List, Optional


class DNSLookup:
    """DNS 记录查询"""

    # 记录类型
    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    PUBLIC_NAMESERVERS = [
        '223.5.5.5',        # 阿里 DNS (Primary)
        '223.6.6.6',        # 阿里 DNS (Secondary)
        '119.29.29.29',     # 腾讯 DNS (DNSPod)
        '114.114.114.114',  # 114 DNS (中国)
        '180.76.76.76',     # 百度 DNS
        '1.1.1.1',          # Cloudflare DNS (Primary)
        '1.0.0.1',          # Cloudflare DNS (Secondary)
        '8.8.8.8',          # Google Public DNS (Primary)
        '8.8.4.4',          # Google Public DNS (Secondary)
    ]

    def __init__(self, timeout: int = 2, max_workers: int = 7):
        """
        初始化 DNS 查询器

        Args:
            timeout: 单次查询超时（秒），默认 2s
            max_workers: 并行查询线程数，默认 7（对应 7 种记录类型）
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self._dns_resolver = None
        self._resolver_mode = 'socket'
        self._init_resolver()

    def _build_public_resolver(self):
        """构建公共 DNS 解析器"""
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = self.PUBLIC_NAMESERVERS
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        return resolver

    def _init_resolver(self):
        """优先初始化系统 DNS，异常时回退到公共 DNS"""
        try:
            import dns.resolver
        except ImportError:
            self._dns_resolver = None
            self._resolver_mode = 'socket'
            return

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            self._dns_resolver = resolver
            self._resolver_mode = 'system'
            return
        except Exception:
            pass

        try:
            self._dns_resolver = self._build_public_resolver()
            self._resolver_mode = 'public'
        except Exception:
            self._dns_resolver = None
            self._resolver_mode = 'socket'

    def lookup(self, domain: str, record_types: List[str] = None) -> Dict:
        """
        并行查询 DNS 记录

        Args:
            domain: 域名
            record_types: 要查询的记录类型列表

        Returns:
            dict: 查询结果
        """
        if record_types is None:
            record_types = self.RECORD_TYPES

        result = {
            'domain': domain,
            'success': False,
            'resolver': self._resolver_mode if self._dns_resolver else 'socket',
            'records': {},
            'errors': [],
        }

        def query_single(rtype: str):
            """单个记录类型查询"""
            try:
                records = self._query(domain, rtype)
                return rtype, records, None
            except Exception as e:
                return rtype, None, str(e)

        # 并行查询所有记录类型
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(query_single, rtype): rtype for rtype in record_types}

            # 总超时按记录类型数量放宽，避免部分慢查询拖垮整次查询
            total_timeout = max(self.timeout + 1, min(len(record_types) * self.timeout, 10))
            pending_futures = set(futures)

            try:
                for future in as_completed(futures, timeout=total_timeout):
                    pending_futures.discard(future)
                    try:
                        rtype, records, error = future.result(timeout=1)
                        if error:
                            result['errors'].append(f"{rtype}: {error}")
                        elif records:
                            result['records'][rtype] = records
                            result['success'] = True
                    except Exception:
                        rtype = futures[future]
                        result['errors'].append(f"{rtype}: timeout")
            except TimeoutError:
                pass

            for future in pending_futures:
                future.cancel()
                rtype = futures[future]
                result['errors'].append(f"{rtype}: timeout")

        return result

    def _query(self, domain: str, rtype: str) -> List[str]:
        """执行 DNS 查询"""
        if self._dns_resolver:
            return self._query_dnspython(domain, rtype)
        else:
            return self._query_socket(domain, rtype)

    def _query_dnspython(self, domain: str, rtype: str) -> List[str]:
        """使用 dnspython 查询"""
        import dns.exception
        import dns.resolver
        import dns.rdatatype

        resolvers = []
        if self._dns_resolver:
            resolvers.append((self._resolver_mode, self._dns_resolver))
        if self._resolver_mode != 'public':
            try:
                resolvers.append(('public', self._build_public_resolver()))
            except Exception:
                pass

        last_exception = None
        for mode, resolver in resolvers:
            try:
                answers = resolver.resolve(domain, rtype)
                results = []

                for rdata in answers:
                    if rtype == 'MX':
                        results.append(f"{rdata.preference} {rdata.exchange}")
                    elif rtype == 'SOA':
                        results.append(
                            f"{rdata.mname} {rdata.rname} "
                            f"{rdata.serial} {rdata.refresh} "
                            f"{rdata.retry} {rdata.expire} {rdata.minimum}"
                        )
                    else:
                        results.append(str(rdata))

                if mode != self._resolver_mode:
                    self._dns_resolver = resolver
                    self._resolver_mode = mode
                return results
            except dns.resolver.NXDOMAIN:
                return []
            except dns.resolver.NoAnswer:
                return []
            except dns.resolver.NoNameservers:
                last_exception = dns.resolver.NoNameservers()
            except dns.exception.Timeout as e:
                last_exception = e
            except Exception as e:
                last_exception = e

        raise last_exception if last_exception else RuntimeError('DNS query failed')

    def _query_socket(self, domain: str, rtype: str) -> List[str]:
        """使用 socket 基础查询（仅支持 A 记录）"""
        if rtype == 'A':
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                return ips
            except socket.gaierror:
                return []
        elif rtype == 'AAAA':
            try:
                infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
                return list(set(info[4][0] for info in infos))
            except socket.gaierror:
                return []
        else:
            # 其他类型需要 dnspython
            return []

    def check_spf(self, domain: str) -> Dict:
        """检查 SPF 记录"""
        result = {
            'has_spf': False,
            'spf_record': None,
            'spf_valid': False,
            'issues': [],
        }

        try:
            txt_records = self._query(domain, 'TXT')
            for record in txt_records:
                if record.startswith('"v=spf1') or record.startswith('v=spf1'):
                    result['has_spf'] = True
                    result['spf_record'] = record.strip('"')

                    # 简单验证
                    if 'all' in record:
                        result['spf_valid'] = True
                    if '-all' in record:
                        result['issues'].append('严格 SPF (推荐)')
                    elif '~all' in record:
                        result['issues'].append('软失败 SPF')
                    elif '+all' in record:
                        result['issues'].append('[!] 过于宽松的 SPF (+all)')
                    break
        except Exception:
            pass

        return result

    def check_dmarc(self, domain: str) -> Dict:
        """检查 DMARC 记录"""
        result = {
            'has_dmarc': False,
            'dmarc_record': None,
            'policy': None,
        }

        dmarc_domain = f"_dmarc.{domain}"
        try:
            txt_records = self._query(dmarc_domain, 'TXT')
            for record in txt_records:
                if 'v=DMARC1' in record:
                    result['has_dmarc'] = True
                    result['dmarc_record'] = record.strip('"')

                    # 提取策略
                    if 'p=reject' in record:
                        result['policy'] = 'reject'
                    elif 'p=quarantine' in record:
                        result['policy'] = 'quarantine'
                    elif 'p=none' in record:
                        result['policy'] = 'none'
                    break
        except Exception:
            pass

        return result


def format_result(result: Dict, output_format: str = 'text') -> str:
    """格式化输出结果"""
    if output_format == 'json':
        return json.dumps(result, ensure_ascii=False, indent=2)

    lines = []
    lines.append(f"域名: {result['domain']}")
    lines.append(f"解析器: {result['resolver']}")
    lines.append("")

    if not result['success'] and not result['records']:
        lines.append("未找到 DNS 记录")
        if result['errors']:
            for error in result['errors']:
                lines.append(f"  错误: {error}")
        return '\n'.join(lines)

    # DNS 记录
    for rtype, records in result['records'].items():
        lines.append(f"【{rtype} 记录】")
        for record in records:
            lines.append(f"  {record}")
        lines.append("")

    # 错误
    if result['errors']:
        lines.append("【查询错误】")
        for error in result['errors']:
            lines.append(f"  {error}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='DNS 记录查询工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s example.com
  %(prog)s example.com -t A AAAA MX
  %(prog)s example.com --all
  %(prog)s example.com --check-email
        '''
    )
    parser.add_argument('domain', help='要查询的域名')
    parser.add_argument('-t', '--types', nargs='+',
                        choices=['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'],
                        help='要查询的记录类型')
    parser.add_argument('--all', action='store_true',
                        help='查询所有类型的记录')
    parser.add_argument('--check-email', action='store_true',
                        help='检查邮件安全配置 (SPF/DMARC)')
    parser.add_argument('-o', '--output', choices=['text', 'json'],
                        default='text', help='输出格式')
    parser.add_argument('--timeout', type=int, default=2,
                        help='单次查询超时时间（秒），默认 2s')

    args = parser.parse_args()

    lookup = DNSLookup(timeout=args.timeout)

    if args.check_email:
        # 邮件安全检查
        spf = lookup.check_spf(args.domain)
        dmarc = lookup.check_dmarc(args.domain)

        result = {
            'domain': args.domain,
            'spf': spf,
            'dmarc': dmarc,
        }

        if args.output == 'json':
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(f"域名: {args.domain}")
            print("")
            print("【SPF 检查】")
            print(f"  配置: {'是' if spf['has_spf'] else '否'}")
            if spf['spf_record']:
                print(f"  记录: {spf['spf_record']}")
            if spf['issues']:
                for issue in spf['issues']:
                    print(f"  {issue}")
            print("")
            print("【DMARC 检查】")
            print(f"  配置: {'是' if dmarc['has_dmarc'] else '否'}")
            if dmarc['dmarc_record']:
                print(f"  记录: {dmarc['dmarc_record']}")
                print(f"  策略: {dmarc['policy']}")
    else:
        # DNS 记录查询
        if args.all:
            record_types = DNSLookup.RECORD_TYPES
        elif args.types:
            record_types = args.types
        else:
            record_types = ['A', 'AAAA', 'MX', 'NS']

        result = lookup.lookup(args.domain, record_types)
        print(format_result(result, args.output))

        sys.exit(0 if result['success'] else 1)


if __name__ == '__main__':
    main()
