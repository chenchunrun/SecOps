#!/usr/bin/env python3
"""
URL 解析工具
解析 URL 各组件，检测编码和特殊模式
"""

import argparse
import json
import re
import sys
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, unquote, unquote_plus


class URLParser:
    """URL 解析器"""

    # 常见协议
    KNOWN_SCHEMES = {
        'http', 'https', 'ftp', 'ftps', 'sftp',
        'mailto', 'tel', 'file', 'data', 'javascript',
    }

    # 可疑协议
    SUSPICIOUS_SCHEMES = {
        'javascript', 'data', 'vbscript',
    }

    def __init__(self):
        pass

    def parse(self, url: str) -> Dict:
        """
        解析 URL

        Args:
            url: URL 字符串

        Returns:
            dict: 解析结果
        """
        result = {
            'original_url': url,
            'valid': False,
            'scheme': None,
            'netloc': None,
            'domain': None,
            'port': None,
            'path': None,
            'query': None,
            'fragment': None,
            'params': {},
            'username': None,
            'password': None,
            'tld': None,
            'subdomain': None,
            'is_ip': False,
            'encoding_issues': [],
            'suspicious_elements': [],
            'decoded_url': None,
        }

        # 处理空 URL
        if not url or not url.strip():
            result['encoding_issues'].append("空 URL")
            return result

        url = url.strip()

        # 检测多重编码
        decoded, encoding_depth = self._detect_encoding(url)
        result['decoded_url'] = decoded
        if encoding_depth > 1:
            result['encoding_issues'].append(f"多重 URL 编码 (深度: {encoding_depth})")

        # 添加默认协议
        parse_url = url
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
            parse_url = 'http://' + url

        try:
            parsed = urlparse(parse_url)
            result['valid'] = True
        except Exception as e:
            result['encoding_issues'].append(f"URL 解析失败: {e}")
            return result

        # 基础组件
        result['scheme'] = parsed.scheme
        result['netloc'] = parsed.netloc
        result['path'] = parsed.path
        result['query'] = parsed.query
        result['fragment'] = parsed.fragment

        # 用户名密码
        if parsed.username:
            result['username'] = parsed.username
            result['suspicious_elements'].append("URL 包含用户名")
        if parsed.password:
            result['password'] = parsed.password
            result['suspicious_elements'].append("URL 包含密码")

        # 解析域名和端口
        domain, port = self._extract_domain_port(parsed.netloc)
        result['domain'] = domain
        result['port'] = port

        # 检测 IP 地址
        if self._is_ip_address(domain):
            result['is_ip'] = True
            result['suspicious_elements'].append("使用 IP 地址而非域名")
        else:
            # 解析 TLD 和子域名
            tld, subdomain = self._extract_tld_subdomain(domain)
            result['tld'] = tld
            result['subdomain'] = subdomain

        # 解析查询参数
        if parsed.query:
            try:
                result['params'] = parse_qs(parsed.query)
            except Exception:
                result['encoding_issues'].append("查询参数解析失败")

        # 检测可疑协议
        if parsed.scheme.lower() in self.SUSPICIOUS_SCHEMES:
            result['suspicious_elements'].append(f"可疑协议: {parsed.scheme}")

        # 检测路径中的可疑元素
        suspicious_path = self._detect_suspicious_path(parsed.path)
        result['suspicious_elements'].extend(suspicious_path)

        # 检测参数中的可疑元素
        suspicious_params = self._detect_suspicious_params(result['params'])
        result['suspicious_elements'].extend(suspicious_params)

        return result

    def _detect_encoding(self, url: str) -> tuple:
        """检测 URL 编码深度"""
        depth = 0
        decoded = url

        while True:
            try:
                new_decoded = unquote(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
                depth += 1
                if depth > 10:  # 防止无限循环
                    break
            except Exception:
                break

        return decoded, depth

    def _extract_domain_port(self, netloc: str) -> tuple:
        """提取域名和端口"""
        # 移除用户信息
        if '@' in netloc:
            netloc = netloc.split('@')[-1]

        domain = netloc
        port = None

        # 处理 IPv6
        if '[' in netloc:
            match = re.match(r'\[([^\]]+)\]:?(\d+)?', netloc)
            if match:
                domain = match.group(1)
                port = int(match.group(2)) if match.group(2) else None
        elif ':' in netloc:
            parts = netloc.rsplit(':', 1)
            domain = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        return domain.lower(), port

    def _is_ip_address(self, domain: str) -> bool:
        """检测是否是 IP 地址"""
        # IPv4
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return True
        # IPv6
        if ':' in domain:
            return True
        return False

    def _extract_tld_subdomain(self, domain: str) -> tuple:
        """提取 TLD 和子域名"""
        if not domain or '.' not in domain:
            return None, None

        parts = domain.split('.')

        # 简单处理：假设最后一个部分是 TLD
        # 对于 .com.cn 等复合 TLD 需要更复杂的处理
        tld = parts[-1]

        # 检测复合 TLD
        if len(parts) >= 2:
            combined = f"{parts[-2]}.{parts[-1]}"
            if combined in ('com.cn', 'net.cn', 'org.cn', 'gov.cn', 'co.uk', 'co.jp', 'com.au'):
                tld = combined
                subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else None
            else:
                subdomain = '.'.join(parts[:-1]) if len(parts) > 1 else None
        else:
            subdomain = None

        return tld, subdomain

    def _detect_suspicious_path(self, path: str) -> List[str]:
        """检测路径中的可疑元素"""
        suspicious = []
        path_lower = path.lower()

        # 检测目录遍历
        if '../' in path or '..\\' in path:
            suspicious.append("路径遍历尝试")

        # 检测可疑扩展名
        suspicious_ext = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta']
        for ext in suspicious_ext:
            if path_lower.endswith(ext):
                suspicious.append(f"可疑文件扩展名: {ext}")
                break

        # 检测敏感路径
        sensitive_paths = ['admin', 'login', 'signin', 'password', 'config', '.env', '.git']
        for sensitive in sensitive_paths:
            if sensitive in path_lower:
                suspicious.append(f"敏感路径关键词: {sensitive}")
                break

        return suspicious

    def _detect_suspicious_params(self, params: Dict) -> List[str]:
        """检测参数中的可疑元素"""
        suspicious = []

        sensitive_param_names = ['password', 'passwd', 'pwd', 'token', 'key', 'secret', 'ssn', 'card']

        for name, values in params.items():
            name_lower = name.lower()

            # 检测敏感参数名
            for sensitive in sensitive_param_names:
                if sensitive in name_lower:
                    suspicious.append(f"敏感参数名: {name}")
                    break

            # 检测参数值中的可疑内容
            for value in values:
                if '<script' in value.lower():
                    suspicious.append("参数值包含脚本标签")
                if 'javascript:' in value.lower():
                    suspicious.append("参数值包含 JavaScript 协议")

        return suspicious


def format_result(result: Dict, output_format: str = 'text') -> str:
    """格式化输出"""
    if output_format == 'json':
        return json.dumps(result, ensure_ascii=False, indent=2)

    lines = []
    lines.append("=" * 50)
    lines.append("URL 解析结果")
    lines.append("=" * 50)
    lines.append("")

    lines.append(f"原始 URL: {result['original_url']}")
    if result['decoded_url'] != result['original_url']:
        lines.append(f"解码 URL: {result['decoded_url']}")

    lines.append("")
    lines.append("【组件解析】")
    lines.append(f"  协议: {result['scheme']}")
    lines.append(f"  域名: {result['domain']}")
    if result['port']:
        lines.append(f"  端口: {result['port']}")
    if result['path']:
        lines.append(f"  路径: {result['path']}")
    if result['query']:
        lines.append(f"  查询: {result['query']}")
    if result['fragment']:
        lines.append(f"  锚点: {result['fragment']}")

    if result['is_ip']:
        lines.append(f"  类型: IP 地址")
    else:
        if result['tld']:
            lines.append(f"  TLD: .{result['tld']}")
        if result['subdomain']:
            lines.append(f"  子域名: {result['subdomain']}")

    if result['params']:
        lines.append("")
        lines.append("【查询参数】")
        for name, values in result['params'].items():
            for value in values:
                lines.append(f"  {name} = {value[:50]}{'...' if len(value) > 50 else ''}")

    if result['encoding_issues']:
        lines.append("")
        lines.append("【编码问题】")
        for issue in result['encoding_issues']:
            lines.append(f"  - {issue}")

    if result['suspicious_elements']:
        lines.append("")
        lines.append("【可疑元素】")
        for element in result['suspicious_elements']:
            lines.append(f"  - {element}")

    lines.append("")
    lines.append("=" * 50)

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='URL 解析工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s "https://example.com/path?query=1"
  %(prog)s "http://user:pass@example.com:8080/admin"
  %(prog)s -f urls.txt -o json
        '''
    )
    parser.add_argument('url', nargs='?', help='要解析的 URL')
    parser.add_argument('-f', '--file', help='从文件读取 URL 列表')
    parser.add_argument('-o', '--output', choices=['text', 'json'],
                        default='text', help='输出格式')

    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    url_parser = URLParser()

    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip()]

        results = [url_parser.parse(url) for url in urls]

        if args.output == 'json':
            print(json.dumps(results, ensure_ascii=False, indent=2))
        else:
            for result in results:
                print(format_result(result, args.output))
                print()
    else:
        result = url_parser.parse(args.url)
        print(format_result(result, args.output))

        if result['suspicious_elements']:
            sys.exit(1)


if __name__ == '__main__':
    main()
