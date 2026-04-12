#!/usr/bin/env python3
"""
域名验证和分类工具
支持 IDN/Punycode 处理、TLD 提取、域名分类
"""

import argparse
import json
import re
import sys
from typing import Dict, Optional, Tuple


class DomainValidator:
    """域名验证和分类"""

    # 高风险 TLD
    HIGH_RISK_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq',  # 免费域名
        'xyz', 'top', 'work', 'click', 'link',  # 低价域名
        'info', 'biz', 'cc', 'pw', 'ws',  # 常被滥用
    }

    # 动态 DNS 服务商域名
    DYNAMIC_DNS_DOMAINS = {
        'dyndns.org', 'no-ip.com', 'no-ip.org', 'ddns.net',
        'hopto.org', 'zapto.org', 'sytes.net', 'ddns.info',
        'duckdns.org', 'freedns.afraid.org', 'dynu.com',
    }

    # 域名正则
    DOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )

    # Punycode 前缀
    PUNYCODE_PREFIX = 'xn--'

    def __init__(self):
        pass

    def validate(self, domain: str) -> Dict:
        """
        验证域名并返回分类信息

        Args:
            domain: 域名字符串

        Returns:
            dict: 验证结果
        """
        result = {
            'input': domain,
            'valid': False,
            'normalized': None,
            'is_idn': False,
            'punycode': None,
            'unicode': None,
            'tld': None,
            'sld': None,  # 二级域名
            'subdomain': None,
            'is_subdomain': False,
            'domain_type': None,
            'risk_level': 'unknown',
            'risk_factors': [],
            'error': None,
        }

        # 清理输入
        domain = domain.strip().lower()

        # 移除协议前缀
        if '://' in domain:
            domain = domain.split('://')[1]

        # 移除路径
        if '/' in domain:
            domain = domain.split('/')[0]

        # 移除端口
        if ':' in domain:
            domain = domain.split(':')[0]

        result['normalized'] = domain

        # 检查 Punycode
        if self.PUNYCODE_PREFIX in domain:
            result['is_idn'] = True
            result['punycode'] = domain
            try:
                result['unicode'] = domain.encode('ascii').decode('idna')
            except Exception as e:
                result['error'] = f"Punycode 解码失败: {e}"
                return result
        elif any(ord(c) > 127 for c in domain):
            # Unicode 域名
            result['is_idn'] = True
            result['unicode'] = domain
            try:
                result['punycode'] = domain.encode('idna').decode('ascii')
            except Exception as e:
                result['error'] = f"IDN 编码失败: {e}"
                return result

        # 验证格式
        check_domain = result['punycode'] if result['punycode'] else domain
        if not self._is_valid_format(check_domain):
            result['error'] = "域名格式无效"
            return result

        result['valid'] = True

        # 提取 TLD 和 SLD
        parts = domain.split('.')
        if len(parts) >= 2:
            result['tld'] = parts[-1]
            result['sld'] = parts[-2]

            if len(parts) > 2:
                result['subdomain'] = '.'.join(parts[:-2])
                result['is_subdomain'] = True

        # 分类
        result['domain_type'] = self._classify_domain(domain, result)

        # 风险评估
        result['risk_level'], result['risk_factors'] = self._assess_risk(result)

        return result

    def _is_valid_format(self, domain: str) -> bool:
        """检查域名格式是否有效"""
        if not domain or len(domain) > 253:
            return False

        # 检查每个标签
        labels = domain.split('.')
        if len(labels) < 2:
            return False

        for label in labels:
            if not label or len(label) > 63:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
            if not re.match(r'^[a-zA-Z0-9-]+$', label):
                return False

        return True

    def _classify_domain(self, domain: str, result: Dict) -> str:
        """域名分类"""
        # 检查是否是动态 DNS
        for ddns in self.DYNAMIC_DNS_DOMAINS:
            if domain.endswith('.' + ddns) or domain == ddns:
                return 'dynamic_dns'

        # 检查是否是 IP 地址（虽然不是域名，但可能被错误输入）
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return 'ip_address'

        # 检查 TLD 类型
        tld = result.get('tld', '')
        if tld in ('gov', 'edu', 'mil'):
            return 'government_education'
        elif tld in self.HIGH_RISK_TLDS:
            return 'high_risk_tld'
        elif result['is_subdomain']:
            return 'subdomain'
        else:
            return 'standard'

    def _assess_risk(self, result: Dict) -> Tuple[str, list]:
        """风险评估"""
        risk_factors = []
        score = 0

        tld = result.get('tld', '')
        domain_type = result.get('domain_type', '')

        # TLD 风险
        if tld in self.HIGH_RISK_TLDS:
            risk_factors.append(f"高风险 TLD: .{tld}")
            score += 15

        # 动态 DNS
        if domain_type == 'dynamic_dns':
            risk_factors.append("动态 DNS 服务域名")
            score += 20

        # IDN 域名
        if result.get('is_idn'):
            risk_factors.append("国际化域名 (IDN) - 可能存在同形字攻击")
            score += 10

        # 域名长度异常
        domain = result.get('normalized', '')
        if len(domain) > 50:
            risk_factors.append(f"域名过长: {len(domain)} 字符")
            score += 5

        # 计算等级
        if score >= 30:
            level = 'high'
        elif score >= 15:
            level = 'medium'
        else:
            level = 'low'

        return level, risk_factors

    # 常见的双后缀 TLD（公共后缀列表简化版）
    MULTI_PART_TLDS = {
        # 中国
        'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
        # 英国
        'co.uk', 'org.uk', 'me.uk', 'gov.uk', 'ac.uk',
        # 日本
        'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
        # 澳大利亚
        'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
        # 其他常见
        'com.hk', 'org.hk', 'edu.hk', 'gov.hk',
        'com.tw', 'org.tw', 'edu.tw', 'gov.tw',
        'com.sg', 'org.sg', 'edu.sg', 'gov.sg',
        'co.kr', 'or.kr', 'go.kr',
        'com.br', 'org.br', 'gov.br',
        'co.nz', 'org.nz', 'govt.nz',
        'co.in', 'org.in', 'gov.in',
        'com.ru', 'org.ru',
        'com.mx', 'org.mx', 'gob.mx',
    }

    def extract_registered_domain(self, domain: str) -> str:
        """
        提取注册域名（用于 ICP 备案查询等场景）

        正确处理双后缀 TLD：
        - sub.example.com     → example.com
        - sub.example.com.cn  → example.com.cn
        - sub.example.co.uk   → example.co.uk

        Args:
            domain: 完整域名（可包含子域名）

        Returns:
            注册域名（主域名）
        """
        # 先验证和标准化
        result = self.validate(domain)
        if not result['valid']:
            return domain

        domain = result['normalized']
        parts = domain.split('.')

        if len(parts) < 2:
            return domain

        # 尝试使用 tld 库（如果安装）
        try:
            from tld import get_tld
            tld_result = get_tld(f"http://{domain}", as_object=True, fail_silently=True)
            if tld_result:
                return tld_result.fld  # First Level Domain = 注册域名
        except ImportError:
            pass

        # 回退到手动检测双后缀 TLD
        if len(parts) >= 3:
            potential_tld = f"{parts[-2]}.{parts[-1]}"
            if potential_tld in self.MULTI_PART_TLDS:
                # 双后缀 TLD，取最后三部分
                return '.'.join(parts[-3:])

        # 普通 TLD，取最后两部分
        return '.'.join(parts[-2:])

    def extract_main_domain(self, domain: str) -> str:
        """提取主域名（别名，兼容旧代码）"""
        return self.extract_registered_domain(domain)


def format_result(result: Dict, output_format: str = 'text') -> str:
    """格式化输出结果"""
    if output_format == 'json':
        return json.dumps(result, ensure_ascii=False, indent=2)

    lines = []
    lines.append(f"域名: {result['input']}")

    if not result['valid']:
        lines.append(f"状态: 无效 - {result['error']}")
        return '\n'.join(lines)

    lines.append(f"状态: 有效")

    if result['normalized'] != result['input']:
        lines.append(f"标准化: {result['normalized']}")

    if result['is_idn']:
        lines.append(f"IDN 域名: 是")
        if result['unicode']:
            lines.append(f"  Unicode: {result['unicode']}")
        if result['punycode']:
            lines.append(f"  Punycode: {result['punycode']}")

    lines.append(f"TLD: .{result['tld']}")
    lines.append(f"SLD: {result['sld']}")

    if result['is_subdomain']:
        lines.append(f"子域名: {result['subdomain']}")

    lines.append(f"类型: {result['domain_type']}")
    lines.append(f"风险等级: {result['risk_level']}")

    if result['risk_factors']:
        lines.append("风险因素:")
        for factor in result['risk_factors']:
            lines.append(f"  - {factor}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='域名验证和分类工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s example.com
  %(prog)s xn--pple-43d.com
  %(prog)s sub.example.com
  %(prog)s -f domains.txt -o json
        '''
    )
    parser.add_argument('domain', nargs='?', help='要验证的域名')
    parser.add_argument('-f', '--file', help='从文件读取域名列表')
    parser.add_argument('-o', '--output', choices=['text', 'json'],
                        default='text', help='输出格式')
    parser.add_argument('--main-domain', action='store_true',
                        help='只输出主域名')

    args = parser.parse_args()

    if not args.domain and not args.file:
        parser.print_help()
        sys.exit(1)

    validator = DomainValidator()

    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            domains = [line.strip() for line in f if line.strip()]

        results = []
        for domain in domains:
            if args.main_domain:
                print(validator.extract_main_domain(domain))
            else:
                result = validator.validate(domain)
                results.append(result)

        if not args.main_domain:
            if args.output == 'json':
                print(json.dumps(results, ensure_ascii=False, indent=2))
            else:
                for result in results:
                    print(format_result(result, args.output))
                    print('-' * 40)
    else:
        if args.main_domain:
            print(validator.extract_main_domain(args.domain))
        else:
            result = validator.validate(args.domain)
            print(format_result(result, args.output))

            sys.exit(0 if result['valid'] else 1)


if __name__ == '__main__':
    main()
