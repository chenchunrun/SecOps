#!/usr/bin/env python3
"""
同形字攻击检测工具
检测域名中的 IDN 同形字攻击
"""

import argparse
import json
import sys
import unicodedata
from typing import Dict, List, Tuple, Optional

# 常见同形字映射表
CONFUSABLES = {
    # 西里尔字母
    'а': 'a', 'А': 'A',
    'с': 'c', 'С': 'C',
    'е': 'e', 'Е': 'E',
    'о': 'o', 'О': 'O',
    'р': 'p', 'Р': 'P',
    'х': 'x', 'Х': 'X',
    'у': 'y', 'У': 'Y',
    'і': 'i', 'І': 'I',
    'В': 'B',
    'Н': 'H',
    'К': 'K',
    'М': 'M',
    'Т': 'T',
    'ё': 'e',

    # 希腊字母
    'Α': 'A', 'α': 'a',
    'Β': 'B', 'β': 'b',
    'Ε': 'E', 'ε': 'e',
    'Η': 'H',
    'Ι': 'I', 'ι': 'i',
    'Κ': 'K', 'κ': 'k',
    'Μ': 'M',
    'Ν': 'N', 'ν': 'v',
    'Ο': 'O', 'ο': 'o',
    'Ρ': 'P', 'ρ': 'p',
    'Τ': 'T', 'τ': 't',
    'Χ': 'X', 'χ': 'x',
    'Υ': 'Y', 'υ': 'u',
    'Ζ': 'Z',

    # 数字替换
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '8': 'b',
    '9': 'g',

    # 拉丁扩展
    'ɑ': 'a',
    'ı': 'i',
    'ǐ': 'i',
    'ñ': 'n',
    'ø': 'o',

    # 特殊符号
    '−': '-',
    '‐': '-',
    '⁃': '-',
    '․': '.',
    '。': '.',
    '∕': '/',
}


def get_script(char: str) -> str:
    """获取字符的脚本类型"""
    try:
        name = unicodedata.name(char, '')
        if not name:
            return 'UNKNOWN'

        # 从 Unicode 名称中提取脚本
        if 'CYRILLIC' in name:
            return 'CYRILLIC'
        elif 'GREEK' in name:
            return 'GREEK'
        elif 'LATIN' in name:
            return 'LATIN'
        elif 'CJK' in name:
            return 'CJK'
        elif 'DIGIT' in name or char.isdigit():
            return 'DIGIT'
        else:
            return name.split()[0]
    except:
        return 'UNKNOWN'


def detect_homograph(domain: str) -> Dict:
    """检测域名中的同形字"""
    suspicious_chars = []
    normalized = ""
    scripts = set()

    for i, char in enumerate(domain):
        if char in CONFUSABLES:
            suspicious_chars.append({
                'position': i,
                'char': char,
                'unicode': f"U+{ord(char):04X}",
                'looks_like': CONFUSABLES[char],
                'script': get_script(char)
            })
            normalized += CONFUSABLES[char]
        else:
            normalized += char

        if char.isalpha():
            scripts.add(get_script(char))

    # 判断是否为混合脚本攻击
    is_mixed = len(scripts) > 1 and 'LATIN' in scripts

    # 计算相似度
    original_lower = domain.lower()
    normalized_lower = normalized.lower()

    if original_lower == normalized_lower:
        similarity = 100
    else:
        # 简单的相似度计算
        matches = sum(1 for a, b in zip(original_lower, normalized_lower) if a == b)
        similarity = int(matches / len(domain) * 100)

    return {
        'original': domain,
        'normalized': normalized,
        'is_homograph': len(suspicious_chars) > 0,
        'is_mixed_script': is_mixed,
        'scripts': list(scripts),
        'suspicious_chars': suspicious_chars,
        'similarity': similarity,
        'risk_level': calculate_risk(suspicious_chars, is_mixed)
    }


def calculate_risk(suspicious_chars: List, is_mixed: bool) -> str:
    """计算风险等级"""
    if not suspicious_chars:
        return 'safe'

    count = len(suspicious_chars)

    if is_mixed and count >= 2:
        return 'high'
    elif is_mixed or count >= 3:
        return 'high'
    elif count >= 1:
        return 'medium'
    else:
        return 'low'


def to_punycode(domain: str) -> str:
    """转换为 Punycode"""
    try:
        return domain.encode('idna').decode('ascii')
    except:
        return domain


def from_punycode(domain: str) -> str:
    """从 Punycode 解码"""
    try:
        return domain.encode('ascii').decode('idna')
    except:
        return domain


def check_brand(domain: str, brands: List[str]) -> Optional[Dict]:
    """检查是否仿冒已知品牌"""
    result = detect_homograph(domain)
    normalized = result['normalized'].lower()

    for brand in brands:
        brand_lower = brand.lower()

        # 精确匹配
        if normalized == brand_lower or normalized.startswith(brand_lower + '.'):
            return {
                'matched_brand': brand,
                'match_type': 'exact',
                'domain': domain,
                **result
            }

        # 包含匹配
        if brand_lower in normalized:
            return {
                'matched_brand': brand,
                'match_type': 'contains',
                'domain': domain,
                **result
            }

    return None


def main():
    parser = argparse.ArgumentParser(description='同形字攻击检测工具')
    parser.add_argument('domain', nargs='?', help='要检测的域名')
    parser.add_argument('-f', '--file', help='从文件读取域名列表')
    parser.add_argument('-b', '--brands', help='品牌列表文件')
    parser.add_argument('--brand-check', action='store_true', help='启用品牌检测')
    parser.add_argument('-o', '--output', help='输出文件 (JSON)')
    parser.add_argument('--punycode', action='store_true', help='显示 Punycode 编码')

    args = parser.parse_args()

    # 默认品牌列表
    default_brands = [
        'apple', 'google', 'microsoft', 'amazon', 'facebook', 'meta',
        'paypal', 'netflix', 'twitter', 'instagram', 'linkedin',
        'alibaba', 'tencent', 'baidu', 'jd', 'taobao', 'alipay',
        'bank', 'chase', 'wellsfargo', 'citibank', 'hsbc'
    ]

    brands = default_brands
    if args.brands:
        with open(args.brands, 'r', encoding='utf-8', errors='ignore') as f:
            brands = [line.strip() for line in f if line.strip()]

    domains = []
    if args.domain:
        domains = [args.domain]
    elif args.file:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        parser.print_help()
        sys.exit(1)

    results = []

    for domain in domains:
        if args.brand_check:
            result = check_brand(domain, brands)
            if result:
                results.append(result)
                print_result(result, args.punycode)
            else:
                result = detect_homograph(domain)
                results.append(result)
                print_result(result, args.punycode)
        else:
            result = detect_homograph(domain)
            results.append(result)
            print_result(result, args.punycode)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n[+] 结果已保存到: {args.output}")


def print_result(result: Dict, show_punycode: bool = False):
    """打印检测结果"""
    domain = result['original']
    risk = result.get('risk_level', 'unknown')

    # 风险等级颜色
    risk_colors = {
        'high': '\033[91m',    # 红色
        'medium': '\033[93m',  # 黄色
        'low': '\033[92m',     # 绿色
        'safe': '\033[92m'     # 绿色
    }
    reset = '\033[0m'

    color = risk_colors.get(risk, '')

    print(f"\n{'='*50}")
    print(f"域名: {domain}")

    if show_punycode:
        punycode = to_punycode(domain)
        if punycode != domain:
            print(f"Punycode: {punycode}")

    print(f"标准化: {result['normalized']}")
    print(f"风险等级: {color}{risk.upper()}{reset}")

    if result.get('matched_brand'):
        print(f"仿冒品牌: {result['matched_brand']} ({result['match_type']})")

    if result['is_homograph']:
        print(f"同形字攻击: [+] 检测到")
        print(f"混合脚本: {'[+]' if result['is_mixed_script'] else '[-]'}")
        print(f"脚本类型: {', '.join(result['scripts'])}")

        print("\n可疑字符:")
        for char in result['suspicious_chars']:
            print(f"  位置 {char['position']}: '{char['char']}' ({char['unicode']}) "
                  f"-> '{char['looks_like']}' [{char['script']}]")
    else:
        print(f"同形字攻击: [-] 未检测到")


if __name__ == '__main__':
    main()
