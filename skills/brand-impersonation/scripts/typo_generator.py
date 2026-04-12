#!/usr/bin/env python3
"""
打字错误域名生成器
生成各种类型的仿冒域名变体
"""

import argparse
import json
import sys
from typing import List, Set
from itertools import product

# 键盘布局 - QWERTY
KEYBOARD_ADJACENT = {
    'q': 'wa', 'w': 'qeas', 'e': 'wrds', 'r': 'etfd', 't': 'ryfg',
    'y': 'tuhg', 'u': 'yijh', 'i': 'uokj', 'o': 'iplk', 'p': 'ol',
    'a': 'qwsz', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc',
    'g': 'ftyhbv', 'h': 'gyujnb', 'j': 'huikmn', 'k': 'jiolm',
    'l': 'kop', 'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb',
    'b': 'vghn', 'n': 'bhjm', 'm': 'njk',
    '1': '2q', '2': '13qw', '3': '24we', '4': '35er', '5': '46rt',
    '6': '57ty', '7': '68yu', '8': '79ui', '9': '80io', '0': '9p'
}

# 常见双字母
DOUBLE_LETTERS = ['aa', 'bb', 'cc', 'dd', 'ee', 'ff', 'gg', 'hh', 'ii',
                  'jj', 'kk', 'll', 'mm', 'nn', 'oo', 'pp', 'qq', 'rr',
                  'ss', 'tt', 'uu', 'vv', 'ww', 'xx', 'yy', 'zz']

# 常见 TLD
COMMON_TLDS = [
    'com', 'net', 'org', 'info', 'biz', 'xyz', 'top', 'online',
    'site', 'club', 'app', 'dev', 'io', 'co', 'me', 'cc',
    'cn', 'com.cn', 'net.cn', 'org.cn'
]

# 恶意前缀后缀
MALICIOUS_PREFIXES = [
    'secure-', 'login-', 'account-', 'verify-', 'update-', 'support-',
    'auth-', 'signin-', 'my-', 'new-', 'get-', 'www-', 'mail-',
    'web-', 'ssl-', 'service-', 'official-'
]

MALICIOUS_SUFFIXES = [
    '-login', '-secure', '-support', '-verify', '-update', '-account',
    '-auth', '-signin', '-service', '-official', '-online', '-web',
    '-app', '-mobile', '-portal', '-help'
]


def split_domain(domain: str) -> tuple:
    """分离域名和 TLD"""
    parts = domain.lower().split('.')

    # 处理多级 TLD (如 .com.cn)
    if len(parts) >= 3 and parts[-2] in ['com', 'net', 'org', 'gov', 'edu']:
        name = '.'.join(parts[:-2])
        tld = '.'.join(parts[-2:])
    elif len(parts) >= 2:
        name = '.'.join(parts[:-1])
        tld = parts[-1]
    else:
        name = domain
        tld = 'com'

    return name, tld


def generate_omissions(name: str) -> Set[str]:
    """遗漏字母变体"""
    variants = set()
    for i in range(len(name)):
        variant = name[:i] + name[i+1:]
        if variant and variant != name:
            variants.add(variant)
    return variants


def generate_duplications(name: str) -> Set[str]:
    """重复字母变体"""
    variants = set()
    for i in range(len(name)):
        variant = name[:i] + name[i] + name[i:]
        if variant != name:
            variants.add(variant)
    return variants


def generate_swaps(name: str) -> Set[str]:
    """相邻字母互换变体"""
    variants = set()
    for i in range(len(name) - 1):
        variant = name[:i] + name[i+1] + name[i] + name[i+2:]
        if variant != name:
            variants.add(variant)
    return variants


def generate_adjacent_keys(name: str) -> Set[str]:
    """相邻键误触变体"""
    variants = set()
    for i, char in enumerate(name):
        if char.lower() in KEYBOARD_ADJACENT:
            for adj in KEYBOARD_ADJACENT[char.lower()]:
                variant = name[:i] + adj + name[i+1:]
                if variant != name:
                    variants.add(variant)
    return variants


def generate_insertions(name: str) -> Set[str]:
    """插入字母变体"""
    variants = set()
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    for i in range(len(name) + 1):
        for char in alphabet:
            variant = name[:i] + char + name[i:]
            if variant != name:
                variants.add(variant)
    return variants


def generate_homoglyphs(name: str) -> Set[str]:
    """同形字变体 (ASCII 范围)"""
    variants = set()

    # ASCII 同形字
    ascii_homoglyphs = {
        'l': ['1', 'i'],
        'i': ['1', 'l'],
        'o': ['0'],
        '0': ['o'],
        '1': ['l', 'i'],
        's': ['5'],
        '5': ['s'],
        'e': ['3'],
        'a': ['4'],
        'b': ['8'],
        'g': ['9', 'q'],
        'q': ['g'],
    }

    for i, char in enumerate(name.lower()):
        if char in ascii_homoglyphs:
            for replacement in ascii_homoglyphs[char]:
                variant = name[:i] + replacement + name[i+1:]
                if variant != name:
                    variants.add(variant)

    return variants


def generate_tld_variants(name: str, original_tld: str) -> Set[str]:
    """TLD 变体"""
    variants = set()
    for tld in COMMON_TLDS:
        if tld != original_tld:
            variants.add(f"{name}.{tld}")
    return variants


def generate_prefix_variants(name: str, tld: str) -> Set[str]:
    """前缀变体"""
    variants = set()
    for prefix in MALICIOUS_PREFIXES:
        variants.add(f"{prefix}{name}.{tld}")
    return variants


def generate_suffix_variants(name: str, tld: str) -> Set[str]:
    """后缀变体"""
    variants = set()
    for suffix in MALICIOUS_SUFFIXES:
        variants.add(f"{name}{suffix}.{tld}")
    return variants


def generate_subdomain_spoofs(name: str, tld: str) -> Set[str]:
    """子域名欺骗变体"""
    variants = set()
    fake_domains = ['attacker.com', 'evil.xyz', 'phish.top', 'fake.site']

    for fake in fake_domains:
        variants.add(f"{name}.{tld}.{fake}")
        variants.add(f"{name}-{tld}.{fake}")

    return variants


def generate_all_variants(domain: str, include_tld: bool = True,
                         include_prefixes: bool = True,
                         include_suffixes: bool = True,
                         include_subdomains: bool = False) -> dict:
    """生成所有变体"""
    name, tld = split_domain(domain)

    results = {
        'original': domain,
        'name': name,
        'tld': tld,
        'variants': {}
    }

    # 基础变体
    omissions = generate_omissions(name)
    results['variants']['omission'] = [f"{v}.{tld}" for v in omissions]

    duplications = generate_duplications(name)
    results['variants']['duplication'] = [f"{v}.{tld}" for v in duplications]

    swaps = generate_swaps(name)
    results['variants']['swap'] = [f"{v}.{tld}" for v in swaps]

    adjacent = generate_adjacent_keys(name)
    results['variants']['adjacent_key'] = [f"{v}.{tld}" for v in adjacent]

    homoglyphs = generate_homoglyphs(name)
    results['variants']['homoglyph'] = [f"{v}.{tld}" for v in homoglyphs]

    # 可选变体
    if include_tld:
        tld_variants = generate_tld_variants(name, tld)
        results['variants']['tld_variant'] = list(tld_variants)

    if include_prefixes:
        prefix_variants = generate_prefix_variants(name, tld)
        results['variants']['prefix'] = list(prefix_variants)

    if include_suffixes:
        suffix_variants = generate_suffix_variants(name, tld)
        results['variants']['suffix'] = list(suffix_variants)

    if include_subdomains:
        subdomain_variants = generate_subdomain_spoofs(name, tld)
        results['variants']['subdomain_spoof'] = list(subdomain_variants)

    # 统计
    total = sum(len(v) for v in results['variants'].values())
    results['total_variants'] = total

    return results


def main():
    parser = argparse.ArgumentParser(description='打字错误域名生成器')
    parser.add_argument('domain', help='目标域名')
    parser.add_argument('--all', action='store_true', help='生成所有类型变体')
    parser.add_argument('--omission', action='store_true', help='遗漏字母')
    parser.add_argument('--duplication', action='store_true', help='重复字母')
    parser.add_argument('--swap', action='store_true', help='字母互换')
    parser.add_argument('--adjacent', action='store_true', help='相邻键误触')
    parser.add_argument('--homoglyph', action='store_true', help='同形字')
    parser.add_argument('--tld', action='store_true', help='TLD 变体')
    parser.add_argument('--prefix', action='store_true', help='恶意前缀')
    parser.add_argument('--suffix', action='store_true', help='恶意后缀')
    parser.add_argument('--subdomain', action='store_true', help='子域名欺骗')
    parser.add_argument('-o', '--output', help='输出文件')
    parser.add_argument('--json', action='store_true', help='JSON 格式输出')

    args = parser.parse_args()

    # 确定生成哪些类型
    include_tld = args.all or args.tld
    include_prefix = args.all or args.prefix
    include_suffix = args.all or args.suffix
    include_subdomain = args.all or args.subdomain

    results = generate_all_variants(
        args.domain,
        include_tld=include_tld,
        include_prefixes=include_prefix,
        include_suffixes=include_suffix,
        include_subdomains=include_subdomain
    )

    # 过滤指定类型
    if not args.all:
        filtered = {}
        type_map = {
            'omission': args.omission,
            'duplication': args.duplication,
            'swap': args.swap,
            'adjacent_key': args.adjacent,
            'homoglyph': args.homoglyph,
            'tld_variant': args.tld,
            'prefix': args.prefix,
            'suffix': args.suffix,
            'subdomain_spoof': args.subdomain
        }

        # 如果没有指定任何类型，默认显示基础类型
        if not any(type_map.values()):
            type_map = {k: True for k in ['omission', 'duplication', 'swap', 'adjacent_key', 'homoglyph']}

        for vtype, include in type_map.items():
            if include and vtype in results['variants']:
                filtered[vtype] = results['variants'][vtype]

        results['variants'] = filtered
        results['total_variants'] = sum(len(v) for v in filtered.values())

    # 输出
    if args.json:
        output = json.dumps(results, ensure_ascii=False, indent=2)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
        else:
            print(output)
    else:
        print(f"\n目标域名: {results['original']}")
        print(f"域名部分: {results['name']}")
        print(f"TLD: {results['tld']}")
        print(f"总变体数: {results['total_variants']}")
        print("=" * 50)

        all_domains = []
        for vtype, variants in results['variants'].items():
            print(f"\n[{vtype}] ({len(variants)} 个)")
            for v in variants[:10]:  # 限制显示数量
                print(f"  {v}")
            if len(variants) > 10:
                print(f"  ... 还有 {len(variants) - 10} 个")
            all_domains.extend(variants)

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(set(all_domains))))
            print(f"\n[+] 已保存 {len(all_domains)} 个变体到: {args.output}")


if __name__ == '__main__':
    main()
