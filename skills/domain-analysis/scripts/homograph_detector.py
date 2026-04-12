#!/usr/bin/env python3
"""
同形字攻击检测工具
检测域名中的视觉欺骗字符（IDN Homograph Attack）
"""

import argparse
import json
import re
import sys
import unicodedata
from typing import Dict, List, Tuple, Optional


class HomographDetector:
    """同形字攻击检测器"""

    # 常见同形字映射 (视觉相似的字符)
    CONFUSABLES = {
        # 西里尔字母 -> ASCII
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p',
        'х': 'x', 'у': 'y', 'А': 'A', 'В': 'B', 'С': 'C',
        'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M', 'О': 'O',
        'Р': 'P', 'Т': 'T', 'Х': 'X', 'і': 'i', 'ј': 'j',

        # 希腊字母 -> ASCII
        'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'τ': 't',
        'υ': 'u', 'ω': 'w', 'Α': 'A', 'Β': 'B', 'Ε': 'E',
        'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N',
        'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',

        # 其他相似字符
        'ı': 'i',  # 土耳其语无点 i
        'ł': 'l',  # 波兰语
        'ɑ': 'a',  # IPA
        'ɡ': 'g',  # IPA
        'ɴ': 'n',  # 小型大写
        'ʀ': 'r',  # 小型大写
        'ꜱ': 's',  # 小型大写

        # 数字相似
        '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
        '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
    }

    # 常见数字/字母替换
    LEETSPEAK = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
        '7': 't', '8': 'b', '@': 'a', '$': 's',
    }

    # 视觉相似的字符对
    VISUAL_SIMILAR = {
        ('r', 'n'): 'm',  # rn 看起来像 m
        ('c', 'l'): 'd',  # cl 看起来像 d
        ('v', 'v'): 'w',  # vv 看起来像 w
    }

    # 知名品牌列表
    KNOWN_BRANDS = {
        'google', 'facebook', 'apple', 'microsoft', 'amazon',
        'paypal', 'netflix', 'instagram', 'twitter', 'linkedin',
        'whatsapp', 'telegram', 'yahoo', 'outlook', 'gmail',
        'icloud', 'dropbox', 'github', 'gitlab', 'slack',
        'zoom', 'skype', 'adobe', 'oracle', 'salesforce',
        'alibaba', 'taobao', 'jd', 'baidu', 'tencent', 'wechat',
        'alipay', 'weibo', 'bilibili', 'douyin', 'kuaishou',
    }

    def __init__(self):
        pass

    def detect(self, domain: str) -> Dict:
        """
        检测域名中的同形字攻击

        Args:
            domain: 域名字符串

        Returns:
            dict: 检测结果
        """
        result = {
            'domain': domain,
            'is_homograph': False,
            'risk_level': 'low',
            'has_non_ascii': False,
            'has_mixed_scripts': False,
            'confusable_chars': [],
            'normalized_domain': None,
            'ascii_skeleton': None,
            'target_brand': None,
            'brand_similarity': 0.0,
            'punycode': None,
            'warnings': [],
        }

        # 清理域名
        domain = domain.strip().lower()

        # 移除协议和路径
        if '://' in domain:
            domain = domain.split('://')[1]
        if '/' in domain:
            domain = domain.split('/')[0]

        result['domain'] = domain

        # 检查是否包含非 ASCII 字符
        non_ascii_chars = [(i, c) for i, c in enumerate(domain) if ord(c) > 127]
        result['has_non_ascii'] = len(non_ascii_chars) > 0

        # 转换为 Punycode
        try:
            result['punycode'] = domain.encode('idna').decode('ascii')
        except Exception:
            result['punycode'] = None

        # 检测混合脚本
        scripts = self._detect_scripts(domain)
        result['has_mixed_scripts'] = len(scripts) > 1
        if result['has_mixed_scripts']:
            result['warnings'].append(f"混合脚本: {', '.join(scripts)}")

        # 查找同形字
        confusables = []
        for i, char in enumerate(domain):
            if char in self.CONFUSABLES:
                confusables.append({
                    'position': i,
                    'char': char,
                    'looks_like': self.CONFUSABLES[char],
                    'unicode_name': unicodedata.name(char, 'UNKNOWN'),
                    'script': self._get_script(char),
                })

        result['confusable_chars'] = confusables
        if confusables:
            result['is_homograph'] = True
            result['warnings'].append(f"发现 {len(confusables)} 个同形字符")

        # 生成 ASCII 骨架
        result['ascii_skeleton'] = self._to_ascii_skeleton(domain)
        result['normalized_domain'] = self._normalize(domain)

        # 品牌仿冒检测
        brand, similarity = self._detect_brand_impersonation(result['ascii_skeleton'])
        if brand:
            result['target_brand'] = brand
            result['brand_similarity'] = similarity
            if similarity > 0.8:
                result['warnings'].append(f"高度相似品牌: {brand} ({similarity:.0%})")

        # 计算风险等级
        result['risk_level'] = self._calculate_risk(result)

        return result

    def _detect_scripts(self, text: str) -> set:
        """检测文本中使用的脚本类型"""
        scripts = set()
        for char in text:
            if char.isalpha():
                try:
                    name = unicodedata.name(char, '')
                    if 'LATIN' in name:
                        scripts.add('Latin')
                    elif 'CYRILLIC' in name:
                        scripts.add('Cyrillic')
                    elif 'GREEK' in name:
                        scripts.add('Greek')
                    elif 'CJK' in name or 'HANGUL' in name or 'HIRAGANA' in name or 'KATAKANA' in name:
                        scripts.add('CJK')
                    elif 'ARABIC' in name:
                        scripts.add('Arabic')
                    else:
                        scripts.add('Other')
                except:
                    pass
        return scripts

    def _get_script(self, char: str) -> str:
        """获取单个字符的脚本类型"""
        try:
            name = unicodedata.name(char, '')
            if 'LATIN' in name:
                return 'Latin'
            elif 'CYRILLIC' in name:
                return 'Cyrillic'
            elif 'GREEK' in name:
                return 'Greek'
            else:
                return 'Other'
        except:
            return 'Unknown'

    def _to_ascii_skeleton(self, domain: str) -> str:
        """将域名转换为 ASCII 骨架"""
        result = []
        for char in domain:
            if char in self.CONFUSABLES:
                result.append(self.CONFUSABLES[char])
            elif char in self.LEETSPEAK:
                result.append(self.LEETSPEAK[char])
            elif ord(char) < 128:
                result.append(char)
            else:
                # 尝试 NFKD 规范化
                normalized = unicodedata.normalize('NFKD', char)
                ascii_part = ''.join(c for c in normalized if ord(c) < 128)
                result.append(ascii_part if ascii_part else char)

        return ''.join(result)

    def _normalize(self, domain: str) -> str:
        """规范化域名"""
        # 使用 NFKC 规范化
        return unicodedata.normalize('NFKC', domain)

    def _detect_brand_impersonation(self, skeleton: str) -> Tuple[Optional[str], float]:
        """
        检测品牌仿冒

        返回条件更严格：
        - 精确包含品牌名：返回 100%
        - 编辑距离相似度 > 75%：返回匹配结果
        - 长度差异过大：不匹配（避免短域名误判）
        """
        # 提取域名主体（去除 TLD）
        if '.' in skeleton:
            main_part = skeleton.rsplit('.', 1)[0]
            if '.' in main_part:
                main_part = main_part.rsplit('.', 1)[-1]
        else:
            main_part = skeleton

        best_match = None
        best_similarity = 0.0

        for brand in self.KNOWN_BRANDS:
            # 精确包含品牌名
            if brand in main_part:
                return brand, 1.0

            # 长度约束：域名主体与品牌长度差异不超过 3 个字符
            # 避免短域名误判（如 "jd" 不应该匹配到 "microsoft"）
            len_diff = abs(len(main_part) - len(brand))
            if len_diff > 3:
                continue

            # 编辑距离相似度（阈值提高到 0.75）
            similarity = self._similarity(main_part, brand)
            if similarity > best_similarity and similarity > 0.75:
                best_similarity = similarity
                best_match = brand

        return best_match, best_similarity

    def _similarity(self, s1: str, s2: str) -> float:
        """计算两个字符串的相似度（基于编辑距离）"""
        if not s1 or not s2:
            return 0.0

        # 简单的编辑距离相似度
        len1, len2 = len(s1), len(s2)
        if len1 > len2:
            s1, s2 = s2, s1
            len1, len2 = len2, len1

        distances = range(len1 + 1)
        for i2, c2 in enumerate(s2):
            distances_ = [i2 + 1]
            for i1, c1 in enumerate(s1):
                if c1 == c2:
                    distances_.append(distances[i1])
                else:
                    distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
            distances = distances_

        distance = distances[-1]
        max_len = max(len1, len2)
        return 1 - (distance / max_len) if max_len > 0 else 0.0

    def _calculate_risk(self, result: Dict) -> str:
        """计算风险等级"""
        score = 0

        if result['is_homograph']:
            score += 30

        if result['has_mixed_scripts']:
            score += 20

        if result['target_brand']:
            if result['brand_similarity'] > 0.9:
                score += 40
            elif result['brand_similarity'] > 0.7:
                score += 25

        if len(result['confusable_chars']) > 3:
            score += 10

        if score >= 50:
            return 'high'
        elif score >= 25:
            return 'medium'
        else:
            return 'low'


def format_result(result: Dict, output_format: str = 'text') -> str:
    """格式化输出结果"""
    if output_format == 'json':
        return json.dumps(result, ensure_ascii=False, indent=2)

    lines = []
    lines.append(f"域名: {result['domain']}")

    if result['punycode'] and result['punycode'] != result['domain']:
        lines.append(f"Punycode: {result['punycode']}")

    lines.append("")

    # 检测结果
    risk_display = {
        'low': '[+] 低',
        'medium': '[*] 中',
        'high': '[!] 高',
    }
    lines.append(f"风险等级: {risk_display.get(result['risk_level'], '未知')}")
    lines.append(f"同形字攻击: {'是' if result['is_homograph'] else '否'}")
    lines.append(f"混合脚本: {'是' if result['has_mixed_scripts'] else '否'}")

    if result['ascii_skeleton'] != result['domain']:
        lines.append(f"ASCII 骨架: {result['ascii_skeleton']}")

    # 品牌检测
    if result['target_brand']:
        lines.append(f"目标品牌: {result['target_brand']} (相似度: {result['brand_similarity']:.0%})")

    # 同形字详情
    if result['confusable_chars']:
        lines.append("")
        lines.append("【同形字符详情】")
        for char_info in result['confusable_chars']:
            lines.append(
                f"  位置 {char_info['position']}: '{char_info['char']}' "
                f"→ '{char_info['looks_like']}' "
                f"({char_info['script']}: {char_info['unicode_name']})"
            )

    # 警告
    if result['warnings']:
        lines.append("")
        lines.append("【警告】")
        for warning in result['warnings']:
            lines.append(f"  [!] {warning}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='同形字攻击检测工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s "аpple.com"          # 西里尔字母 'а'
  %(prog)s "paypa1.com"         # 数字 '1' 替换 'l'
  %(prog)s "gοοgle.com"         # 希腊字母 'ο'
  %(prog)s -f domains.txt --only-suspicious
        '''
    )
    parser.add_argument('domain', nargs='?', help='要检测的域名')
    parser.add_argument('-f', '--file', help='从文件读取域名列表')
    parser.add_argument('-o', '--output', choices=['text', 'json'],
                        default='text', help='输出格式')
    parser.add_argument('--only-suspicious', action='store_true',
                        help='只输出可疑域名')
    parser.add_argument('--brand-check', action='store_true',
                        help='启用品牌仿冒检测')

    args = parser.parse_args()

    if not args.domain and not args.file:
        parser.print_help()
        sys.exit(1)

    detector = HomographDetector()

    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            domains = [line.strip() for line in f if line.strip()]

        results = []
        for domain in domains:
            result = detector.detect(domain)
            if args.only_suspicious and result['risk_level'] == 'low':
                continue
            results.append(result)

        if args.output == 'json':
            print(json.dumps(results, ensure_ascii=False, indent=2))
        else:
            for result in results:
                print(format_result(result, args.output))
                print('-' * 50)
    else:
        result = detector.detect(args.domain)
        print(format_result(result, args.output))

        # 返回码
        if result['risk_level'] == 'high':
            sys.exit(2)
        elif result['risk_level'] == 'medium':
            sys.exit(1)
        else:
            sys.exit(0)


if __name__ == '__main__':
    main()
