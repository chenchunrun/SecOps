#!/usr/bin/env python3
"""
DGA (Domain Generation Algorithm) 域名检测工具
检测疑似自动生成的恶意域名
"""

import argparse
import json
import math
import re
import sys
from collections import Counter
from typing import Dict


class DGADetector:
    """DGA 域名检测器"""

    # 英语常见双字母组合（二元组）
    COMMON_BIGRAMS = {
        'th', 'he', 'in', 'en', 'nt', 'er', 're', 'es', 'on', 'st',
        'an', 'or', 'te', 'ed', 'is', 'it', 'al', 'ar', 'nd', 'to',
        'ng', 'se', 'ha', 'as', 'ou', 'io', 'le', 've', 'co', 'me',
    }

    # 元音和辅音
    VOWELS = set('aeiou')
    CONSONANTS = set('bcdfghjklmnpqrstvwxyz')

    # 已知 DGA 家族特征
    DGA_FAMILIES = {
        'conficker': {
            'length_range': (8, 11),
            'tlds': ['com', 'net', 'org', 'info', 'biz'],
            'pattern': r'^[a-z]+$',
        },
        'cryptolocker': {
            'length_range': (12, 15),
            'tlds': ['com', 'net', 'org', 'info', 'biz', 'ru', 'co.uk'],
            'pattern': r'^[a-z]+$',
        },
        'necurs': {
            'length_range': (6, 15),
            'tlds': ['com', 'net', 'org', 'biz', 'info'],
            'pattern': r'^[a-z0-9]+$',
        },
        'qakbot': {
            'length_range': (8, 25),
            'tlds': ['com', 'net', 'org', 'biz'],
            'pattern': r'^[a-z]+$',
        },
    }

    def __init__(self):
        pass

    def detect(self, domain: str) -> Dict:
        """
        检测域名是否为 DGA 生成

        Args:
            domain: 域名字符串

        Returns:
            dict: 检测结果
        """
        result = {
            'domain': domain,
            'is_dga': False,
            'dga_score': 0.0,
            'dga_probability': 'low',
            'entropy': 0.0,
            'features': {},
            'matched_family': None,
            'risk_factors': [],
        }

        # 清理域名
        domain = domain.strip().lower()
        if '.' in domain:
            parts = domain.rsplit('.', 1)
            sld = parts[0]  # 二级域名部分
            tld = parts[1] if len(parts) > 1 else ''
        else:
            sld = domain
            tld = ''

        # 如果是子域名，只分析最后一个子域
        if '.' in sld:
            sld = sld.rsplit('.', 1)[-1]

        # 计算特征
        features = self._extract_features(sld)
        result['features'] = features
        result['entropy'] = features['entropy']

        # 评分
        score = 0.0

        # 1. 熵值评分 (0-30 分)
        if features['entropy'] > 4.0:
            score += 30
            result['risk_factors'].append(f"极高熵值: {features['entropy']:.2f}")
        elif features['entropy'] > 3.5:
            score += 20
            result['risk_factors'].append(f"高熵值: {features['entropy']:.2f}")
        elif features['entropy'] > 3.0:
            score += 10

        # 2. 长度评分 (0-15 分)
        if features['length'] > 20:
            score += 15
            result['risk_factors'].append(f"域名过长: {features['length']} 字符")
        elif features['length'] > 15:
            score += 10

        # 3. 数字比例 (0-15 分)
        if features['digit_ratio'] > 0.4:
            score += 15
            result['risk_factors'].append(f"数字比例过高: {features['digit_ratio']:.1%}")
        elif features['digit_ratio'] > 0.2:
            score += 8

        # 4. 辅音连续 (0-15 分)
        if features['max_consonant_seq'] >= 5:
            score += 15
            result['risk_factors'].append(f"辅音连续过长: {features['max_consonant_seq']}")
        elif features['max_consonant_seq'] >= 4:
            score += 8

        # 5. 二元组异常 (0-15 分)
        if features['uncommon_bigram_ratio'] > 0.7:
            score += 15
            result['risk_factors'].append("缺少常见字母组合")
        elif features['uncommon_bigram_ratio'] > 0.5:
            score += 8

        # 6. 元音比例异常 (0-10 分)
        if features['vowel_ratio'] < 0.15 or features['vowel_ratio'] > 0.6:
            score += 10
            result['risk_factors'].append(f"元音比例异常: {features['vowel_ratio']:.1%}")

        result['dga_score'] = score

        # 判断概率
        if score >= 60:
            result['is_dga'] = True
            result['dga_probability'] = 'high'
        elif score >= 40:
            result['dga_probability'] = 'medium'
        elif score >= 20:
            result['dga_probability'] = 'low'
        else:
            result['dga_probability'] = 'very_low'

        # 匹配已知 DGA 家族
        result['matched_family'] = self._match_family(sld, tld)

        return result

    def _extract_features(self, domain: str) -> Dict:
        """提取域名特征"""
        features = {}

        # 长度
        features['length'] = len(domain)

        # 熵值
        features['entropy'] = self._calculate_entropy(domain)

        # 字符类型统计
        letters = sum(1 for c in domain if c.isalpha())
        digits = sum(1 for c in domain if c.isdigit())
        hyphens = domain.count('-')

        features['letter_count'] = letters
        features['digit_count'] = digits
        features['hyphen_count'] = hyphens

        if len(domain) > 0:
            features['digit_ratio'] = digits / len(domain)
            features['letter_ratio'] = letters / len(domain)
        else:
            features['digit_ratio'] = 0
            features['letter_ratio'] = 0

        # 元音辅音分析
        vowels = sum(1 for c in domain if c in self.VOWELS)
        consonants = sum(1 for c in domain if c in self.CONSONANTS)

        if letters > 0:
            features['vowel_ratio'] = vowels / letters
        else:
            features['vowel_ratio'] = 0

        # 最长辅音连续
        features['max_consonant_seq'] = self._max_consonant_sequence(domain)

        # 二元组分析
        features['uncommon_bigram_ratio'] = self._uncommon_bigram_ratio(domain)

        # 重复字符
        features['has_repeating'] = bool(re.search(r'(.)\1{2,}', domain))

        return features

    def _calculate_entropy(self, s: str) -> float:
        """计算 Shannon 熵"""
        if not s:
            return 0.0

        freq = Counter(s)
        length = len(s)
        entropy = 0.0

        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    def _max_consonant_sequence(self, s: str) -> int:
        """计算最长辅音连续长度"""
        max_seq = 0
        current_seq = 0

        for c in s:
            if c in self.CONSONANTS:
                current_seq += 1
                max_seq = max(max_seq, current_seq)
            else:
                current_seq = 0

        return max_seq

    def _uncommon_bigram_ratio(self, s: str) -> float:
        """计算非常见二元组比例"""
        if len(s) < 2:
            return 0.0

        bigrams = [s[i:i+2] for i in range(len(s)-1)]
        uncommon = sum(1 for bg in bigrams if bg not in self.COMMON_BIGRAMS)

        return uncommon / len(bigrams)

    def _match_family(self, sld: str, tld: str) -> str:
        """匹配已知 DGA 家族"""
        for family, rules in self.DGA_FAMILIES.items():
            # 检查长度
            min_len, max_len = rules['length_range']
            if not (min_len <= len(sld) <= max_len):
                continue

            # 检查 TLD
            if tld and tld not in rules['tlds']:
                continue

            # 检查模式
            if not re.match(rules['pattern'], sld):
                continue

            return family

        return None


def format_result(result: Dict, output_format: str = 'text') -> str:
    """格式化输出结果"""
    if output_format == 'json':
        return json.dumps(result, ensure_ascii=False, indent=2)

    lines = []
    lines.append(f"域名: {result['domain']}")
    lines.append("")

    # DGA 检测结果
    if result['is_dga']:
        lines.append("[!] DGA 检测: 命中（疑似自动生成域名）")
    else:
        prob_display = {
            'very_low': '[+] 极低',
            'low': '[+] 低',
            'medium': '[*] 中等',
            'high': '[!] 高',
        }
        lines.append(f"DGA 检测: {prob_display.get(result['dga_probability'], '未知')}")

    lines.append(f"DGA 评分: {result['dga_score']:.1f}/100")
    lines.append(f"熵值: {result['entropy']:.3f}")

    if result['matched_family']:
        lines.append(f"匹配家族: {result['matched_family']}")

    lines.append("")

    # 特征
    features = result['features']
    lines.append("【特征分析】")
    lines.append(f"  长度: {features['length']}")
    lines.append(f"  熵值: {features['entropy']:.3f}")
    lines.append(f"  数字比例: {features['digit_ratio']:.1%}")
    lines.append(f"  元音比例: {features['vowel_ratio']:.1%}")
    lines.append(f"  最长辅音连续: {features['max_consonant_seq']}")
    lines.append(f"  非常见二元组: {features['uncommon_bigram_ratio']:.1%}")

    # 风险因素
    if result['risk_factors']:
        lines.append("")
        lines.append("【风险因素】")
        for factor in result['risk_factors']:
            lines.append(f"  - {factor}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='DGA 域名检测工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s qxwz7k2m9p.com
  %(prog)s google.com
  %(prog)s -f domains.txt --only-dga
        '''
    )
    parser.add_argument('domain', nargs='?', help='要检测的域名')
    parser.add_argument('-f', '--file', help='从文件读取域名列表')
    parser.add_argument('-o', '--output', choices=['text', 'json'],
                        default='text', help='输出格式')
    parser.add_argument('--only-dga', action='store_true',
                        help='只输出检测为 DGA 的域名')
    parser.add_argument('--threshold', type=float, default=40,
                        help='DGA 判定阈值 (默认 40)')

    args = parser.parse_args()

    if not args.domain and not args.file:
        parser.print_help()
        sys.exit(1)

    detector = DGADetector()

    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            domains = [line.strip() for line in f if line.strip()]

        results = []
        for domain in domains:
            result = detector.detect(domain)
            if args.only_dga and result['dga_score'] < args.threshold:
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

        # 返回码: 0=非 DGA, 1=疑似 DGA, 2=确认 DGA
        if result['is_dga']:
            sys.exit(2)
        elif result['dga_probability'] == 'medium':
            sys.exit(1)
        else:
            sys.exit(0)


if __name__ == '__main__':
    main()
