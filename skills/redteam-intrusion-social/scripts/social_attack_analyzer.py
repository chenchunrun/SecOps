#!/usr/bin/env python3
"""社会工程攻击模拟与检测工具 - 钓鱼邮件分析、钓鱼页面克隆检测"""

import argparse
import json
import re
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, unquote

# 钓鱼关键词检测
PHISHING_KEYWORDS = {
    'urgency': ['urgent', 'immediately', 'action required', 'account suspended',
                'verify now', '紧急', '立即', '验证', '暂停', '账户异常'],
    'authority': ['bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google',
                  '银行', '客服', '安全中心', 'official', 'support'],
    'reward': ['winner', 'congratulations', 'free', 'prize', 'gift',
               '中奖', '免费', '奖品', '恭喜'],
    'threat': ['suspended', 'closed', 'limited', 'unauthorized', 'locked',
               '冻结', '关闭', '限制', '未授权'],
}

# 可疑URL模式
SUSPICIOUS_URL_PATTERNS = [
    re.compile(r'(?:bit\.ly|tinyurl|t\.co|is\.gd|v\.gd|ow\.ly|shorte\.st)/', re.I),
    re.compile(r'@\w+\.\w+.*\.\w+'),  # user@domain.com.evil.com
    re.compile(r'(?:login|signin|verify|account|secure|update)\.[a-z0-9-]+\.(?:tk|ml|ga|cf|gq)', re.I),
    re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    re.compile(r'(?:href|src|action)\s*=\s*["\']?(?:https?:)?//(?!(?:www\.)?(?:google|facebook|twitter|microsoft|apple|amazon)\.com)', re.I),
]

# 邮件头伪造指标
SPOOFING_INDICATORS = {
    'spf_fail': re.compile(r'spf=(?:fail|softfail|temperror|permerror)', re.I),
    'dmarc_fail': re.compile(r'dmarc=(?:fail|none|temperror|permerror)', re.I),
    'dkim_fail': re.compile(r'dkim=(?:fail|neutral|temperror|permerror)', re.I),
    'received_chain': re.compile(r'Received:\s*from\s+\[', re.I),
}

def analyze_phishing_email(email_content: str) -> Dict:
    """分析钓鱼邮件内容"""
    findings = {
        'score': 0,
        'max_score': 100,
        'indicators': [],
        'category': 'clean',
    }

    content_lower = email_content.lower()

    # 1. 紧迫性检测 (0-25)
    urgency_hits = [kw for kw in PHISHING_KEYWORDS['urgency'] if kw.lower() in content_lower]
    if urgency_hits:
        findings['score'] += min(25, len(urgency_hits) * 8)
        findings['indicators'].append(f'⚠️ 紧迫性语言 ({len(urgency_hits)} 处): {", ".join(urgency_hits[:5])}')

    # 2. 权威伪装 (0-20)
    authority_hits = [kw for kw in PHISHING_KEYWORDS['authority'] if kw.lower() in content_lower]
    if authority_hits:
        findings['score'] += min(20, len(authority_hits) * 5)
        findings['indicators'].append(f'🏢 权威机构引用 ({len(authority_hits)} 处): {", ".join(set(authority_hits[:5]))}')

    # 3. 奖励/威胁 (0-20)
    reward_hits = [kw for kw in PHISHING_KEYWORDS['reward'] if kw.lower() in content_lower]
    threat_hits = [kw for kw in PHISHING_KEYWORDS['threat'] if kw.lower() in content_lower]
    if reward_hits:
        findings['score'] += min(15, len(reward_hits) * 5)
        findings['indicators'].append(f'🎁 奖励诱导: {", ".join(reward_hits[:3])}')
    if threat_hits:
        findings['score'] += min(15, len(threat_hits) * 5)
        findings['indicators'].append(f'⚠️ 威胁恐吓: {", ".join(threat_hits[:3])}')

    # 4. URL分析 (0-20)
    urls = re.findall(r'https?://[^\s<>"\']+', email_content)
    suspicious_urls = []
    for url in urls:
        parsed = urlparse(url)
        for pattern in SUSPICIOUS_URL_PATTERNS:
            if pattern.search(url):
                suspicious_urls.append(url)
                break
        # 检查URL与显示文本不匹配
        display_text = re.findall(r'>(.*?)</a>', email_content)
        for text in display_text:
            text_url_match = re.search(r'https?://[^\s<>"\']+', text)
            if text_url_match and text_url_match.group() != url:
                suspicious_urls.append(f'[显示不匹配] {text} -> {url}')

    if suspicious_urls:
        findings['score'] += min(20, len(suspicious_urls) * 10)
        findings['indicators'].append(f'🔗 可疑URL ({len(suspicious_urls)} 个): {"; ".join(suspicious_urls[:5])}')

    # 5. 附件检测 (0-15)
    dangerous_exts = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.docm', '.xlsm', '.zip']
    attachments = re.findall(r'filename="([^"]+)"', email_content, re.I)
    dangerous_atts = [a for a in attachments if any(a.lower().endswith(ext) for ext in dangerous_exts)]
    if dangerous_atts:
        findings['score'] += min(15, len(dangerous_atts) * 8)
        findings['indicators'].append(f'📎 危险附件 ({len(dangerous_atts)}): {", ".join(dangerous_atts)}')

    # 分类
    score = findings['score']
    if score >= 70:
        findings['category'] = '🔴 高度疑似钓鱼'
    elif score >= 40:
        findings['category'] = '🟡 疑似钓鱼（需人工确认）'
    elif score >= 20:
        findings['category'] = '🟠 存在可疑特征'
    else:
        findings['category'] = '✅ 未见明显钓鱼特征'

    return findings

def analyze_social_media_profile(profile_data: str) -> Dict:
    """分析社交媒体资料的可信度"""
    findings = {
        'trust_score': 100,
        'warnings': [],
    }

    # 检查新账号指标
    if re.search(r'(?:joined|created|registered)\s*:\s*202[4-6]', profile_data, re.I):
        findings['trust_score'] -= 20
        findings['warnings'].append('📅 新创建的账号')

    # 检查粉丝/关注比
    follower_match = re.search(r'followers?\s*:\s*(\d+)', profile_data, re.I)
    following_match = re.search(r'following\s*:\s*(\d+)', profile_data, re.I)
    if follower_match and following_match:
        followers = int(follower_match.group(1))
        following = int(following_match.group(1))
        if following > 0 and followers / following < 0.1:
            findings['trust_score'] -= 25
            findings['warnings'].append(f'📊 粉丝/关注比例异常: {followers}/{following}')

    # 检查模板化描述
    generic_descs = ['crypto enthusiast', 'nft collector', 'dm for collab', 'entrepreneur', 'investor']
    for desc in generic_descs:
        if desc.lower() in profile_data.lower():
            findings['trust_score'] -= 10
            findings['warnings'].append(f'📝 通用描述: {desc}')
            break

    return findings

def generate_awareness_report(analysis: Dict) -> str:
    """生成安全意识报告"""
    lines = [
        f"{'='*50}",
        f"🛡️ 社会工程攻击分析报告",
        f"{'='*50}",
        f"评分: {analysis['score']}/{analysis['max_score']}",
        f"分类: {analysis['category']}",
        f"",
        f"检测指标:",
    ]
    for indicator in analysis.get('indicators', []):
        lines.append(f"  • {indicator}")
    lines.append(f"\n建议:")
    if analysis['score'] >= 40:
        lines.append("  1. 不要点击任何链接或下载附件")
        lines.append("  2. 通过官方渠道直接验证")
        lines.append("  3. 向安全团队报告此事件")
    elif analysis['score'] >= 20:
        lines.append("  1. 仔细核实发件人身份")
        lines.append("  2. 悬停查看链接真实地址")
    else:
        lines.append("  1. 仍建议保持基本警惕")
    return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser(description='社会工程攻击模拟与检测工具')
    parser.add_argument('-f', '--file', help='邮件/文本文件路径')
    parser.add_argument('-t', '--text', help='直接输入文本')
    parser.add_argument('--json', action='store_true', help='JSON输出')
    args = parser.parse_args()

    content = ''
    if args.file:
        from pathlib import Path
        content = Path(args.file).read_text(errors='ignore')
    elif args.text:
        content = args.text
    else:
        parser.print_help()
        sys.exit(1)

    result = analyze_phishing_email(content)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(generate_awareness_report(result))

    return result

if __name__ == '__main__':
    main()
