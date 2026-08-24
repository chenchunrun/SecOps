#!/usr/bin/env python3
"""
BEC (Business Email Compromise) 检测器
检测伪装高管/供应商进行金融欺诈的邮件模式。

ATT&CK 映射: T1656 (Impersonation), T1566.002 (Spearphishing Link)
用法:
    python bec_detector.py -f email.eml
    python bec_detector.py --sender "ceo@fake.co" --body "urgent wire transfer"
    python bec_detector.py -f email.eml --json
"""

import argparse
import json
import re
import sys
from datetime import datetime
from typing import Dict, List
from urllib.parse import urlparse


# BEC 高危金融关键词
FINANCIAL_KEYWORDS = {
    'transfer': ['wire transfer', 'bank transfer', '资金转账', '汇款', '银行转账',
                 'urgent payment', '紧急付款', 'immediate transfer'],
    'invoice': ['invoice', 'billing', 'payment due', '发票', '账单', '付款通知',
                'overdue', '逾期'],
    'account': ['account number', 'banking details', 'update account', '账号变更',
                '银行信息变更', '收款账户更新'],
    'authority': ['CEO', 'CFO', 'President', 'Director', '总经理', '总裁',
                  '董事长', '副总'],
    'urgency': ['urgent', 'immediate', 'ASAP', 'today', '紧急', '立即', '今天',
                '限时', 'deadline'],
    'secrecy': ['confidential', 'private', 'between us', '机密', '保密',
                '仅限你我', 'don\'t discuss'],
}

# BEC 常见域名欺骗模式
DOMAIN_DECEPTION_PATTERNS = [
    re.compile(r'[0-9].*\.(com|net|org|co|io)', re.I),          # 含数字的域名
    re.compile(r'\.(co|xyz|top|tk|ml|ga|cf|gq|info|biz)$', re.I),  # 高风险TLD
    re.compile(r'-.*\.(com|net|org)$', re.I),                    # 含连字符
    re.compile(r'(reply|mail|srv|mx|gw)[0-9]*\.', re.I),         # 动态回复域名
]

# 高管职务关键词（用于检测伪装高管）
EXECUTIVE_TITLES = [
    'CEO', 'CFO', 'COO', 'CTO', 'CIO', 'President', 'Vice President',
    'Director', 'Chairman', 'Managing Director', 'General Manager',
    '总经理', '总裁', '董事长', '副总经理', '总监', '局长',
]

# 回复链异常指标
REPLY_CHAIN_ANOMALIES = [
    re.compile(r'from:\s*\[?external\]?', re.I),
    re.compile(r'reply-to:\s*\w+@(?!\w+\.(com|org|net|edu|gov))', re.I),
    re.compile(r'return-path:.*different\s*from\s*from:', re.I),
]


def extract_sender_domain(sender: str) -> str:
    """从发件人地址提取域名"""
    match = re.search(r'@([\w.-]+)', sender)
    return match.group(1).lower() if match else ''


def check_domain_deception(domain: str) -> List[str]:
    """检查域名欺骗模式"""
    warnings = []
    for pattern in DOMAIN_DECEPTION_PATTERNS:
        if pattern.search(domain):
            warnings.append(f"域名模式可疑: {domain}")
            break
    return warnings


def check_financial_indicators(text: str) -> Dict:
    """检测金融欺诈关键词"""
    text_lower = text.lower()
    hits = {}
    total_score = 0

    for category, keywords in FINANCIAL_KEYWORDS.items():
        matched = [kw for kw in keywords if kw.lower() in text_lower]
        if matched:
            hits[category] = matched
            if category in ('transfer', 'account'):
                total_score += 20
            elif category == 'authority':
                total_score += 15
            elif category == 'urgency':
                total_score += 15
            elif category == 'secrecy':
                total_score += 10
            elif category == 'invoice':
                total_score += 10

    return {'score': min(total_score, 70), 'hits': hits}


def check_executive_impersonation(text: str, sender: str) -> List[str]:
    """检测高管伪装"""
    warnings = []
    text_upper = text.upper()

    for title in EXECUTIVE_TITLES:
        if title.upper() in text_upper:
            # 检查发件人域名是否与高管身份匹配
            domain = extract_sender_domain(sender)
            if domain and not any(legit in domain for legit in
                                  ['gmail.com', 'outlook.com', 'yahoo.com'] + ['']):
                # 非常见邮箱域名发送高管相关内容
                pass  # 外部域名发高管内容本身不一定是问题
            warnings.append(f"邮件中包含高管职务引用: {title}")

    return warnings


def check_reply_chain_anomalies(headers: str) -> List[str]:
    """检测回复链异常"""
    warnings = []
    for pattern in REPLY_CHAIN_ANOMALIES:
        if pattern.search(headers):
            warnings.append(f"回复链异常: {pattern.pattern}")
    return warnings


def detect_bec(sender: str = '', body: str = '', headers: str = '',
               full_email: str = '') -> Dict:
    """BEC 检测主函数"""
    if full_email:
        # 从完整邮件中提取字段
        sender_match = re.search(r'From:\s*(.+)', full_email)
        sender = sender_match.group(1).strip() if sender_match else sender
        body = full_email
        headers = full_email

    result = {
        'timestamp': datetime.now().isoformat(),
        'sender': sender,
        'sender_domain': extract_sender_domain(sender),
        'risk_score': 0,
        'max_score': 100,
        'risk_level': 'LOW',
        'indicators': [],
        'attck_mapping': ['T1656'],
    }

    # 1. 域名欺骗检测 (0-15)
    domain = extract_sender_domain(sender)
    if domain:
        domain_warnings = check_domain_deception(domain)
        if domain_warnings:
            result['risk_score'] += 15
            result['indicators'].extend(domain_warnings)

    # 2. 金融欺诈关键词 (0-70)
    if body:
        fin_result = check_financial_indicators(body)
        result['risk_score'] += fin_result['score']
        for cat, kws in fin_result['hits'].items():
            result['indicators'].append(f"[{cat}] 匹配: {', '.join(kws[:3])}")

    # 3. 高管伪装检测 (0-10)
    exec_warnings = check_executive_impersonation(body or '', sender)
    if exec_warnings:
        result['risk_score'] += min(10, len(exec_warnings) * 5)
        result['indicators'].extend(exec_warnings)
        result['attck_mapping'].append('T1566.002')

    # 4. 回复链异常 (0-5)
    if headers:
        chain_warnings = check_reply_chain_anomalies(headers)
        if chain_warnings:
            result['risk_score'] += min(5, len(chain_warnings) * 3)
            result['indicators'].extend(chain_warnings)

    # 确定风险等级
    score = result['risk_score']
    if score >= 60:
        result['risk_level'] = 'CRITICAL'
        result['recommendation'] = '极可能为BEC攻击，立即阻止转账并联系安全团队'
    elif score >= 40:
        result['risk_level'] = 'HIGH'
        result['recommendation'] = '高度可疑，建议电话确认发件人身份'
    elif score >= 20:
        result['risk_level'] = 'MEDIUM'
        result['recommendation'] = '存在风险特征，谨慎处理'
    else:
        result['risk_level'] = 'LOW'
        result['recommendation'] = '未见明显BEC特征'

    return result


def generate_report(result: Dict) -> str:
    """生成人类可读报告"""
    lines = [
        '=' * 55,
        '🔍 BEC (商业邮件欺诈) 检测报告',
        '=' * 55,
        f"时间: {result['timestamp']}",
        f"发件人: {result['sender']}",
        f"发件域名: {result['sender_domain']}",
        f"风险评分: {result['risk_score']}/{result['max_score']}",
        f"风险等级: {result['risk_level']}",
        f"ATT&CK 映射: {', '.join(result['attck_mapping'])}",
        '',
        '检测指标:',
    ]
    for ind in result.get('indicators', []):
        lines.append(f'  • {ind}')

    if 'recommendation' in result:
        lines.append(f"\n建议: {result['recommendation']}")

    lines.append(f"\n防御建议:")
    lines.append(f"  M1017 - 员工安全意识培训（BEC 专项）")
    lines.append(f"  M1047 - 财务流程审计（双重确认机制）")
    lines.append(f"  M1054 - 邮件网关强化（发件人验证规则）")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='BEC (Business Email Compromise) 检测器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s -f email.eml                    # 分析邮件文件
  %(prog)s --sender "ceo@fake.co" --body "urgent wire transfer"  # 直接输入
  %(prog)s -f email.eml --json             # JSON 输出

ATT&CK 映射: T1656 (Impersonation)
        """
    )
    parser.add_argument('-f', '--file', help='邮件文件路径')
    parser.add_argument('--sender', help='发件人地址')
    parser.add_argument('--body', help='邮件正文')
    parser.add_argument('--json', action='store_true', help='JSON 输出')
    args = parser.parse_args()

    content = ''
    if args.file:
        from pathlib import Path
        content = Path(args.file).read_text(errors='ignore')

    result = detect_bec(
        sender=args.sender or '',
        body=args.body or content,
        full_email=content if args.file else '',
    )

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(generate_report(result))

    # 高风险退出码
    sys.exit(1 if result['risk_level'] in ('CRITICAL', 'HIGH') else 0)


if __name__ == '__main__':
    main()
