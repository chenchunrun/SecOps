#!/usr/bin/env python3
"""
钓鱼内容检测模块
检测敏感字段、金融诈骗关键词、表单提交目标
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse


@dataclass
class PhishingDetectionResult:
    """钓鱼检测结果"""
    is_phishing: bool = False
    confidence: float = 0.0  # 0-100
    phishing_type: str = ""  # financial/credential/identity/generic

    # 检测到的敏感字段
    sensitive_fields: List[str] = field(default_factory=list)
    # 检测到的诈骗关键词
    scam_keywords: List[str] = field(default_factory=list)
    # 表单提交目标
    form_actions: List[str] = field(default_factory=list)
    # 品牌仿冒
    impersonated_brands: List[str] = field(default_factory=list)
    # 风险因素
    risk_factors: List[str] = field(default_factory=list)
    # 风险评分明细
    score_breakdown: Dict[str, int] = field(default_factory=dict)


class PhishingDetector:
    """钓鱼内容检测器"""

    # 敏感字段模式 - 中文
    SENSITIVE_FIELDS_CN = {
        'identity': [
            r'身份证', r'证件号', r'身份信息', r'实名', r'真实姓名',
            r'姓名', r'名字', r'户籍', r'住址', r'地址',
        ],
        'financial': [
            r'银行卡', r'卡号', r'账号', r'账户', r'开户行',
            r'信用卡', r'储蓄卡', r'借记卡', r'支付宝', r'微信支付',
            r'余额', r'转账', r'汇款',
        ],
        'credential': [
            r'密码', r'口令', r'PIN', r'支付密码', r'交易密码',
            r'登录密码', r'取款密码', r'查询密码',
        ],
        'verification': [
            r'验证码', r'短信码', r'动态码', r'OTP', r'手机验证',
            r'短信验证', r'安全码', r'确认码',
        ],
        'contact': [
            r'手机号', r'电话', r'联系方式', r'手机', r'号码',
        ],
    }

    # 敏感字段模式 - 英文
    SENSITIVE_FIELDS_EN = {
        'identity': [
            r'(?i)ssn', r'(?i)social\s*security', r'(?i)passport',
            r'(?i)driver.?s?\s*license', r'(?i)id\s*number', r'(?i)full\s*name',
            r'(?i)date\s*of\s*birth', r'(?i)dob', r'(?i)address',
        ],
        'financial': [
            r'(?i)card\s*number', r'(?i)credit\s*card', r'(?i)debit\s*card',
            r'(?i)account\s*number', r'(?i)routing\s*number', r'(?i)iban',
            r'(?i)swift', r'(?i)cvv', r'(?i)cvc', r'(?i)expir',
            r'(?i)bank\s*account', r'(?i)paypal', r'(?i)venmo',
        ],
        'credential': [
            r'(?i)password', r'(?i)passwd', r'(?i)pin\s*code',
            r'(?i)secret\s*question', r'(?i)security\s*answer',
        ],
        'verification': [
            r'(?i)verification\s*code', r'(?i)otp', r'(?i)one.?time',
            r'(?i)sms\s*code', r'(?i)2fa', r'(?i)mfa',
        ],
        'contact': [
            r'(?i)phone\s*number', r'(?i)mobile', r'(?i)cell\s*phone',
            r'(?i)email\s*address',
        ],
    }

    # 金融诈骗关键词
    FINANCIAL_SCAM_KEYWORDS = [
        # 贷款诈骗
        r'贷款', r'借款', r'借贷', r'放款', r'下款', r'秒批', r'秒到账',
        r'低息', r'无抵押', r'信用贷', r'网贷', r'小额贷',
        # 额度诈骗
        r'额度', r'提额', r'提现', r'套现', r'取现',
        r'信用额度', r'借款额度', r'可用额度',
        # 认证诈骗
        r'认证', r'审核', r'激活', r'解冻', r'解封',
        r'实名认证', r'身份认证', r'银行认证',
        r'审核中', r'审核通过', r'等待审核',
        # 返利诈骗
        r'返利', r'返现', r'佣金', r'提成', r'刷单',
        r'兼职', r'日结', r'在家赚钱',
        # 投资诈骗
        r'高收益', r'稳赚', r'保本', r'理财', r'投资回报',
        r'区块链', r'数字货币', r'虚拟币',
        # 中奖诈骗
        r'中奖', r'恭喜', r'幸运', r'抽奖', r'红包',
        r'领取奖品', r'奖金', r'大奖',
        # 紧急诈骗
        r'紧急', r'立即', r'马上', r'限时', r'过期',
        r'账户异常', r'风险提示', r'安全验证',
    ]

    # 品牌关键词（用于检测仿冒）
    BRAND_KEYWORDS = {
        'banks_cn': [
            '工商银行', '建设银行', '农业银行', '中国银行', '交通银行',
            '招商银行', '浦发银行', '民生银行', '兴业银行', '光大银行',
            '平安银行', '中信银行', '华夏银行', '广发银行',
        ],
        'payment_cn': [
            '支付宝', '微信支付', '云闪付', '京东支付', '美团支付',
            '花呗', '借呗', '白条', '微粒贷',
        ],
        'banks_global': [
            'PayPal', 'Chase', 'Bank of America', 'Wells Fargo', 'Citibank',
            'HSBC', 'Barclays', 'Santander', 'ING', 'Deutsche Bank',
        ],
        'tech': [
            'Apple', 'Google', 'Microsoft', 'Amazon', 'Facebook', 'Netflix',
            'Dropbox', 'LinkedIn', 'Twitter', 'Instagram', 'WhatsApp',
        ],
        'ecommerce': [
            '淘宝', '天猫', '京东', '拼多多', '苏宁', '国美',
            '唯品会', '当当', '网易严选', '小米商城',
        ],
        'government_cn': [
            '公安', '税务', '社保', '医保', '人社局',
            '政务', '政府', '国家', '中央',
        ],
    }

    # 表单相关标签
    FORM_PATTERNS = [
        r'<form[^>]*action=["\']([^"\']+)["\']',
        r'<input[^>]*name=["\']([^"\']+)["\']',
        r'<button[^>]*type=["\']submit["\']',
        r'\.submit\s*\(',
        r'ajax\s*\([^)]*url\s*:',
    ]

    def __init__(self):
        self.result = PhishingDetectionResult()

    def detect(self, html_content: str, url: str = "") -> PhishingDetectionResult:
        """执行钓鱼检测"""
        self.result = PhishingDetectionResult()

        if not html_content:
            return self.result

        # 1. 检测敏感字段
        self._detect_sensitive_fields(html_content)

        # 2. 检测金融诈骗关键词
        self._detect_scam_keywords(html_content)

        # 3. 检测表单提交目标
        self._detect_form_actions(html_content, url)

        # 4. 检测品牌仿冒
        self._detect_brand_impersonation(html_content, url)

        # 5. 计算综合评分
        self._calculate_score()

        return self.result

    def _detect_sensitive_fields(self, html: str):
        """检测敏感字段"""
        detected = set()

        # 检测中文敏感字段
        for category, patterns in self.SENSITIVE_FIELDS_CN.items():
            for pattern in patterns:
                if re.search(pattern, html):
                    detected.add(f"{category}:{pattern}")
                    if category not in [f.split(':')[0] for f in self.result.sensitive_fields]:
                        self.result.sensitive_fields.append(f"{category}:{pattern}")

        # 检测英文敏感字段
        for category, patterns in self.SENSITIVE_FIELDS_EN.items():
            for pattern in patterns:
                if re.search(pattern, html):
                    detected.add(f"{category}:{pattern}")
                    existing_categories = [f.split(':')[0] for f in self.result.sensitive_fields]
                    if category not in existing_categories:
                        self.result.sensitive_fields.append(f"{category}:{pattern}")

        # 添加风险因素
        categories = set(f.split(':')[0] for f in self.result.sensitive_fields)
        if 'identity' in categories and 'financial' in categories:
            self.result.risk_factors.append("同时收集身份和金融信息")
        if 'credential' in categories:
            self.result.risk_factors.append("收集密码/凭证信息")
        if 'verification' in categories:
            self.result.risk_factors.append("收集验证码（可能实时盗用）")

    def _detect_scam_keywords(self, html: str):
        """检测诈骗关键词"""
        for keyword in self.FINANCIAL_SCAM_KEYWORDS:
            if re.search(keyword, html):
                if keyword not in self.result.scam_keywords:
                    self.result.scam_keywords.append(keyword)

        # 识别诈骗类型
        loan_keywords = ['贷款', '借款', '放款', '下款', '额度', '借贷']
        auth_keywords = ['认证', '审核', '激活', '解冻', '解封']
        prize_keywords = ['中奖', '恭喜', '红包', '奖金', '抽奖']
        invest_keywords = ['高收益', '投资', '理财', '区块链', '虚拟币']

        if any(k in self.result.scam_keywords for k in loan_keywords):
            self.result.phishing_type = "financial_loan"
            self.result.risk_factors.append("贷款诈骗特征")
        elif any(k in self.result.scam_keywords for k in auth_keywords):
            self.result.phishing_type = "financial_auth"
            self.result.risk_factors.append("认证诈骗特征")
        elif any(k in self.result.scam_keywords for k in prize_keywords):
            self.result.phishing_type = "prize_scam"
            self.result.risk_factors.append("中奖诈骗特征")
        elif any(k in self.result.scam_keywords for k in invest_keywords):
            self.result.phishing_type = "investment_scam"
            self.result.risk_factors.append("投资诈骗特征")

    def _detect_form_actions(self, html: str, url: str):
        """检测表单提交目标"""
        # 提取 form action
        actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.I)

        for action in actions:
            if action and action not in ['#', '', 'javascript:void(0)']:
                self.result.form_actions.append(action)

                # 检查是否跨域提交
                if url:
                    url_domain = urlparse(url).netloc
                    action_domain = urlparse(action).netloc if '://' in action else url_domain
                    if action_domain and action_domain != url_domain:
                        self.result.risk_factors.append(f"表单跨域提交到: {action_domain}")

        # 检测 AJAX 提交
        ajax_patterns = [
            r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
        ]
        for pattern in ajax_patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                if match not in self.result.form_actions:
                    self.result.form_actions.append(f"AJAX:{match}")

    def _detect_brand_impersonation(self, html: str, url: str):
        """检测品牌仿冒"""
        html_lower = html.lower()
        url_lower = url.lower() if url else ""

        for category, brands in self.BRAND_KEYWORDS.items():
            for brand in brands:
                brand_lower = brand.lower()
                # 页面内容中提到品牌
                if brand_lower in html_lower or brand in html:
                    # 但URL不是官方域名
                    official_domain = self._get_official_domain(brand)
                    if official_domain and official_domain not in url_lower:
                        self.result.impersonated_brands.append(brand)
                        self.result.risk_factors.append(f"疑似仿冒: {brand}")

    def _get_official_domain(self, brand: str) -> Optional[str]:
        """获取品牌官方域名"""
        domain_map = {
            # 中国银行
            '工商银行': 'icbc.com.cn',
            '建设银行': 'ccb.com',
            '农业银行': 'abchina.com',
            '中国银行': 'boc.cn',
            '招商银行': 'cmbchina.com',
            # 支付
            '支付宝': 'alipay.com',
            '微信支付': 'pay.weixin.qq.com',
            'PayPal': 'paypal.com',
            # 科技
            'Apple': 'apple.com',
            'Google': 'google.com',
            'Microsoft': 'microsoft.com',
            'Amazon': 'amazon.com',
            # 电商
            '淘宝': 'taobao.com',
            '天猫': 'tmall.com',
            '京东': 'jd.com',
        }
        return domain_map.get(brand)

    def _calculate_score(self):
        """计算钓鱼置信度评分"""
        score = 0
        breakdown = {}

        # 敏感字段评分
        categories = set(f.split(':')[0] for f in self.result.sensitive_fields)
        if 'identity' in categories:
            score += 25
            breakdown['身份信息收集'] = 25
        if 'financial' in categories:
            score += 30
            breakdown['金融信息收集'] = 30
        if 'credential' in categories:
            score += 25
            breakdown['密码/凭证收集'] = 25
        if 'verification' in categories:
            score += 20
            breakdown['验证码收集'] = 20
        if 'contact' in categories:
            score += 10
            breakdown['联系方式收集'] = 10

        # 多类型组合加分
        if len(categories) >= 3:
            score += 15
            breakdown['多类型敏感信息组合'] = 15

        # 诈骗关键词评分
        scam_count = len(self.result.scam_keywords)
        if scam_count > 0:
            scam_score = min(scam_count * 5, 25)
            score += scam_score
            breakdown[f'诈骗关键词({scam_count}个)'] = scam_score

        # 品牌仿冒评分
        if self.result.impersonated_brands:
            brand_score = min(len(self.result.impersonated_brands) * 15, 30)
            score += brand_score
            breakdown['品牌仿冒'] = brand_score

        # 表单跨域提交
        cross_domain = any('跨域' in f for f in self.result.risk_factors)
        if cross_domain:
            score += 10
            breakdown['表单跨域提交'] = 10

        # 确定是否为钓鱼
        self.result.confidence = min(score, 100)
        self.result.is_phishing = score >= 40
        self.result.score_breakdown = breakdown

        # 设置钓鱼类型
        if not self.result.phishing_type:
            if 'financial' in categories or 'credential' in categories:
                self.result.phishing_type = "credential_theft"
            elif 'identity' in categories:
                self.result.phishing_type = "identity_theft"
            else:
                self.result.phishing_type = "generic"


def analyze_phishing(html_content: str, url: str = "") -> PhishingDetectionResult:
    """便捷函数：分析HTML内容是否为钓鱼页面"""
    detector = PhishingDetector()
    return detector.detect(html_content, url)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("用法: python phishing_detector.py <html_file_or_url>")
        sys.exit(1)

    target = sys.argv[1]

    # 读取HTML内容
    if target.startswith('http'):
        try:
            import requests
            resp = requests.get(target, timeout=10, verify=False)
            html = resp.text
            url = target
        except Exception as e:
            print(f"获取URL失败: {e}")
            sys.exit(1)
    else:
        with open(target, 'r', encoding='utf-8') as f:
            html = f.read()
        url = ""

    # 执行检测
    result = analyze_phishing(html, url)

    # 输出结果
    print("=" * 60)
    print("钓鱼内容检测报告")
    print("=" * 60)

    print(f"\n【检测结论】")
    if result.is_phishing:
        print(f"  判定: [!] 钓鱼页面")
    else:
        print(f"  判定: [+] 未检测到明显钓鱼特征")
    print(f"  置信度: {result.confidence:.0f}%")
    print(f"  类型: {result.phishing_type or '未知'}")

    if result.sensitive_fields:
        print(f"\n【敏感字段】")
        for field in result.sensitive_fields[:10]:
            category, keyword = field.split(':', 1)
            print(f"  - [{category}] {keyword}")

    if result.scam_keywords:
        print(f"\n【诈骗关键词】")
        print(f"  {', '.join(result.scam_keywords[:15])}")

    if result.impersonated_brands:
        print(f"\n【品牌仿冒】")
        print(f"  {', '.join(result.impersonated_brands)}")

    if result.risk_factors:
        print(f"\n【风险因素】")
        for factor in result.risk_factors:
            print(f"  - {factor}")

    if result.score_breakdown:
        print(f"\n【评分明细】")
        for item, score in result.score_breakdown.items():
            print(f"  - {item}: +{score}")

    print("=" * 60)
