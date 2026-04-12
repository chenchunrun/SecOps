#!/usr/bin/env python3
"""
域名 WHOIS 查询模块
查询域名注册信息，计算域名年龄，评估新域名风险

优化：添加超时保护，确保 10 秒内返回结果

依赖: pip install python-whois
"""

import re
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse

# WHOIS 查询超时（秒）
WHOIS_TIMEOUT = 4  # WHOIS 超时 4 秒，小于总超时


@dataclass
class WhoisResult:
    """WHOIS 查询结果"""
    domain: str
    success: bool = False
    error: Optional[str] = None

    # 注册信息
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None

    # 域名年龄
    domain_age_days: Optional[int] = None
    domain_age_text: Optional[str] = None

    # 风险评估
    is_new_domain: bool = False  # < 30 天
    is_young_domain: bool = False  # < 180 天
    age_risk_score: int = 0
    age_risk_level: str = "unknown"

    # 其他信息
    name_servers: List[str] = field(default_factory=list)
    registrant_country: Optional[str] = None
    privacy_protected: bool = False

    # 原始数据
    raw_data: Dict = field(default_factory=dict)


class DomainWhoisChecker:
    """域名 WHOIS 查询器"""

    # 域名年龄风险阈值
    AGE_THRESHOLDS = {
        'critical': 7,    # < 7 天: 严重风险
        'high': 30,       # < 30 天: 高风险
        'medium': 90,     # < 90 天: 中风险
        'low': 180,       # < 180 天: 低风险
    }

    # 高风险注册商（常被滥用）
    HIGH_RISK_REGISTRARS = [
        'namecheap',
        'namesilo',
        'porkbun',
        'dynadot',
        'freenom',
    ]

    def __init__(self):
        self._whois_available = False
        try:
            import whois
            self._whois = whois
            self._whois_available = True
        except ImportError:
            pass

    def query(self, domain: str, timeout: int = WHOIS_TIMEOUT) -> WhoisResult:
        """
        查询域名 WHOIS 信息（带超时保护）

        Args:
            domain: 域名或 URL
            timeout: 查询超时（秒），默认 5s

        Returns:
            WhoisResult: 查询结果
        """
        # 从 URL 提取域名
        domain = self._extract_domain(domain)

        result = WhoisResult(domain=domain)

        if not self._whois_available:
            result.error = "python-whois 未安装，请运行: pip install python-whois"
            return result

        def do_whois():
            """在线程中执行 WHOIS 查询"""
            return self._whois.whois(domain)

        try:
            # 使用线程池执行带超时的查询
            # 注意：不使用 with 语句，避免等待超时的线程
            executor = ThreadPoolExecutor(max_workers=1)
            future = executor.submit(do_whois)
            try:
                w = future.result(timeout=timeout)
            except FuturesTimeoutError:
                result.error = f"WHOIS 查询超时（>{timeout}s）"
                executor.shutdown(wait=False, cancel_futures=True)
                return result
            finally:
                executor.shutdown(wait=False)

            if not w or not w.domain_name:
                result.error = "未找到 WHOIS 记录"
                return result

            result.success = True

            # 解析注册商
            result.registrar = w.registrar

            # 解析日期
            result.creation_date = self._parse_date(w.creation_date)
            result.expiration_date = self._parse_date(w.expiration_date)
            result.updated_date = self._parse_date(w.updated_date)

            # 计算域名年龄
            if result.creation_date:
                age = datetime.now() - result.creation_date
                result.domain_age_days = age.days
                result.domain_age_text = self._format_age(age.days)

                # 判断是否新域名
                result.is_new_domain = age.days < 30
                result.is_young_domain = age.days < 180

            # 名称服务器
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    result.name_servers = [ns.lower() for ns in w.name_servers if ns]
                else:
                    result.name_servers = [w.name_servers.lower()]

            # 注册人国家
            result.registrant_country = getattr(w, 'country', None)

            # 隐私保护检测
            result.privacy_protected = self._detect_privacy_protection(w)

            # 风险评估
            self._assess_risk(result)

            # 保存原始数据
            result.raw_data = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(result.creation_date) if result.creation_date else None,
                'expiration_date': str(result.expiration_date) if result.expiration_date else None,
                'name_servers': result.name_servers,
            }

        except Exception as e:
            result.error = str(e)

        return result

    def _extract_domain(self, input_str: str) -> str:
        """从 URL 或域名字符串中提取域名"""
        # 如果是 URL，解析出域名
        if '://' in input_str or input_str.startswith('//'):
            try:
                parsed = urlparse(input_str if '://' in input_str else 'http:' + input_str)
                domain = parsed.netloc
            except:
                domain = input_str
        else:
            domain = input_str

        # 移除端口
        if ':' in domain:
            domain = domain.split(':')[0]

        # 移除路径
        domain = domain.split('/')[0]

        return domain.lower().strip()

    def _parse_date(self, date_value) -> Optional[datetime]:
        """解析日期值"""
        if not date_value:
            return None

        if isinstance(date_value, datetime):
            return date_value

        if isinstance(date_value, list):
            # 取第一个有效日期
            for d in date_value:
                parsed = self._parse_date(d)
                if parsed:
                    return parsed
            return None

        if isinstance(date_value, str):
            # 尝试解析字符串日期
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d',
                '%d-%b-%Y',
                '%Y/%m/%d',
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(date_value, fmt)
                except:
                    continue

        return None

    def _format_age(self, days: int) -> str:
        """格式化域名年龄"""
        if days < 1:
            return "不到 1 天"
        elif days < 7:
            return f"{days} 天"
        elif days < 30:
            weeks = days // 7
            return f"约 {weeks} 周"
        elif days < 365:
            months = days // 30
            return f"约 {months} 个月"
        else:
            years = days // 365
            months = (days % 365) // 30
            if months > 0:
                return f"约 {years} 年 {months} 个月"
            return f"约 {years} 年"

    def _detect_privacy_protection(self, whois_data) -> bool:
        """检测是否启用隐私保护"""
        privacy_indicators = [
            'privacy', 'proxy', 'protect', 'redacted',
            'whoisguard', 'privacyguardian', 'contactprivacy',
            'domainsbyproxy', 'withheld', 'data protected',
        ]

        # 检查注册人名称
        registrant = getattr(whois_data, 'name', '') or ''
        registrant += ' ' + (getattr(whois_data, 'org', '') or '')

        for indicator in privacy_indicators:
            if indicator in registrant.lower():
                return True

        return False

    def _assess_risk(self, result: WhoisResult):
        """评估域名年龄风险"""
        score = 0

        # 基于域名年龄评分
        if result.domain_age_days is not None:
            if result.domain_age_days < self.AGE_THRESHOLDS['critical']:
                score += 30
                result.age_risk_level = "critical"
            elif result.domain_age_days < self.AGE_THRESHOLDS['high']:
                score += 20
                result.age_risk_level = "high"
            elif result.domain_age_days < self.AGE_THRESHOLDS['medium']:
                score += 10
                result.age_risk_level = "medium"
            elif result.domain_age_days < self.AGE_THRESHOLDS['low']:
                score += 5
                result.age_risk_level = "low"
            else:
                result.age_risk_level = "safe"
        else:
            result.age_risk_level = "unknown"
            score += 5  # 无法确定年龄也是风险

        # 基于注册商评分
        if result.registrar:
            registrar_lower = result.registrar.lower()
            for risky_registrar in self.HIGH_RISK_REGISTRARS:
                if risky_registrar in registrar_lower:
                    score += 5
                    break

        # 隐私保护加分（钓鱼站点常用）
        if result.privacy_protected:
            score += 5

        result.age_risk_score = score


def query_domain_whois(domain: str) -> WhoisResult:
    """便捷函数：查询域名 WHOIS"""
    checker = DomainWhoisChecker()
    return checker.query(domain)


def format_whois_report(result: WhoisResult) -> str:
    """格式化 WHOIS 报告（Markdown）"""
    lines = []

    lines.append("## 域名注册信息 (WHOIS)")
    lines.append("")

    if not result.success:
        lines.append(f"**查询失败**: {result.error}")
        return '\n'.join(lines)

    # 风险等级标记
    risk_tag = {
        'critical': '[!]',
        'high': '[!]',
        'medium': '[*]',
        'low': '[+]',
        'safe': '[+]',
        'unknown': '[-]',
    }
    emoji = risk_tag.get(result.age_risk_level, '[-]')

    lines.append("| 字段 | 值 | 风险 |")
    lines.append("|------|-----|------|")
    lines.append(f"| 域名 | {result.domain} | - |")

    if result.domain_age_text:
        lines.append(f"| **域名年龄** | **{result.domain_age_text}** | {emoji} {result.age_risk_level} |")
    else:
        lines.append(f"| 域名年龄 | 未知 | [-] unknown |")

    if result.creation_date:
        lines.append(f"| 注册日期 | {result.creation_date.strftime('%Y-%m-%d')} | - |")

    if result.expiration_date:
        lines.append(f"| 到期日期 | {result.expiration_date.strftime('%Y-%m-%d')} | - |")

    if result.registrar:
        lines.append(f"| 注册商 | {result.registrar} | - |")

    if result.privacy_protected:
        lines.append(f"| 隐私保护 | 是 | [*] |")

    lines.append("")

    # 风险提示
    if result.is_new_domain:
        lines.append(f"> [!] **新注册域名** (< 30 天)：高度可疑，钓鱼站点常使用新域名")
    elif result.is_young_domain:
        lines.append(f"> [!] **年轻域名** (< 180 天)：需要额外关注")

    if result.name_servers:
        lines.append("")
        lines.append("**名称服务器**:")
        for ns in result.name_servers[:3]:
            lines.append(f"- {ns}")

    return '\n'.join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python domain_whois.py <域名或URL>")
        print("示例: python domain_whois.py example.com")
        print("示例: python domain_whois.py http://phishing-site.tk/login")
        sys.exit(1)

    domain = sys.argv[1]
    result = query_domain_whois(domain)
    print(format_whois_report(result))

    # 输出 JSON 摘要
    if result.success:
        print("\n---")
        print(f"域名年龄: {result.domain_age_days} 天")
        print(f"风险等级: {result.age_risk_level}")
        print(f"风险评分: +{result.age_risk_score}")
