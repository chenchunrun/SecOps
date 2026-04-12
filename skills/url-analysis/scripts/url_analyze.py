#!/usr/bin/env python3
"""
URL 综合分析工具
解析 URL、检测钓鱼、同形字攻击、规避技术、查询威胁情报

增强版本 - 集成 CloakHunter (EMGES) 检测能力

环境变量配置：
  URL_ANALYSIS_TIMEOUT      - HTTP 请求超时时间（秒），默认 30
  URL_ANALYSIS_MAX_REDIRECTS - 最大重定向次数，默认 10
  URL_ANALYSIS_USER_AGENT   - User-Agent 类型（chrome/firefox/safari/googlebot/curl），默认 chrome
  URL_ANALYSIS_VERIFY_SSL   - 是否验证 SSL 证书（true/false），默认 false
"""

import argparse
import json
import re
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs, unquote
import unicodedata


# ============ 环境变量配置 ============
def _get_env_int(key: str, default: int) -> int:
    """从环境变量获取整数值"""
    val = os.environ.get(key, '')
    if val:
        try:
            return int(val)
        except ValueError:
            print(f"警告: 环境变量 {key}={val} 不是有效整数，使用默认值 {default}", file=sys.stderr)
    return default


def _get_env_bool(key: str, default: bool) -> bool:
    """从环境变量获取布尔值"""
    val = os.environ.get(key, '').lower()
    if val in ('true', '1', 'yes', 'on'):
        return True
    elif val in ('false', '0', 'no', 'off'):
        return False
    return default


# 默认配置（可通过环境变量覆盖）
DEFAULT_TIMEOUT = _get_env_int('URL_ANALYSIS_TIMEOUT', 30)
DEFAULT_MAX_REDIRECTS = _get_env_int('URL_ANALYSIS_MAX_REDIRECTS', 10)

# 导入同目录下的模块
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

# 尝试导入增强模块
try:
    from phishing_detector import PhishingDetector, PhishingDetectionResult
    PHISHING_DETECTOR_AVAILABLE = True
except ImportError:
    PHISHING_DETECTOR_AVAILABLE = False

try:
    from url_evasion_patterns import EvasionPatternDetector
    EVASION_DETECTOR_AVAILABLE = True
except ImportError:
    EVASION_DETECTOR_AVAILABLE = False

try:
    from threat_actor_attribution import ThreatActorAttributor, format_attribution_report, attribution_to_dict
    ATTRIBUTION_AVAILABLE = True
except ImportError:
    ATTRIBUTION_AVAILABLE = False



class HomoglyphDetector:
    """
    同形字攻击检测器
    检测 IDN Homograph Attack (国际化域名同形字攻击)
    """

    # 常见同形字映射 (Unicode -> ASCII)
    HOMOGLYPH_MAP = {
        # 西里尔字母
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
        'у': 'y', 'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H',
        'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X',
        # 希腊字母
        'α': 'a', 'ο': 'o', 'ν': 'v', 'τ': 't', 'Α': 'A', 'Β': 'B',
        'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N',
        'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X', 'Ζ': 'Z',
        # 数字替换
        '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
        '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
        # 常见混淆字符
        'і': 'i', 'ı': 'i', 'ӏ': 'l', 'ⅰ': 'i', 'ⅼ': 'l',
        'ℓ': 'l', '∨': 'v', '∧': 'a', 'ⅴ': 'v', 'ⅹ': 'x',
        'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i', 'ɴ': 'n', 'ʀ': 'r',
        'ѕ': 's', 'ᴀ': 'a', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e',
        'ᴍ': 'm', 'ᴏ': 'o', 'ᴘ': 'p', 'ᴛ': 't', 'ᴜ': 'u',
        # 特殊符号
        '‐': '-', '‑': '-', '‒': '-', '–': '-', '—': '-',
        '⁄': '/', '／': '/', '∕': '/',
        '．': '.', '。': '.',
    }

    # 品牌特定的同形字变体
    BRAND_HOMOGLYPHS = {
        'paypal': ['pаypal', 'payрal', 'раypal', 'paypaI', 'раураl'],
        'google': ['gооgle', 'googIe', 'gοοgle', 'g00gle'],
        'apple': ['аpple', 'appIe', 'аррlе', 'app1e'],
        'microsoft': ['micrоsoft', 'microsоft', 'micrоsоft'],
        'amazon': ['аmazon', 'amazоn', 'аmаzon', 'amaz0n'],
        'facebook': ['fаcebook', 'facеbook', 'facebооk'],
        'netflix': ['netfIix', 'netfliх', 'netf1ix'],
        'instagram': ['instаgram', 'instagгam', '1nstagram'],
        'twitter': ['twittеr', 'tωitter', 'tw1tter'],
        'linkedin': ['linkedіn', 'lіnkedin', '1inkedin'],
    }

    def __init__(self):
        pass

    def detect(self, domain: str) -> Dict[str, Any]:
        """
        检测域名中的同形字攻击

        Args:
            domain: 域名字符串

        Returns:
            检测结果字典
        """
        result = {
            'has_homoglyphs': False,
            'mixed_scripts': False,
            'suspicious_chars': [],
            'normalized_domain': None,
            'possible_target': None,
            'confidence': 0,
            'details': {}
        }

        # 检查是否包含非 ASCII 字符
        non_ascii_chars = []
        for char in domain:
            if ord(char) > 127:
                non_ascii_chars.append({
                    'char': char,
                    'codepoint': f'U+{ord(char):04X}',
                    'name': unicodedata.name(char, 'UNKNOWN'),
                    'script': self._get_script(char)
                })

        if non_ascii_chars:
            result['has_homoglyphs'] = True
            result['suspicious_chars'] = non_ascii_chars

        # 检测混合脚本
        scripts = set()
        for char in domain:
            if char not in '.-':
                script = self._get_script(char)
                if script:
                    scripts.add(script)

        if len(scripts) > 1:
            result['mixed_scripts'] = True
            result['details']['scripts'] = list(scripts)

        # 标准化域名
        normalized = self._normalize_domain(domain)
        result['normalized_domain'] = normalized

        # 检测是否仿冒已知品牌
        target = self._detect_brand_target(domain, normalized)
        if target:
            result['possible_target'] = target['brand']
            result['confidence'] = target['confidence']

        return result

    def _get_script(self, char: str) -> str:
        """获取字符的脚本类型"""
        try:
            name = unicodedata.name(char, '')
            if 'LATIN' in name:
                return 'Latin'
            elif 'CYRILLIC' in name:
                return 'Cyrillic'
            elif 'GREEK' in name:
                return 'Greek'
            elif 'CJK' in name:
                return 'CJK'
            elif 'ARABIC' in name:
                return 'Arabic'
            elif 'HEBREW' in name:
                return 'Hebrew'
            elif 'DIGIT' in name:
                return 'Digit'
            else:
                return 'Other'
        except:
            return 'Unknown'

    def _normalize_domain(self, domain: str) -> str:
        """将域名中的同形字标准化为 ASCII"""
        normalized = []
        for char in domain:
            if char in self.HOMOGLYPH_MAP:
                normalized.append(self.HOMOGLYPH_MAP[char])
            else:
                normalized.append(char)
        return ''.join(normalized)

    def _detect_brand_target(self, domain: str, normalized: str) -> Optional[Dict]:
        """检测是否仿冒特定品牌"""
        domain_lower = domain.lower()
        normalized_lower = normalized.lower()

        # 检查已知品牌的同形字变体
        for brand, variants in self.BRAND_HOMOGLYPHS.items():
            # 直接匹配变体
            for variant in variants:
                if variant in domain_lower:
                    return {'brand': brand, 'confidence': 95}

            # 检查标准化后是否匹配
            if brand in normalized_lower and brand not in domain_lower:
                return {'brand': brand, 'confidence': 85}

        # 通用品牌检测
        brands = ['paypal', 'google', 'apple', 'microsoft', 'amazon',
                  'facebook', 'netflix', 'instagram', 'twitter', 'linkedin',
                  'whatsapp', 'telegram', 'yahoo', 'outlook', 'gmail']

        for brand in brands:
            if brand in normalized_lower and brand not in domain_lower:
                return {'brand': brand, 'confidence': 75}

        return None


class RedirectChainAnalyzer:
    """跳转链全链分析器"""

    def __init__(self):
        pass

    def analyze_chain(self, redirect_chain: List[Dict], original_url: str) -> Dict[str, Any]:
        """
        分析完整的跳转链

        Args:
            redirect_chain: 跳转链列表
            original_url: 原始 URL

        Returns:
            跳转链分析结果
        """
        result = {
            'total_hops': len(redirect_chain),
            'domains_visited': [],
            'cross_domain_redirects': 0,
            'js_redirects': 0,
            'meta_redirects': 0,
            'http_redirects': 0,
            'risk_score': 0,
            'risk_factors': [],
            'final_domain': None,
            'domain_changes': [],
        }

        if not redirect_chain:
            return result

        prev_domain = None
        try:
            prev_domain = urlparse(original_url).netloc
        except:
            pass

        for hop in redirect_chain:
            try:
                hop_url = hop.get('url', '')
                hop_type = hop.get('type', 'unknown')
                current_domain = urlparse(hop_url).netloc

                # 统计跳转类型
                if hop_type == 'js_redirect':
                    result['js_redirects'] += 1
                elif hop_type == 'meta_refresh':
                    result['meta_redirects'] += 1
                elif hop_type in ('301', '302', '303', '307', '308', 'http'):
                    result['http_redirects'] += 1

                # 收集访问的域名
                if current_domain and current_domain not in result['domains_visited']:
                    result['domains_visited'].append(current_domain)

                # 检测跨域跳转
                if prev_domain and current_domain and prev_domain != current_domain:
                    result['cross_domain_redirects'] += 1
                    result['domain_changes'].append({
                        'from': prev_domain,
                        'to': current_domain,
                        'type': hop_type,
                    })

                prev_domain = current_domain
            except:
                continue

        result['final_domain'] = prev_domain

        # 风险评估
        # JS 跳转风险
        if result['js_redirects'] > 0:
            score = result['js_redirects'] * 15
            result['risk_score'] += score
            result['risk_factors'].append({
                'factor': 'js_redirect',
                'description': f"JS 跳转 ({result['js_redirects']} 次)",
                'score': score,
            })

        # 跨域跳转风险
        if result['cross_domain_redirects'] >= 2:
            score = result['cross_domain_redirects'] * 10
            result['risk_score'] += score
            result['risk_factors'].append({
                'factor': 'cross_domain_chain',
                'description': f"多次跨域跳转 ({result['cross_domain_redirects']} 次)",
                'score': score,
            })

        # 总跳转次数风险
        if result['total_hops'] >= 4:
            score = 15
            result['risk_score'] += score
            result['risk_factors'].append({
                'factor': 'long_redirect_chain',
                'description': f"长跳转链 ({result['total_hops']} 跳)",
                'score': score,
            })

        return result


class URLAnalyzer:
    """URL 综合分析器 (增强版)"""

    # 短链接服务
    SHORT_URL_DOMAINS = {
        'bit.ly', 'j.mp', 'tinyurl.com', 't.co', 'goo.gl',
        't.cn', 'url.cn', 'dwz.cn', 'is.gd', 'v.gd',
        'ow.ly', 'buff.ly', 'adf.ly', 'cutt.ly', 'rb.gy',
        'shorturl.at', 's.id', 'rebrand.ly',
    }

    # 高风险 TLD
    HIGH_RISK_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work',
        'click', 'link', 'info', 'biz', 'online', 'site',
        'club', 'icu', 'buzz', 'fun', 'space', 'website',
    }

    # 钓鱼关键词
    PHISHING_KEYWORDS = {
        'login', 'signin', 'sign-in', 'password', 'passwd',
        'account', 'verify', 'verification', 'secure', 'security',
        'update', 'confirm', 'authenticate', 'bank', 'paypal',
        'apple', 'microsoft', 'google', 'amazon', 'netflix',
        'suspend', 'locked', 'unlock', 'recover', 'restore',
        'billing', 'invoice', 'payment', 'wallet', 'credential',
    }

    # 恶意文件扩展名
    MALICIOUS_EXTENSIONS = {
        'exe', 'dll', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js',
        'hta', 'msi', 'jar', 'wsf', 'com', 'pif', 'lnk', 'iso',
        'img', 'vhd', 'reg', 'inf', 'cpl', 'application',
    }

    # 知名品牌及其官方域名
    KNOWN_BRANDS = {
        'google': ['google.com', 'google.cn', 'googleapis.com'],
        'facebook': ['facebook.com', 'fb.com', 'fb.me'],
        'apple': ['apple.com', 'icloud.com'],
        'microsoft': ['microsoft.com', 'office.com', 'live.com', 'outlook.com'],
        'amazon': ['amazon.com', 'amazon.cn', 'aws.amazon.com'],
        'paypal': ['paypal.com', 'paypal.me'],
        'netflix': ['netflix.com'],
        'instagram': ['instagram.com'],
        'twitter': ['twitter.com', 'x.com'],
        'linkedin': ['linkedin.com'],
        'whatsapp': ['whatsapp.com', 'wa.me'],
        'telegram': ['telegram.org', 't.me'],
        'yahoo': ['yahoo.com'],
        'gmail': ['gmail.com'],
        'outlook': ['outlook.com', 'outlook.live.com'],
        'dropbox': ['dropbox.com'],
        'github': ['github.com'],
        'zoom': ['zoom.us'],
        'adobe': ['adobe.com'],
        'stripe': ['stripe.com'],
    }

    def __init__(self, follow_redirects: bool = False, timeout: int = None):
        self.follow_redirects = follow_redirects
        self.timeout = timeout if timeout is not None else DEFAULT_TIMEOUT
        self.homoglyph_detector = HomoglyphDetector()
        self.redirect_chain_analyzer = RedirectChainAnalyzer()

        # 初始化钓鱼检测器
        if PHISHING_DETECTOR_AVAILABLE:
            self.phishing_detector = PhishingDetector()
        else:
            self.phishing_detector = None

        # 初始化规避检测器
        if EVASION_DETECTOR_AVAILABLE:
            self.evasion_detector = EvasionPatternDetector()
        else:
            self.evasion_detector = None

        # 初始化威胁组织归因器
        if ATTRIBUTION_AVAILABLE:
            self.threat_attributor = ThreatActorAttributor()
        else:
            self.threat_attributor = None

    def analyze(self, url: str, html_content: Optional[str] = None,
                fetch_result: Optional[Any] = None) -> Dict[str, Any]:
        """
        分析 URL

        Args:
            url: 要分析的 URL
            html_content: 可选的 HTML 内容，用于规避技术检测
            fetch_result: 可选的 URLFetcher 返回结果

        Returns:
            分析结果字典
        """
        result = {
            'url': url,
            'analysis_time': datetime.now().isoformat(),
            'valid': False,
            'components': None,
            'is_short_url': False,
            'final_url': None,
            'redirect_chain': [],
            'redirect_chain_analysis': None,  # 新增：跳转链分析
            'domain_info': None,
            'threat_intel': None,
            'risk_score': 0,
            'risk_level': 'unknown',
            'risk_factors': [],
            'phishing_indicators': [],
            'phishing_detection': None,  # 新增：钓鱼内容检测
            'homoglyph_analysis': None,
            'evasion_analysis': None,
            'fetch_info': None,
            'file_download': None,
            'recommendations': [],
            'defanged_url': None,
            'related_iocs': {
                'domains': [],
                'ips': [],
                'hashes': [],
            },
            'attribution': None,  # 威胁组织归因
            'domain_whois': None,  # 域名 WHOIS 信息
            'errors': [],
        }

        # ============ 处理 fetch_result ============
        if fetch_result:
            result['fetch_info'] = {
                'fetched': True,
                'final_url': fetch_result.final_url,
                'status_code': fetch_result.status_code,
                'title': fetch_result.title,
                'response_time_ms': fetch_result.response_time_ms,
                'total_redirects': fetch_result.total_redirects,
                'has_js_redirect': fetch_result.has_js_redirect,
                'js_redirect_target': fetch_result.js_redirect_target,
            }
            result['final_url'] = fetch_result.final_url
            result['redirect_chain'] = [
                {'url': h.url, 'type': h.redirect_type, 'status': h.status_code}
                for h in fetch_result.redirect_chain
            ]

            # 重定向链风险评估
            if fetch_result.total_redirects >= 3:
                result['risk_factors'].append({
                    'factor': 'multiple_redirects',
                    'description': f"多重跳转链 ({fetch_result.total_redirects} 次)",
                    'score': 15,
                })

            if fetch_result.has_js_redirect:
                result['risk_factors'].append({
                    'factor': 'js_redirect',
                    'description': f"JS 跳转到: {fetch_result.js_redirect_target}",
                    'score': 20,
                })

            # 如果最终 URL 域名与原始不同，额外分析
            if fetch_result.final_url != url:
                try:
                    final_parsed = urlparse(fetch_result.final_url)
                    final_domain = final_parsed.netloc
                    if final_domain and final_domain not in result['related_iocs']['domains']:
                        result['related_iocs']['domains'].append(final_domain)
                except:
                    pass

            # ============ 跳转链全链分析 ============
            if result['redirect_chain']:
                chain_analysis = self.redirect_chain_analyzer.analyze_chain(
                    result['redirect_chain'], url
                )
                result['redirect_chain_analysis'] = chain_analysis

                # 将跳转链风险因素合并到总体风险
                for rf in chain_analysis.get('risk_factors', []):
                    result['risk_factors'].append(rf)

        # 解析 URL
        try:
            components = self._parse_url(url)
            result['components'] = components
            result['valid'] = True
        except Exception as e:
            result['errors'].append(f"URL 解析失败: {e}")
            return result

        # 脱敏 URL
        result['defanged_url'] = self._defang_url(url)

        # 提取域名
        domain = components.get('domain', '')
        result['related_iocs']['domains'].append(domain)

        # ============ 域名分析提示 (WHOIS/年龄 -> domain-analysis) ============
        # 域名注册信息（WHOIS、域名年龄）已迁移到 domain-analysis 技能
        # 必须调用 domain-analysis 获取完整域名信息
        if not components.get('is_ip'):
            result['domain_whois'] = {
                'status': 'ACTION_REQUIRED',
                'priority': 'HIGH',
                'message': '[!] 必须调用 domain-analysis 技能！域名年龄是判断恶意站点的核心指标',
                'call_suggestion': {
                    'skill': 'domain-analysis',
                    'command': f"python domain_analyze.py {domain}",
                    'features': ['WHOIS 查询', '域名年龄风险评估', 'DNS 记录', 'DGA 检测', '同形字检测'],
                    'risk_scoring': {
                        'age_lt_7d': '+30 (critical)',
                        'age_lt_30d': '+20 (high)',
                        'age_lt_90d': '+10 (medium)',
                        'age_lt_180d': '+5 (low)'
                    }
                }
            }
        else:
            result['domain_whois'] = {
                'status': 'skipped',
                'reason': 'IP 地址无需 WHOIS 查询'
            }

        # ============ 同形字攻击检测 ============
        homoglyph_result = self.homoglyph_detector.detect(domain)
        result['homoglyph_analysis'] = homoglyph_result

        if homoglyph_result['has_homoglyphs']:
            score = 25
            desc = "检测到同形字 (IDN Homograph Attack)"
            if homoglyph_result['possible_target']:
                score = 40
                desc = f"同形字攻击仿冒: {homoglyph_result['possible_target']} (置信度: {homoglyph_result['confidence']}%)"

            result['risk_factors'].append({
                'factor': 'homoglyph_attack',
                'description': desc,
                'score': score,
            })

        if homoglyph_result['mixed_scripts']:
            result['risk_factors'].append({
                'factor': 'mixed_scripts',
                'description': f"混合脚本域名: {homoglyph_result['details'].get('scripts', [])}",
                'score': 15,
            })

        # 检查是否是短链接
        if self._is_short_url(domain):
            result['is_short_url'] = True
            result['risk_factors'].append({
                'factor': 'short_url',
                'description': "短链接服务 - 隐藏真实目标",
                'score': 10,
            })

        # 检查高风险 TLD
        tld = components.get('tld', '')
        if tld in self.HIGH_RISK_TLDS:
            result['risk_factors'].append({
                'factor': 'high_risk_tld',
                'description': f"高风险 TLD: .{tld}",
                'score': 15,
            })

        # 检查 IP 直连
        if components.get('is_ip'):
            result['risk_factors'].append({
                'factor': 'ip_direct',
                'description': "IP 地址直连 - 无域名",
                'score': 20,
            })
            result['related_iocs']['ips'].append(domain)

        # 检查非标准端口
        port = components.get('port')
        if port and port not in (80, 443):
            result['risk_factors'].append({
                'factor': 'non_standard_port',
                'description': f"非标准端口: {port}",
                'score': 10,
            })

        # 钓鱼检测
        phishing = self._detect_phishing(url, components)
        result['phishing_indicators'] = phishing
        if phishing:
            for indicator in phishing:
                result['risk_factors'].append({
                    'factor': 'phishing',
                    'description': indicator,
                    'score': 15,
                })

        # 品牌仿冒检测 (增强版)
        brand_result = self._detect_brand_impersonation_enhanced(domain)
        if brand_result:
            result['risk_factors'].append({
                'factor': 'brand_impersonation',
                'description': brand_result['description'],
                'score': brand_result['score'],
            })

        # 文件下载检测
        file_info = self._detect_file_download(components)
        if file_info:
            result['file_download'] = file_info
            if file_info.get('is_malicious_type'):
                result['risk_factors'].append({
                    'factor': 'malicious_file',
                    'description': f"恶意文件类型: .{file_info['extension']}",
                    'score': 40,
                })

        # ============ HTML 内容分析（钓鱼检测 + 规避技术） ============
        if html_content:
            # 钓鱼内容检测
            if self.phishing_detector:
                try:
                    phishing_result = self.phishing_detector.detect(html_content, url)
                    result['phishing_detection'] = {
                        'is_phishing': phishing_result.is_phishing,
                        'confidence': phishing_result.confidence,
                        'phishing_type': phishing_result.phishing_type,
                        'sensitive_fields': phishing_result.sensitive_fields,
                        'scam_keywords': phishing_result.scam_keywords,
                        'form_actions': phishing_result.form_actions,
                        'impersonated_brands': phishing_result.impersonated_brands,
                        'risk_factors': phishing_result.risk_factors,
                        'score_breakdown': phishing_result.score_breakdown,
                    }

                    # 根据钓鱼检测结果添加风险因素
                    if phishing_result.is_phishing:
                        result['risk_factors'].append({
                            'factor': 'phishing_content',
                            'description': f"钓鱼内容检测: {phishing_result.phishing_type} (置信度: {phishing_result.confidence:.0f}%)",
                            'score': 40,
                        })

                    # 敏感字段风险
                    if phishing_result.sensitive_fields:
                        score = min(len(phishing_result.sensitive_fields) * 5, 25)
                        result['risk_factors'].append({
                            'factor': 'sensitive_fields',
                            'description': f"敏感信息收集: {', '.join(phishing_result.sensitive_fields[:5])}",
                            'score': score,
                        })

                    # 金融诈骗关键词
                    if phishing_result.scam_keywords:
                        score = min(len(phishing_result.scam_keywords) * 8, 30)
                        result['risk_factors'].append({
                            'factor': 'scam_keywords',
                            'description': f"诈骗关键词: {', '.join(phishing_result.scam_keywords[:3])}",
                            'score': score,
                        })

                    # 品牌仿冒
                    if phishing_result.impersonated_brands:
                        result['risk_factors'].append({
                            'factor': 'brand_impersonation_content',
                            'description': f"品牌仿冒: {', '.join(phishing_result.impersonated_brands)}",
                            'score': 25,
                        })

                except Exception as e:
                    result['phishing_detection'] = {
                        'status': 'error',
                        'error': str(e),
                    }
            else:
                result['phishing_detection'] = {
                    'status': 'unavailable',
                    'reason': 'phishing_detector module not found',
                }

            # 规避技术检测
            if self.evasion_detector:
                try:
                    evasion_result = self.evasion_detector.analyze_html(html_content)
                    result['evasion_analysis'] = {
                        'total_techniques': evasion_result.total_techniques,
                        'detected_techniques': evasion_result.detected_techniques,
                        'anti_detection_score': evasion_result.anti_detection_score,
                        'evasion_complexity': evasion_result.evasion_complexity,
                    }

                    # DOM 噪音分析
                    if hasattr(evasion_result, 'dom_noise') and evasion_result.dom_noise:
                        result['evasion_analysis']['dom_noise'] = {
                            'severity': evasion_result.dom_noise.severity,
                            'noise_ratio': evasion_result.dom_noise.noise_ratio,
                            'hidden_chinese_words': evasion_result.dom_noise.hidden_chinese_words,
                            'score': evasion_result.dom_noise.score,
                        }
                        if evasion_result.dom_noise.score > 0:
                            result['risk_factors'].append({
                                'factor': 'dom_noise_injection',
                                'description': f"DOM噪音注入 ({evasion_result.dom_noise.severity}): {evasion_result.dom_noise.hidden_chinese_words} 个隐藏中文词",
                                'score': evasion_result.dom_noise.score,
                            })

                    # CSS 规避分析
                    if hasattr(evasion_result, 'css_evasion') and evasion_result.css_evasion:
                        result['evasion_analysis']['css_evasion'] = {
                            'severity': evasion_result.css_evasion.severity,
                            'total_hidden': evasion_result.css_evasion.total_hidden,
                            'score': evasion_result.css_evasion.score,
                        }
                        if evasion_result.css_evasion.score > 0:
                            result['risk_factors'].append({
                                'factor': 'css_evasion',
                                'description': f"CSS内容隐藏 ({evasion_result.css_evasion.severity}): {evasion_result.css_evasion.total_hidden} 个隐藏元素",
                                'score': evasion_result.css_evasion.score,
                            })

                    # 基础规避技术评分
                    if evasion_result.anti_detection_score >= 5:
                        result['risk_factors'].append({
                            'factor': 'evasion_techniques',
                            'description': f"检测到规避技术 (复杂度: {evasion_result.evasion_complexity})",
                            'score': min(evasion_result.anti_detection_score, 25),
                        })
                except Exception as e:
                    result['evasion_analysis'] = {
                        'status': 'error',
                        'error': str(e),
                    }
            else:
                result['evasion_analysis'] = {'status': 'unavailable', 'reason': 'module not found'}

        # 威胁情报查询提示
        result['threat_intel'] = {
            'status': 'pending',
            'message': '需要调用 MCP 查询威胁情报',
            'mcp_call': {
                'server': 'cybersec-cloud',
                'tool': 'risk_insight',
                'params': {
                    'indicator': url,
                    'kind': 'url',
                }
            }
        }

        # ============ 威胁组织归因分析 (新增) ============
        if self.threat_attributor:
            try:
                page_title = ""
                if fetch_result and fetch_result.title:
                    page_title = fetch_result.title

                phishing_dict = None
                if result.get('phishing_detection') and isinstance(result['phishing_detection'], dict):
                    phishing_dict = result['phishing_detection']

                attribution_result = self.threat_attributor.analyze(
                    url=url,
                    domain=domain,
                    html_content=html_content or "",
                    page_title=page_title,
                    phishing_detection=phishing_dict
                )

                if attribution_result.has_attribution:
                    actor = attribution_result.primary_actor
                    result['attribution'] = {
                        'has_attribution': True,
                        'actor_id': actor.actor_id,
                        'actor_name': actor.actor_name,
                        'aliases': actor.aliases,
                        'confidence': actor.confidence,
                        'description': actor.description,
                        'targets': actor.targets,
                        'ttps': actor.ttps,
                        'matched_indicators': [
                            {'type': m['type'], 'description': m['description']}
                            for m in actor.matched_indicators[:5]
                        ],
                        'references': actor.references,
                        'secondary_actors': [
                            {'name': a.actor_name, 'confidence': a.confidence}
                            for a in attribution_result.secondary_actors
                        ]
                    }

                    # 归因成功加分
                    result['risk_factors'].append({
                        'factor': 'threat_actor_attribution',
                        'description': f"归因到已知黑产组织: {actor.actor_name} (置信度: {actor.confidence}%)",
                        'score': 20 if actor.confidence >= 60 else 10,
                    })
                else:
                    result['attribution'] = {
                        'has_attribution': False,
                        'message': '未能归因到已知黑产组织'
                    }

                # 添加 WebSearch 增强建议
                result['websearch_suggestions'] = {
                    'enabled': attribution_result.websearch_enabled,
                    'trigger_reason': attribution_result.websearch_trigger_reason,
                    'suggestions': [
                        {
                            'type': s.search_type,
                            'query': s.query,
                            'purpose': s.purpose,
                            'priority': s.priority,
                        }
                        for s in attribution_result.websearch_suggestions
                    ] if attribution_result.websearch_suggestions else []
                }
            except Exception as e:
                result['attribution'] = {
                    'has_attribution': False,
                    'error': str(e)
                }
        else:
            result['attribution'] = {
                'has_attribution': False,
                'reason': 'attribution module not available'
            }

        # 计算风险分数
        result['risk_score'] = sum(f['score'] for f in result['risk_factors'])
        result['risk_level'] = self._calculate_risk_level(result['risk_score'])

        # 生成威胁扩线建议（仅作为深度分析建议信号）
        result['expansion_suggestions'] = generate_expansion_suggestions(result)

        # 生成深度分析建议信号
        deep_analysis_reasons = self._generate_deep_analysis_reasons(result)
        result['deep_analysis_recommended'] = bool(deep_analysis_reasons)
        result['deep_analysis_reasons'] = deep_analysis_reasons

        # 生成建议
        result['recommendations'] = self._generate_recommendations(result)

        return result

    def _parse_url(self, url: str) -> Dict:
        """解析 URL 组件"""
        # 添加协议（如果没有）
        if not url.startswith(('http://', 'https://', 'ftp://')):
            url = 'http://' + url

        parsed = urlparse(url)

        domain = parsed.netloc
        port = None

        # 提取端口
        if ':' in domain:
            parts = domain.rsplit(':', 1)
            domain = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        # 检查是否是 IP
        is_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', domain))

        # 提取 TLD
        tld = ''
        if not is_ip and '.' in domain:
            tld = domain.rsplit('.', 1)[-1]

        return {
            'scheme': parsed.scheme,
            'domain': domain,
            'port': port,
            'path': parsed.path,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'params': parse_qs(parsed.query),
            'tld': tld,
            'is_ip': is_ip,
            'full_url': url,
        }

    def _defang_url(self, url: str) -> str:
        """URL 脱敏"""
        url = url.replace('http://', 'hxxp://')
        url = url.replace('https://', 'hxxps://')
        url = url.replace('.', '[.]')
        return url

    def _is_short_url(self, domain: str) -> bool:
        """检查是否是短链接"""
        return domain.lower() in self.SHORT_URL_DOMAINS

    def _detect_phishing(self, url: str, components: Dict) -> List[str]:
        """检测钓鱼特征"""
        indicators = []
        url_lower = url.lower()
        path = components.get('path', '').lower()

        # 检查路径中的钓鱼关键词
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in path:
                indicators.append(f"路径包含敏感关键词: {keyword}")
                break

        # 检查参数
        params = components.get('params', {})
        sensitive_params = {'password', 'passwd', 'pwd', 'card', 'ssn', 'pin', 'token', 'secret'}
        for param in params:
            if param.lower() in sensitive_params:
                indicators.append(f"包含敏感参数: {param}")

        # 检查 URL 长度
        if len(url) > 200:
            indicators.append("URL 过长 - 可能隐藏真实目标")

        # 检查多重子域名
        domain = components.get('domain', '')
        if domain.count('.') > 3:
            indicators.append("多重子域名 - 可能仿冒")

        # 检查 @ 符号 (用户信息欺骗)
        if '@' in url:
            indicators.append("URL 包含 @ 符号 - 可能欺骗用户")

        # 检查数据 URI
        if url.lower().startswith('data:'):
            indicators.append("Data URI - 可能包含恶意内容")

        return indicators

    def _detect_brand_impersonation_enhanced(self, domain: str) -> Optional[Dict]:
        """增强版品牌仿冒检测"""
        domain_lower = domain.lower()

        for brand, official_domains in self.KNOWN_BRANDS.items():
            # 检查是否是官方域名
            is_official = any(
                domain_lower == od or domain_lower.endswith('.' + od)
                for od in official_domains
            )

            if is_official:
                continue

            # 检查是否包含品牌名
            if brand in domain_lower:
                # 检测仿冒模式
                patterns = self._get_impersonation_patterns(brand, domain_lower)
                if patterns:
                    return {
                        'brand': brand,
                        'description': f"疑似仿冒品牌: {brand} ({', '.join(patterns)})",
                        'score': 35,
                        'patterns': patterns,
                    }

        return None

    def _get_impersonation_patterns(self, brand: str, domain: str) -> List[str]:
        """获取仿冒模式"""
        patterns = []

        # 品牌名在子域名中
        if domain.startswith(brand + '.') or domain.startswith(brand + '-'):
            patterns.append('子域名仿冒')

        # 品牌名后缀变体
        if re.search(rf'{brand}[0-9]+', domain):
            patterns.append('数字后缀')

        if re.search(rf'{brand}[-_](login|secure|verify|update)', domain):
            patterns.append('钓鱼关键词组合')

        # 拼写变体
        typo_patterns = [
            (brand, brand[:-1]),  # 少一个字母
            (brand, brand + brand[-1]),  # 多一个字母
        ]
        for orig, typo in typo_patterns:
            if typo in domain and orig not in domain:
                patterns.append('拼写变体')
                break

        # 默认：包含品牌名就是可疑的
        if not patterns and brand in domain:
            patterns.append('包含品牌名')

        return patterns

    def _detect_file_download(self, components: Dict) -> Optional[Dict]:
        """检测文件下载"""
        path = components.get('path', '')

        if '.' in path:
            ext = path.rsplit('.', 1)[-1].lower()
            # 过滤掉常见的网页扩展名
            if ext and ext not in ('html', 'htm', 'php', 'asp', 'aspx', 'jsp'):
                return {
                    'extension': ext,
                    'is_malicious_type': ext in self.MALICIOUS_EXTENSIONS,
                    'path': path,
                }

        return None

    def _calculate_risk_level(self, score: int) -> str:
        """计算风险等级"""
        if score >= 61:
            return 'critical'
        elif score >= 41:
            return 'high'
        elif score >= 21:
            return 'medium'
        else:
            return 'low'

    def _generate_deep_analysis_reasons(self, result: Dict) -> List[str]:
        """生成深度分析升级原因"""
        reasons = []

        risk_score = result.get('risk_score', 0)
        risk_level = result.get('risk_level', 'low')
        if risk_level in ('high', 'critical'):
            reasons.append(f"风险等级为 {risk_level}（评分: {risk_score}）")

        chain = result.get('redirect_chain_analysis') or {}
        if chain.get('cross_domain_redirects', 0) >= 2:
            reasons.append(f"存在多次跨域跳转（{chain.get('cross_domain_redirects', 0)} 次）")
        if chain.get('js_redirects', 0) > 0:
            reasons.append(f"检测到 JS 跳转（{chain.get('js_redirects', 0)} 次）")

        phishing = result.get('phishing_detection') or {}
        if phishing.get('is_phishing'):
            phishing_type = phishing.get('phishing_type') or 'unknown'
            reasons.append(f"页面内容命中钓鱼检测（类型: {phishing_type}）")

        evasion = result.get('evasion_analysis') or {}
        if evasion.get('evasion_complexity') in ('high', 'very_high'):
            reasons.append(f"检测到较高复杂度规避技术（{evasion.get('evasion_complexity')}）")

        attribution = result.get('attribution') or {}
        if attribution.get('has_attribution'):
            reasons.append(f"已归因到疑似黑产组织 {attribution.get('actor_name', 'unknown')}")

        expansion = result.get('expansion_suggestions') or {}
        if expansion.get('enabled') and expansion.get('trigger_reason'):
            reasons.append(f"建议执行威胁扩线：{expansion.get('trigger_reason')}")

        deduped = []
        seen = set()
        for reason in reasons:
            if reason and reason not in seen:
                deduped.append(reason)
                seen.add(reason)

        return deduped

    def _generate_recommendations(self, result: Dict) -> List[str]:
        """生成处置建议"""
        recommendations = []
        risk_level = result['risk_level']

        if risk_level == 'critical':
            recommendations.append("立即阻断该 URL")
            recommendations.append("检查是否有用户访问过")
            recommendations.append("如有访问，通知用户检查账户安全")
        elif risk_level == 'high':
            recommendations.append("建议阻断该 URL")
            recommendations.append("检查代理日志中的访问记录")
        elif risk_level == 'medium':
            recommendations.append("加入监控列表")
            recommendations.append("确认是否有业务需求")
        else:
            recommendations.append("风险较低，可持续监控")

        if result.get('is_short_url'):
            recommendations.append("建议展开短链接查看真实目标")

        if (result.get('file_download') or {}).get('is_malicious_type'):
            recommendations.append("如有下载，使用沙箱分析文件")

        # 同形字攻击建议
        homoglyph = result.get('homoglyph_analysis', {})
        if homoglyph.get('has_homoglyphs'):
            recommendations.append(f"检测到同形字，标准化域名: {homoglyph.get('normalized_domain')}")
            if homoglyph.get('possible_target'):
                recommendations.append(f"可能仿冒 {homoglyph['possible_target']}，建议阻断")

        # 规避技术建议
        evasion = result.get('evasion_analysis') or {}
        if evasion.get('evasion_complexity') in ('high', 'very_high'):
            recommendations.append("检测到高级规避技术，建议深度分析")

        # DOM 噪音建议
        dom_noise = evasion.get('dom_noise', {})
        if dom_noise.get('severity') in ('high', 'severe'):
            recommendations.append(f"检测到 DOM 噪音注入 ({dom_noise.get('hidden_chinese_words', 0)} 个隐藏词)，确认为对抗检测")

        # 钓鱼检测建议
        phishing = result.get('phishing_detection') or {}
        if phishing.get('is_phishing'):
            phishing_type = phishing.get('phishing_type', '')
            if phishing_type == 'financial':
                recommendations.append("[!] 金融诈骗钓鱼！检查是否有用户提交了银行卡/身份信息")
            elif phishing_type == 'credential':
                recommendations.append("检测到凭证钓鱼，如有用户访问建议修改密码")

            if phishing.get('sensitive_fields'):
                fields = phishing['sensitive_fields'][:5]
                recommendations.append(f"该页面收集敏感信息: {', '.join(fields)}")

        # 跳转链建议
        chain = result.get('redirect_chain_analysis') or {}
        if chain.get('cross_domain_redirects', 0) >= 2:
            recommendations.append(f"多次跨域跳转，最终域名: {chain.get('final_domain')}")

        return recommendations


def generate_expansion_suggestions(analysis_result: dict) -> dict:
    """
    生成威胁扩线建议 (Phase 11)

    Args:
        analysis_result: URL 分析结果字典

    Returns:
        扩线建议字典，格式：
        {
            "enabled": bool,  # 是否建议扩线
            "trigger_reason": str,  # 触发原因
            "suggestions": [
                {
                    "dimension": str,  # 扩线维度：ip/cert/title/domain
                    "query": str,  # FOFA 查询语句
                    "indicator": str,  # 指标值
                    "priority": str  # 优先级：high/medium/low
                }
            ]
        }
    """
    risk_score = analysis_result.get("risk_score", 0)
    suggestions = {
        "enabled": False,
        "trigger_reason": "",
        "suggestions": []
    }

    # 触发条件：风险评分 >= 60
    if risk_score < 60:
        return suggestions

    suggestions["enabled"] = True
    suggestions["trigger_reason"] = f"风险评分 {risk_score} >= 60，建议进行威胁扩线"

    # 1. 提取 IP 地址（从 DNS 历史、HTTP 响应等）
    ips = set()

    # 从 HTTP 响应中提取
    fetch_info = analysis_result.get("fetch_info")
    if fetch_info and fetch_info.get("fetched"):
        # 注意：实际的 IP 地址需要从 MCP dns_history 获取
        # 这里我们提取域名作为占位，Claude 调用 dns_history 后会获得真实 IP
        pass

    # 从关联 IOCs 中提取 IP
    related_iocs = analysis_result.get("related_iocs", {})
    if related_iocs.get("ips"):
        ips.update(related_iocs["ips"])

    # 为每个 IP 创建扩线建议
    for ip in ips:
        suggestions["suggestions"].append({
            "dimension": "ip",
            "query": f'ip="{ip}"',
            "indicator": ip,
            "priority": "high"
        })

    # 2. 提取证书指纹（如果有 SSL 信息）
    # 注意：当前版本未实现证书提取，这里提供接口预留
    # Claude 可以从 MCP 调用结果中获取证书信息后手动添加

    # 3. 提取页面标题（如果检测到钓鱼）
    phishing = analysis_result.get("phishing_detection") or {}
    fetch_info = analysis_result.get("fetch_info") or {}
    if phishing.get("is_phishing") and fetch_info.get("title"):
        title = fetch_info["title"]
        if title and len(title) > 3:  # 标题需要有意义
            # 转义标题中的双引号，避免破坏 FOFA 查询语法
            escaped_title = title.replace('"', '\\"')
            suggestions["suggestions"].append({
                "dimension": "title",
                "query": f'title="{escaped_title}"',
                "indicator": title,
                "priority": "medium"
            })

    # 4. 提取域名关键词（如果是仿冒域名）
    components = analysis_result.get("components", {})
    domain = components.get("domain", "")
    if domain and phishing.get("impersonated_brands"):
        # 提取域名主体部分
        domain_base = domain.split(".")[0] if "." in domain else domain
        if len(domain_base) > 2:  # 避免过短的关键词
            suggestions["suggestions"].append({
                "dimension": "domain",
                "query": f'domain="*{domain_base}*"',
                "indicator": domain_base,
                "priority": "low"
            })

    # 5. 如果没有提取到任何 IOC，至少提取原始域名
    if not suggestions["suggestions"] and domain and not components.get("is_ip"):
        suggestions["suggestions"].append({
            "dimension": "domain",
            "query": f'domain="{domain}"',
            "indicator": domain,
            "priority": "medium"
        })

    return suggestions


def _escape_md_table(text: str) -> str:
    """转义 Markdown 表格中的特殊字符"""
    if not text:
        return ''
    # 使用 Unicode 全角竖线 ｜ (U+FF5C) 替代半角 | 字符
    # 原因：
    # - 反斜杠转义 \| 在某些渲染器中不起作用
    # - HTML 实体 &#124; 在某些渲染器中会先解析表格结构再处理实体，仍会破坏表格
    # - 全角竖线视觉上与半角几乎一致，且不会被识别为表格分隔符
    # 同时处理换行符，替换为空格
    return str(text).replace('|', '｜').replace('\n', ' ').replace('\r', '')


def format_result(result: Dict, output_format: str = 'text') -> str:
    """格式化输出（默认输出快速分析报告）"""
    if output_format == 'json':
        return json.dumps(result, ensure_ascii=False, indent=2)

    risk_display = {
        'critical': '[!] Critical',
        'high': '[!] High',
        'medium': '[*] Medium',
        'low': '[+] Low',
    }
    risk_marker = {'critical': '[!]', 'high': '[!]', 'medium': '[*]', 'low': '[+]'}
    esc = _escape_md_table

    lines = []

    lines.append(f"# {risk_marker.get(result.get('risk_level'), '[-]')} URL 威胁分析报告")
    lines.append("")
    lines.append(f"**威胁等级**: {risk_display.get(result.get('risk_level'), result.get('risk_level'))} (评分: {result.get('risk_score', 0)})")
    lines.append(f"**分析时间**: {result.get('analysis_time', 'N/A')}")
    lines.append("**分析模式**: 快速分析")
    lines.append("---")

    comp = result.get('components') or {}
    fetch_info = result.get('fetch_info') or {}
    original_url = result.get('url', '')
    final_url = result.get('final_url') or fetch_info.get('final_url') or '未获取'
    domain_or_ip = comp.get('domain') or '未解析'
    port = comp.get('port') or (443 if comp.get('scheme') == 'https' else 80 if comp.get('scheme') == 'http' else '未识别')
    path = comp.get('path') or '/'
    if fetch_info.get('fetched'):
        content_status = '已获取'
    elif result.get('phishing_detection') or result.get('evasion_analysis'):
        content_status = '使用本地 HTML'
    else:
        content_status = '未获取'

    whois = result.get('domain_whois') or {}
    if comp.get('is_ip'):
        domain_analysis_status = 'IP 地址无需 WHOIS 查询'
    elif whois.get('status') == 'ACTION_REQUIRED':
        domain_analysis_status = '必须调用（非 IP URL）'
    else:
        domain_analysis_status = '已整合或待补充'

    lines.append("## 1. URL 基础信息")
    lines.append(f"- **原始 URL**: {original_url}")
    lines.append(f"- **脱敏 URL**: {result.get('defanged_url') or '未生成'}")
    lines.append(f"- **协议**: {comp.get('scheme') or '未识别'}")
    lines.append(f"- **域名 / IP**: {domain_or_ip}")
    lines.append(f"- **端口**: {port}")
    lines.append(f"- **路径**: {path}")
    lines.append(f"- **内容获取**: {content_status}")
    lines.append(f"- **最终 URL**: {final_url}")
    lines.append(f"- **domain-analysis**: {domain_analysis_status}")
    lines.append("---")

    redirect_chain = result.get('redirect_chain') or []
    redirect_analysis = result.get('redirect_chain_analysis') or {}
    phishing = result.get('phishing_detection') or {}
    evasion = result.get('evasion_analysis') or {}
    threat_intel = result.get('threat_intel') or {}

    static_findings = []
    for factor in result.get('risk_factors', []):
        factor_name = factor.get('factor', '')
        if factor_name in {
            'high_risk_tld', 'ip_direct', 'non_standard_port', 'short_url',
            'homoglyph_attack', 'mixed_scripts', 'phishing', 'brand_impersonation',
            'malicious_file'
        }:
            static_findings.append(factor.get('description', ''))

    static_status = '已检测（发现风险）' if static_findings else '已检测（未发现风险）'
    static_summary = '；'.join(static_findings[:4]) if static_findings else '未见高风险 TLD、IP 直连、非标准端口、同形字等异常'

    if redirect_chain or redirect_analysis:
        redirect_risks = [rf.get('description', '') for rf in redirect_analysis.get('risk_factors', []) if rf.get('description')]
        redirect_status = '已检测（发现风险）' if redirect_risks else '已检测（未发现风险）'
        redirect_summary = '；'.join(redirect_risks[:3]) if redirect_risks else '未见明显异常跳转'
    else:
        redirect_status = '未执行'
        redirect_summary = '未获取页面内容或未启用跳转分析'

    if phishing:
        if phishing.get('is_phishing'):
            phishing_status = '已检测（发现风险）'
            phishing_parts = []
            if phishing.get('impersonated_brands'):
                phishing_parts.append(f"品牌仿冒: {', '.join(phishing.get('impersonated_brands', [])[:3])}")
            if phishing.get('sensitive_fields'):
                phishing_parts.append(f"敏感字段: {', '.join(phishing.get('sensitive_fields', [])[:5])}")
            if phishing.get('scam_keywords'):
                phishing_parts.append(f"诈骗关键词: {', '.join(phishing.get('scam_keywords', [])[:3])}")
            phishing_summary = '；'.join(phishing_parts) if phishing_parts else '页面内容命中钓鱼检测'
        elif phishing.get('status') in ('error', 'unavailable'):
            phishing_status = '未执行'
            phishing_summary = phishing.get('error') or phishing.get('reason') or '钓鱼检测不可用'
        else:
            phishing_status = '已检测（未发现风险）'
            phishing_summary = '未见品牌仿冒、敏感字段或诈骗关键词'
    else:
        phishing_status = '未执行'
        phishing_summary = '未提供 HTML 内容'

    if evasion:
        if evasion.get('status') in ('error', 'unavailable'):
            evasion_status = '未执行'
            evasion_summary = evasion.get('error') or evasion.get('reason') or '规避技术检测不可用'
        elif evasion.get('total_techniques', 0) > 0 or evasion.get('anti_detection_score', 0) > 0:
            evasion_status = '已检测（发现风险）'
            evasion_parts = []
            if evasion.get('evasion_complexity'):
                evasion_parts.append(f"复杂度: {evasion.get('evasion_complexity')}")
            if evasion.get('detected_techniques'):
                evasion_parts.append(f"技术: {', '.join(evasion.get('detected_techniques', [])[:3])}")
            evasion_summary = '；'.join(evasion_parts) if evasion_parts else '检测到规避技术'
        else:
            evasion_status = '已检测（未发现风险）'
            evasion_summary = '未见 DOM 噪音、CSS 隐藏等规避技术'
    else:
        evasion_status = '未执行'
        evasion_summary = '未提供 HTML 内容'

    intel_status = '已查询' if threat_intel and threat_intel.get('status') not in ('pending', None) else '待查询'
    intel_summary = threat_intel.get('message') or '标签 / 检测率 / 最近活动待补充'

    lines.append("## 2. 核心风险发现")
    lines.append("| 检测项 | 状态 | 说明 |")
    lines.append("|------|------|------|")
    lines.append(f"| URL 静态特征 | {esc(static_status)} | {esc(static_summary)} |")
    lines.append(f"| 跳转分析 | {esc(redirect_status)} | {esc(redirect_summary)} |")
    lines.append(f"| 钓鱼内容检测 | {esc(phishing_status)} | {esc(phishing_summary)} |")
    lines.append(f"| 规避技术检测 | {esc(evasion_status)} | {esc(evasion_summary)} |")
    lines.append(f"| URL 威胁情报 | {esc(intel_status)} | {esc(intel_summary)} |")
    lines.append("")
    lines.append(f"**深度分析建议**: {'是' if result.get('deep_analysis_recommended') else '否'}")
    lines.append("")
    lines.append("**升级原因**:")
    deep_reasons = result.get('deep_analysis_reasons') or []
    if deep_reasons:
        for reason in deep_reasons:
            lines.append(f"- {reason}")
    else:
        lines.append("- 当前快速分析未给出明确升级信号")
    lines.append("---")

    threat_type = '未见明显风险'
    if phishing.get('is_phishing'):
        threat_type = '钓鱼 URL'
    elif (result.get('file_download') or {}).get('is_malicious_type'):
        threat_type = '恶意下载 URL'
    elif result.get('risk_level') in ('medium', 'high', 'critical'):
        threat_type = '可疑 URL'

    risk_level_map = {
        'low': '低',
        'medium': '中',
        'high': '高',
        'critical': '严重',
    }

    lines.append("## 3. 结论与处置建议")
    lines.append(f"**威胁类型**: {threat_type}")
    lines.append(f"**风险等级**: {risk_level_map.get(result.get('risk_level'), result.get('risk_level'))}")
    lines.append("")
    lines.append("**处置建议**:")
    recommendations = result.get('recommendations') or []
    if recommendations:
        for idx, rec in enumerate(recommendations, 1):
            lines.append(f"{idx}. {rec}")
    else:
        lines.append("1. [+] 持续监控 / 核实业务用途")
    lines.append("---")

    related_iocs = result.get('related_iocs') or {}
    domain_ioc = domain_or_ip if domain_or_ip else '未发现'
    ip_ioc = ', '.join(related_iocs.get('ips', [])) if related_iocs.get('ips') else ('未发现' if not comp.get('is_ip') else domain_or_ip)
    hashes = ', '.join(related_iocs.get('hashes', [])) if related_iocs.get('hashes') else '未发现'

    lines.append("## 4. IOC 汇总")
    lines.append(f"**URL**: {original_url}")
    lines.append(f"**域名**: {domain_ioc}")
    lines.append(f"**IP**: {ip_ioc}")
    lines.append(f"**最终跳转目标**: {final_url}")
    lines.append(f"**关联文件 / 哈希**: {hashes}")
    lines.append("---")

    lines.append("## 5. 分析局限性")
    lines.append("- 未进行页面截图")
    lines.append("- 未执行 DNS 历史查询")
    lines.append("- 未执行 WebSearch 归因增强")
    lines.append("- 未执行威胁扩线")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='URL 综合威胁分析工具 (增强版)',
        epilog='''
环境变量配置（优先级低于命令行参数）：
  URL_ANALYSIS_TIMEOUT       超时时间（秒），默认 30
  URL_ANALYSIS_MAX_REDIRECTS 最大重定向次数，默认 10
  URL_ANALYSIS_USER_AGENT    User-Agent 类型，默认 chrome
  URL_ANALYSIS_VERIFY_SSL    是否验证 SSL（true/false），默认 false
''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('url', nargs='?', help='要分析的 URL')
    parser.add_argument('-f', '--file', help='从文件读取 URL 列表')
    parser.add_argument('-o', '--output', choices=['text', 'json'], default='text')
    parser.add_argument('--follow', action='store_true', help='追踪重定向')
    parser.add_argument('--html', help='HTML 文件路径，用于规避技术检测')
    parser.add_argument('--fetch', action='store_true', help='自动获取 URL 内容并分析')
    parser.add_argument('--timeout', type=int, default=None,
                        help=f'获取超时时间(秒)，默认 {DEFAULT_TIMEOUT}')

    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    html_content = None
    fetch_result = None

    # 自动获取内容
    if args.fetch:
        try:
            from url_fetcher import URLFetcher
            fetcher = URLFetcher(timeout=args.timeout)
            fetch_result = fetcher.fetch(args.url)
            if fetch_result.success and fetch_result.html_content:
                html_content = fetch_result.html_content
                if args.output != 'json':
                    print(f"[*] 已获取内容，最终 URL: {fetch_result.final_url}", file=sys.stderr)
                    if fetch_result.total_redirects > 0:
                        print(f"[*] 检测到 {fetch_result.total_redirects} 次跳转", file=sys.stderr)
        except ImportError:
            print("警告: 无法导入 url_fetcher，需要安装 requests: pip install requests", file=sys.stderr)
        except Exception as e:
            print(f"警告: 获取内容失败: {e}", file=sys.stderr)

    # 从文件读取 HTML
    if args.html and not html_content:
        try:
            with open(args.html, 'r', encoding='utf-8') as f:
                html_content = f.read()
        except Exception as e:
            print(f"警告: 无法读取 HTML 文件: {e}", file=sys.stderr)

    analyzer = URLAnalyzer(follow_redirects=args.follow)

    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip()]

        results = [analyzer.analyze(url, html_content, fetch_result) for url in urls]

        if args.output == 'json':
            print(json.dumps(results, ensure_ascii=False, indent=2))
        else:
            for result in results:
                print(format_result(result, args.output))
                print()
    else:
        result = analyzer.analyze(args.url, html_content, fetch_result)
        print(format_result(result, args.output))

        # 输出生成的文件路径（供后端检测）
        if args.output == 'json':
            # JSON 模式下，文件路径已包含在 result 中
            pass
        else:
            # 文本模式下，输出文件生成标记
            # 注意：这里是示例，实际需要在生成文件后输出
            # 例如：如果生成了截图或报告文件
            # print(f"\n[FILE_GENERATED] /path/to/screenshot.png")
            # print(f"[FILE_GENERATED] /path/to/report.json")
            pass

        if result['risk_level'] in ('critical', 'high'):
            sys.exit(2)
        elif result['risk_level'] == 'medium':
            sys.exit(1)


if __name__ == '__main__':
    main()
