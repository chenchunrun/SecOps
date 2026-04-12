#!/usr/bin/env python3
"""
黑产组织归因模块
基于域名特征、基础设施、页面特征识别国内主要黑产组织

支持的组织:
- UTG-Q-1000 (银狐/游蛇/谷堕大盗)
- APT-Q-27 (金眼狗/GoldenEyeDog)
- 缅北魔方G
- Smishing Triad (短信钓鱼三合会)
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs


@dataclass
class ThreatActorMatch:
    """威胁组织匹配结果"""
    actor_id: str  # 组织标识
    actor_name: str  # 组织名称
    aliases: List[str]  # 别名
    confidence: int  # 置信度 0-100
    matched_indicators: List[Dict]  # 匹配的指标
    ttps: List[str]  # 战术技术程序
    targets: List[str]  # 典型目标
    description: str  # 组织描述
    references: List[str]  # 参考链接


@dataclass
class WebSearchSuggestion:
    """WebSearch 搜索建议"""
    search_type: str  # domain_report, ip_report, actor_activity
    query: str  # 搜索查询语句
    purpose: str  # 搜索目的说明
    priority: str  # high, medium, low


@dataclass
class AttributionResult:
    """归因分析结果"""
    has_attribution: bool = False
    primary_actor: Optional[ThreatActorMatch] = None
    secondary_actors: List[ThreatActorMatch] = field(default_factory=list)
    attribution_score: int = 0
    indicators_summary: Dict = field(default_factory=dict)
    # WebSearch 增强
    websearch_enabled: bool = False
    websearch_trigger_reason: str = ""
    websearch_suggestions: List[WebSearchSuggestion] = field(default_factory=list)


class ThreatActorDatabase:
    """黑产组织知识库"""

    ACTORS = {
        'UTG-Q-1000': {
            'name': '银狐/游蛇',
            'aliases': ['银狐', '游蛇', '谷堕大盗', 'SwimSnake', 'SilverFox', '树狼', 'UTG-Q-1000'],
            'description': '国内最活跃的黑产组织之一，主要针对财务人员和企业管理人员，通过仿冒软件下载站、钓鱼邮件传播远控木马',
            'targets': ['财务人员', '企业管理人员', '电商客服', '设计人员'],
            'ttps': [
                'T1566.002 - 钓鱼链接',
                'T1204.002 - 恶意文件执行',
                'T1036 - 伪装',
                'T1574.002 - DLL侧加载(白加黑)',
                'T1059.001 - PowerShell',
                'T1027 - 混淆文件/信息',
            ],
            'references': [
                'https://www.antiy.cn/research/notice&report/research_report/SwimSnakeTrojans_Analysis.html',
                'https://tix.qq.com/sliverFoxDetail',
            ],
            # 域名特征
            'domain_patterns': [
                # 仿冒软件下载站
                r'(?i)(wps|office|finalshell|xshell|navicat|chrome|firefox)[-_]?(cn|zh|download|setup)?',
                r'(?i)(todesk|teamviewer|anydesk|sunlogin)[-_]?(cn|download)?',
                r'(?i)(flash|adobe|pdf)[-_]?(player|reader|cn)?',
                # 随机字符短域名
                r'^[a-z]{4,8}\d{2,6}$',  # 如 msgcj, lpbpgywtkr
                # 含数字后缀
                r'[a-z]+\d{4,}$',
            ],
            # TLD 特征
            'preferred_tlds': ['cn', 'xyz', 'top', 'cc', 'com'],
            # URL 参数特征
            'url_param_patterns': [
                r'member=[a-z0-9]+',  # 会员追踪
                r'(from|source|channel)=',  # 渠道追踪
            ],
            # 页面特征
            'page_indicators': [
                '立即下载', '免费下载', 'Windows版下载', 'Mac版下载',
                '官方正版', '绿色免安装', '破解版',
            ],
            # 基础设施
            'infrastructure': {
                'hosting': ['阿里云 OSS', '腾讯云 COS', '有道云笔记'],
                'oss_patterns': [
                    r'\.oss-cn-[a-z]+\.aliyuncs\.com',
                    r'\.cos\.ap-[a-z]+\.myqcloud\.com',
                ],
            },
            # 钓鱼主题
            'phishing_themes': [
                '税务稽查', '电子发票', '补贴公告', '人事调动',
                '工资补贴', '育儿补贴', '社保认证',
            ],
        },

        'APT-Q-27': {
            'name': '金眼狗',
            'aliases': ['金眼狗', 'GoldenEyeDog', 'APT-Q-27', 'Dragon Breath'],
            'description': '针对东南亚博彩行业、海外华人群体的黑客团伙，业务涵盖远控、挖矿、DDoS',
            'targets': ['博彩行业', '海外华人', 'Telegram用户', '加密货币用户'],
            'ttps': [
                'T1566.002 - 钓鱼链接',
                'T1204.002 - 恶意文件执行',
                'T1036 - 伪装',
                'T1574.002 - DLL侧加载',
                'T1059.005 - Visual Basic',
                'T1112 - 修改注册表',
            ],
            'references': [
                'https://ti.qianxin.com/blog/articles/operation-dragon-breath-(apt-q-27)-dimensionality-reduction-blow-to-the-gambling-industry/',
            ],
            'domain_patterns': [
                r'(?i)telegram[-_]?(zh|cn|chinese|中文)?',
                r'(?i)(potato|signal|whatsapp)[-_]?(cn|download)?',
                r'(?i)tele[-_]?gram',
                r'(?i)纸飞机',
                # 博彩相关
                r'(?i)(bet|casino|lottery|game)[-_]?\d*',
            ],
            'preferred_tlds': ['com', 'xyz', 'cc', 'net'],
            'url_param_patterns': [],
            'page_indicators': [
                'Telegram', '中文版', '语言包', '纸飞机',
                '即时通讯', '加密聊天', '博彩', '棋牌',
            ],
            'infrastructure': {
                'hosting': [],
                'c2_ports': [1445, 1446, 6688, 5780],
            },
            'phishing_themes': [
                'Telegram中文版', '聊天软件', '语言包安装',
            ],
        },

        'MOFANG-G': {
            'name': '缅北魔方G',
            'aliases': ['缅北魔方G', '魔方G', 'Mofang-G'],
            'description': '位于缅北的黑灰产团伙，主要通过钓鱼邮件和短信针对企业员工进行金融诈骗',
            'targets': ['企业财务人员', '普通员工'],
            'ttps': [
                'T1566.001 - 钓鱼附件',
                'T1566.002 - 钓鱼链接',
                'T1598.003 - 钓鱼获取信息',
            ],
            'references': [
                'https://www.anquanke.com/post/id/279371',
            ],
            'domain_patterns': [
                r'site\d+\.g[a-z]+\.r[a-z]+',  # site01.g*.r* 中转域名模式
                # 补贴/社保主题
                r'(?i)(butie|subsidy|shebao|yibao|etc)[-_]?',
                r'(?i)(gongzi|salary|buzhu)[-_]?',
            ],
            'preferred_tlds': ['xyz', 'uho', 'com', 'cn'],
            'url_param_patterns': [],
            'page_indicators': [
                '工资补贴', '社保认证', 'ETC', '医保',
                '补贴申领', '实名认证', '银行认证',
            ],
            'infrastructure': {
                'cname_pattern': r'site\d+\.g[a-z]+\.r[a-z]+',
            },
            'phishing_themes': [
                '工资补贴通知', 'ETC欠费', '社保认证', '医保服务',
            ],
        },

        'SMISHING-TRIAD': {
            'name': '短信钓鱼三合会',
            'aliases': ['Smishing Triad', '短信钓鱼联盟'],
            'description': '专注于短信钓鱼(Smishing)的黑产组织，使用PhaaS模式，主要托管在国内云服务商',
            'targets': ['普通用户', '银行客户', '快递用户'],
            'ttps': [
                'T1566.002 - 钓鱼链接',
                'T1598.003 - 钓鱼获取信息',
                'T1583.001 - 获取域名',
            ],
            'references': [],
            'domain_patterns': [
                # 短域名、随机字符
                r'^[a-z]{3,5}\d{1,3}$',
                # 仿冒快递
                r'(?i)(sf|ems|yd|zt|yto)[-_]?(express|kuaidi)?',
                # 仿冒银行
                r'(?i)(icbc|ccb|abc|boc|cmb)[-_]?(bank|cn)?',
            ],
            'preferred_tlds': ['cc', 'xyz', 'top', 'icu'],
            'url_param_patterns': [],
            'page_indicators': [
                '快递', '包裹', '签收', '银行',
                '验证', '认证', '解冻', '异常',
            ],
            'infrastructure': {
                'hosting': ['腾讯云 (AS132203)', '阿里云 (AS45102)'],
            },
            'phishing_themes': [
                '快递签收', '包裹异常', '银行卡异常', '账户冻结',
            ],
        },
    }


class ThreatActorAttributor:
    """黑产组织归因分析器"""

    def __init__(self):
        self.db = ThreatActorDatabase()

    def analyze(self,
                url: str,
                domain: str = "",
                html_content: str = "",
                page_title: str = "",
                phishing_detection: Dict = None,
                evasion_analysis: Dict = None,
                dns_info: Dict = None) -> AttributionResult:
        """
        执行归因分析

        Args:
            url: 待分析的 URL
            domain: 域名
            html_content: HTML 内容
            page_title: 页面标题
            phishing_detection: 钓鱼检测结果
            evasion_analysis: 规避技术检测结果
            dns_info: DNS 信息

        Returns:
            AttributionResult: 归因结果
        """
        result = AttributionResult()
        actor_scores: Dict[str, Dict] = {}

        # 解析 URL
        if not domain:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                if ':' in domain:
                    domain = domain.split(':')[0]
            except:
                pass

        # 提取 TLD
        tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''

        # 提取 URL 参数
        try:
            parsed = urlparse(url)
            query_string = parsed.query
        except:
            query_string = ''

        # 对每个已知组织进行匹配
        for actor_id, actor_info in self.db.ACTORS.items():
            matches = []
            score = 0

            # 1. 域名模式匹配
            domain_score, domain_matches = self._match_domain_patterns(
                domain, actor_info.get('domain_patterns', [])
            )
            score += domain_score
            matches.extend(domain_matches)

            # 2. TLD 匹配
            if tld in actor_info.get('preferred_tlds', []):
                score += 5
                matches.append({
                    'type': 'tld',
                    'indicator': tld,
                    'description': f'使用该组织偏好的 TLD: .{tld}',
                    'score': 5
                })

            # 3. URL 参数匹配
            param_score, param_matches = self._match_url_params(
                query_string, actor_info.get('url_param_patterns', [])
            )
            score += param_score
            matches.extend(param_matches)

            # 4. 页面内容匹配
            if html_content:
                content_score, content_matches = self._match_page_content(
                    html_content, actor_info.get('page_indicators', [])
                )
                score += content_score
                matches.extend(content_matches)

            # 5. 钓鱼主题匹配
            if html_content or page_title:
                theme_score, theme_matches = self._match_phishing_themes(
                    html_content + ' ' + (page_title or ''),
                    actor_info.get('phishing_themes', [])
                )
                score += theme_score
                matches.extend(theme_matches)

            # 6. 基础设施匹配
            infra_score, infra_matches = self._match_infrastructure(
                url, html_content, actor_info.get('infrastructure', {})
            )
            score += infra_score
            matches.extend(infra_matches)

            # 7. 如果有钓鱼检测结果，进行交叉验证
            if phishing_detection:
                cross_score = self._cross_validate_phishing(
                    phishing_detection, actor_info
                )
                if cross_score > 0:
                    score += cross_score
                    matches.append({
                        'type': 'cross_validation',
                        'indicator': 'phishing_detection',
                        'description': '钓鱼检测结果与组织特征匹配',
                        'score': cross_score
                    })

            # 记录得分
            if score > 0:
                actor_scores[actor_id] = {
                    'score': score,
                    'matches': matches,
                    'info': actor_info
                }

        # 确定主要归因
        if actor_scores:
            # 按得分排序
            sorted_actors = sorted(
                actor_scores.items(),
                key=lambda x: x[1]['score'],
                reverse=True
            )

            # 主要归因（得分最高）
            primary_id, primary_data = sorted_actors[0]
            if primary_data['score'] >= 15:  # 最低置信度阈值
                result.has_attribution = True
                result.primary_actor = self._create_actor_match(
                    primary_id, primary_data
                )
                result.attribution_score = primary_data['score']

            # 次要归因（其他可能的组织）
            for actor_id, actor_data in sorted_actors[1:]:
                if actor_data['score'] >= 10:
                    result.secondary_actors.append(
                        self._create_actor_match(actor_id, actor_data)
                    )

        # 汇总指标
        result.indicators_summary = self._summarize_indicators(result)

        # 生成 WebSearch 增强建议
        self._generate_websearch_suggestions(result, url, domain)

        return result

    def _match_domain_patterns(self, domain: str, patterns: List[str]) -> Tuple[int, List[Dict]]:
        """匹配域名模式"""
        score = 0
        matches = []

        domain_lower = domain.lower()
        # 提取主域名部分（去掉TLD）
        domain_base = domain_lower.rsplit('.', 1)[0] if '.' in domain_lower else domain_lower

        for pattern in patterns:
            try:
                if re.search(pattern, domain_lower) or re.search(pattern, domain_base):
                    score += 20
                    matches.append({
                        'type': 'domain_pattern',
                        'indicator': domain,
                        'pattern': pattern,
                        'description': f'域名匹配模式: {pattern}',
                        'score': 20
                    })
                    break  # 每个域名只匹配一次
            except re.error:
                continue

        return score, matches

    def _match_url_params(self, query_string: str, patterns: List[str]) -> Tuple[int, List[Dict]]:
        """匹配 URL 参数"""
        score = 0
        matches = []

        for pattern in patterns:
            try:
                match = re.search(pattern, query_string)
                if match:
                    score += 15
                    matches.append({
                        'type': 'url_param',
                        'indicator': match.group(),
                        'pattern': pattern,
                        'description': f'URL参数匹配: {match.group()}',
                        'score': 15
                    })
            except re.error:
                continue

        return score, matches

    def _match_page_content(self, html: str, indicators: List[str]) -> Tuple[int, List[Dict]]:
        """匹配页面内容"""
        score = 0
        matches = []
        matched_count = 0

        for indicator in indicators:
            if indicator in html:
                matched_count += 1
                if matched_count <= 3:  # 最多记录3个匹配
                    matches.append({
                        'type': 'page_content',
                        'indicator': indicator,
                        'description': f'页面包含特征词: {indicator}',
                        'score': 5
                    })

        # 根据匹配数量计分
        if matched_count >= 3:
            score = 15
        elif matched_count >= 2:
            score = 10
        elif matched_count >= 1:
            score = 5

        return score, matches

    def _match_phishing_themes(self, content: str, themes: List[str]) -> Tuple[int, List[Dict]]:
        """匹配钓鱼主题"""
        score = 0
        matches = []

        for theme in themes:
            if theme in content:
                score += 10
                matches.append({
                    'type': 'phishing_theme',
                    'indicator': theme,
                    'description': f'钓鱼主题匹配: {theme}',
                    'score': 10
                })
                break  # 只记录第一个匹配的主题

        return score, matches

    def _match_infrastructure(self, url: str, html: str, infra: Dict) -> Tuple[int, List[Dict]]:
        """匹配基础设施特征"""
        score = 0
        matches = []

        # OSS 模式匹配
        oss_patterns = infra.get('oss_patterns', [])
        content_to_check = url + ' ' + (html or '')

        for pattern in oss_patterns:
            try:
                if re.search(pattern, content_to_check):
                    score += 15
                    matches.append({
                        'type': 'infrastructure',
                        'indicator': 'cloud_storage',
                        'pattern': pattern,
                        'description': '使用该组织常用的云存储服务',
                        'score': 15
                    })
                    break
            except re.error:
                continue

        # CNAME 模式匹配
        cname_pattern = infra.get('cname_pattern')
        if cname_pattern:
            try:
                parsed = urlparse(url)
                if re.search(cname_pattern, parsed.netloc):
                    score += 20
                    matches.append({
                        'type': 'infrastructure',
                        'indicator': 'cname_pattern',
                        'description': '域名符合该组织的中转域名模式',
                        'score': 20
                    })
            except:
                pass

        return score, matches

    def _cross_validate_phishing(self, phishing: Dict, actor_info: Dict) -> int:
        """交叉验证钓鱼检测结果"""
        score = 0

        # 检查钓鱼主题是否匹配
        phishing_type = phishing.get('phishing_type', '')
        themes = actor_info.get('phishing_themes', [])

        # 金融诈骗类型与银狐/缅北魔方G 匹配
        if phishing_type in ('financial_auth', 'financial_loan'):
            if any(t in str(themes) for t in ['补贴', '税务', '认证', '社保']):
                score += 10

        # 凭证钓鱼与金眼狗匹配
        if phishing_type == 'credential_theft':
            if any(t in str(themes) for t in ['Telegram', '聊天', '语言包']):
                score += 10

        return score

    def _create_actor_match(self, actor_id: str, data: Dict) -> ThreatActorMatch:
        """创建组织匹配结果"""
        info = data['info']

        # 计算置信度（基于得分）
        score = data['score']
        if score >= 50:
            confidence = 90
        elif score >= 35:
            confidence = 75
        elif score >= 25:
            confidence = 60
        elif score >= 15:
            confidence = 45
        else:
            confidence = 30

        return ThreatActorMatch(
            actor_id=actor_id,
            actor_name=info['name'],
            aliases=info['aliases'],
            confidence=confidence,
            matched_indicators=data['matches'],
            ttps=info.get('ttps', []),
            targets=info.get('targets', []),
            description=info['description'],
            references=info.get('references', [])
        )

    def _summarize_indicators(self, result: AttributionResult) -> Dict:
        """汇总指标"""
        summary = {
            'total_matches': 0,
            'indicator_types': {},
        }

        if result.primary_actor:
            for match in result.primary_actor.matched_indicators:
                summary['total_matches'] += 1
                ind_type = match.get('type', 'unknown')
                summary['indicator_types'][ind_type] = \
                    summary['indicator_types'].get(ind_type, 0) + 1

        return summary

    def _generate_websearch_suggestions(self, result: AttributionResult, url: str, domain: str):
        """
        生成 WebSearch 增强建议

        触发条件:
        1. 无规则归因结果
        2. 规则归因置信度 < 60%
        """
        suggestions = []
        trigger_reason = ""

        # 计算置信度
        confidence = 0
        if result.has_attribution and result.primary_actor:
            confidence = result.primary_actor.confidence

        # 判断是否需要 WebSearch 增强
        needs_enhancement = False

        if not result.has_attribution:
            needs_enhancement = True
            trigger_reason = "无规则匹配结果，需要网络搜索补充"
        elif confidence < 60:
            needs_enhancement = True
            trigger_reason = f"规则归因置信度 {confidence}% < 60%，建议网络搜索验证"

        if not needs_enhancement:
            return

        result.websearch_enabled = True
        result.websearch_trigger_reason = trigger_reason

        # 1. 域名相关安全报告搜索
        if domain:
            suggestions.append(WebSearchSuggestion(
                search_type="domain_report",
                query=f'"{domain}" 钓鱼 OR phishing OR 恶意 威胁情报',
                purpose="搜索域名相关的安全厂商报告和威胁情报",
                priority="high"
            ))

        # 2. URL 相关报告搜索（对短 URL 更有效）
        # 清理 URL 中的敏感参数
        clean_url = url.split('?')[0] if '?' in url else url
        if len(clean_url) < 100:  # 避免搜索过长的 URL
            suggestions.append(WebSearchSuggestion(
                search_type="url_report",
                query=f'"{clean_url}" 钓鱼 OR 诈骗 OR malware',
                purpose="搜索该 URL 是否被安全社区报道",
                priority="medium"
            ))

        # 3. 如果有初步归因，搜索该组织的最新活动
        if result.has_attribution and result.primary_actor:
            actor_name = result.primary_actor.actor_name
            # 使用组织的主要别名进行搜索
            aliases = result.primary_actor.aliases[:2]  # 取前2个别名
            alias_query = ' OR '.join([f'"{a}"' for a in aliases])
            suggestions.append(WebSearchSuggestion(
                search_type="actor_activity",
                query=f'{alias_query} 钓鱼 OR 攻击 OR 木马 2025 OR 2026',
                purpose=f"搜索 {actor_name} 组织的最新攻击活动报告",
                priority="medium"
            ))

        # 4. 如果未归因但有钓鱼特征，搜索相关钓鱼活动
        if not result.has_attribution:
            # 提取域名中的可疑关键词
            domain_lower = domain.lower()
            suspicious_brands = ['wps', 'office', 'telegram', 'bank', 'pay', 'login']
            matched_brand = None
            for brand in suspicious_brands:
                if brand in domain_lower:
                    matched_brand = brand
                    break

            if matched_brand:
                suggestions.append(WebSearchSuggestion(
                    search_type="brand_phishing",
                    query=f'{matched_brand} 钓鱼 OR phishing 黑产 组织 2025 OR 2026',
                    purpose=f"搜索针对 {matched_brand} 的钓鱼活动和相关黑产组织",
                    priority="high"
                ))

        result.websearch_suggestions = suggestions


def analyze_attribution(url: str,
                       domain: str = "",
                       html_content: str = "",
                       page_title: str = "",
                       phishing_detection: Dict = None) -> AttributionResult:
    """便捷函数：执行归因分析"""
    attributor = ThreatActorAttributor()
    return attributor.analyze(
        url=url,
        domain=domain,
        html_content=html_content,
        page_title=page_title,
        phishing_detection=phishing_detection
    )


def format_attribution_report(result: AttributionResult) -> str:
    """格式化归因报告（Markdown）"""
    lines = []

    if not result.has_attribution:
        lines.append("## 威胁组织归因")
        lines.append("")
        lines.append("未能归因到已知黑产组织。")
        return '\n'.join(lines)

    lines.append("## 威胁组织归因")
    lines.append("")

    actor = result.primary_actor

    # 主要归因
    lines.append(f"**归因结论**: {actor.actor_name}")
    lines.append(f"**置信度**: {actor.confidence}%")
    lines.append("")

    # 组织信息表
    lines.append("| 字段 | 值 |")
    lines.append("|------|-----|")
    lines.append(f"| 组织ID | {actor.actor_id} |")
    lines.append(f"| 别名 | {', '.join(actor.aliases[:3])} |")
    lines.append(f"| 典型目标 | {', '.join(actor.targets[:3])} |")
    lines.append("")

    # 组织描述
    lines.append(f"**描述**: {actor.description}")
    lines.append("")

    # 匹配指标
    if actor.matched_indicators:
        lines.append("**匹配指标**:")
        lines.append("")
        for match in actor.matched_indicators[:5]:
            indicator = match.get('indicator', '')
            description = match.get('description', '')
            lines.append(f"- {description}")
        lines.append("")

    # TTP
    if actor.ttps:
        lines.append("**战术技术 (TTPs)**:")
        lines.append("")
        for ttp in actor.ttps[:4]:
            lines.append(f"- {ttp}")
        lines.append("")

    # 参考链接
    if actor.references:
        lines.append("**参考报告**:")
        lines.append("")
        for ref in actor.references[:2]:
            lines.append(f"- {ref}")
        lines.append("")

    # 次要归因
    if result.secondary_actors:
        lines.append("**其他可能的组织**:")
        lines.append("")
        for secondary in result.secondary_actors[:2]:
            lines.append(f"- {secondary.actor_name} (置信度: {secondary.confidence}%)")
        lines.append("")

    # WebSearch 增强建议
    if result.websearch_enabled and result.websearch_suggestions:
        lines.append("---")
        lines.append("")
        lines.append("### [*] WebSearch 增强建议")
        lines.append("")
        lines.append(f"**触发原因**: {result.websearch_trigger_reason}")
        lines.append("")
        lines.append("**建议搜索**:")
        lines.append("")
        for suggestion in result.websearch_suggestions:
            priority_icon = "[!]" if suggestion.priority == "high" else "[*]" if suggestion.priority == "medium" else "[+]"
            lines.append(f"- {priority_icon} **{suggestion.search_type}**: `{suggestion.query}`")
            lines.append(f"  - 目的: {suggestion.purpose}")
        lines.append("")

    return '\n'.join(lines)


def attribution_to_dict(result: AttributionResult) -> Dict:
    """将归因结果转为字典（用于 JSON 输出）"""
    data = {
        'has_attribution': result.has_attribution,
        'attribution_score': result.attribution_score,
        'indicators_summary': result.indicators_summary,
    }

    if result.primary_actor:
        data['primary_actor'] = {
            'actor_id': result.primary_actor.actor_id,
            'actor_name': result.primary_actor.actor_name,
            'aliases': result.primary_actor.aliases,
            'confidence': result.primary_actor.confidence,
            'matched_indicators': result.primary_actor.matched_indicators,
            'ttps': result.primary_actor.ttps,
            'targets': result.primary_actor.targets,
            'description': result.primary_actor.description,
            'references': result.primary_actor.references,
        }

    if result.secondary_actors:
        data['secondary_actors'] = [
            {
                'actor_id': a.actor_id,
                'actor_name': a.actor_name,
                'confidence': a.confidence,
            }
            for a in result.secondary_actors
        ]

    # WebSearch 增强建议
    data['websearch_suggestions'] = {
        'enabled': result.websearch_enabled,
        'trigger_reason': result.websearch_trigger_reason,
        'suggestions': [
            {
                'type': s.search_type,
                'query': s.query,
                'purpose': s.purpose,
                'priority': s.priority,
            }
            for s in result.websearch_suggestions
        ] if result.websearch_suggestions else []
    }

    return data


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("用法: python threat_actor_attribution.py <URL>")
        print("示例: python threat_actor_attribution.py 'http://wps-office-cn.xyz/download'")
        sys.exit(1)

    url = sys.argv[1]

    # 读取 HTML（如果提供）
    html = ""
    if len(sys.argv) >= 3:
        try:
            with open(sys.argv[2], 'r', encoding='utf-8') as f:
                html = f.read()
        except:
            pass

    # 执行归因
    result = analyze_attribution(url, html_content=html)

    # 输出报告
    print(format_attribution_report(result))
