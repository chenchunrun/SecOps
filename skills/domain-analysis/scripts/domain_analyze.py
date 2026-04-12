#!/usr/bin/env python3
"""
域名综合分析工具
整合本地分析和威胁情报查询，提供全面的域名威胁评估

优化：并行执行分析阶段，确保 10 秒内返回结果
"""

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from datetime import datetime
from typing import Dict, List, Any

# 总体超时（秒）
TOTAL_TIMEOUT = 6  # 总超时 6 秒，确保 10 秒内返回

# 导入同目录下的模块
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from domain_validate import DomainValidator
from domain_dns import DNSLookup
from domain_dga import DGADetector
from homograph_detector import HomographDetector

# 尝试导入 WHOIS 模块
try:
    from domain_whois import DomainWhoisChecker
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


class DomainAnalyzer:
    """域名综合分析器"""

    # 威胁评分权重
    THREAT_SCORES = {
        'multi_source_malicious': 40,
        'dga_detected': 35,
        'homograph_attack': 30,
        'new_domain': 20,
        'high_risk_tld': 15,
        'no_whois': 10,
        'malware_samples': 25,
        'c2_tag': 30,
        'phishing_tag': 25,
        'spam_tag': 15,
        'dynamic_dns': 20,
        'mixed_scripts': 15,
    }

    def __init__(self, local_only: bool = False, timeout: int = TOTAL_TIMEOUT):
        """
        初始化域名分析器

        Args:
            local_only: 仅本地分析，不查询威胁情报
            timeout: 总体超时（秒），默认 8s
        """
        self.local_only = local_only
        self.timeout = timeout
        self.validator = DomainValidator()
        # DNS 超时设为总超时的 1/4，确保有时间做其他分析
        self.dns_lookup = DNSLookup(timeout=max(2, timeout // 4))
        self.dga_detector = DGADetector()
        self.homograph_detector = HomographDetector()

        # 初始化 WHOIS 查询器
        if WHOIS_AVAILABLE:
            self.whois_checker = DomainWhoisChecker()
        else:
            self.whois_checker = None

    def analyze(self, domain: str) -> Dict[str, Any]:
        """
        对域名进行综合分析（并行优化版）

        Args:
            domain: 域名

        Returns:
            dict: 分析结果
        """
        result = {
            'domain': domain,
            'analysis_time': datetime.now().isoformat(),
            'validation': None,
            'dns_records': None,
            'whois_info': None,
            'dga_detection': None,
            'homograph_detection': None,
            'spf_check': None,
            'dmarc_check': None,
            'threat_intel': None,
            'icp_info': None,
            'risk_score': 0,
            'risk_level': 'unknown',
            'risk_factors': [],
            'recommendations': [],
            'related_iocs': {
                'ips': [],
                'hashes': [],
                'urls': [],
                'subdomains': [],
            },
            'errors': [],
        }

        # 第一阶段：验证（快速，必须先执行）
        validation = self.validator.validate(domain)
        result['validation'] = validation

        if not validation['valid']:
            result['errors'].append(f"域名格式无效: {validation['error']}")
            return result

        # 添加验证阶段的风险因素
        for factor in validation.get('risk_factors', []):
            result['risk_factors'].append({
                'factor': 'validation',
                'description': factor,
                'score': 10,
            })

        # 高风险 TLD 检测
        if validation.get('domain_type') == 'high_risk_tld':
            result['risk_factors'].append({
                'factor': 'high_risk_tld',
                'description': f"高风险 TLD: .{validation.get('tld')}",
                'score': self.THREAT_SCORES['high_risk_tld'],
            })

        # 动态 DNS 检测
        if validation.get('domain_type') == 'dynamic_dns':
            result['risk_factors'].append({
                'factor': 'dynamic_dns',
                'description': "动态 DNS 服务域名",
                'score': self.THREAT_SCORES['dynamic_dns'],
            })

        # ========== 并行执行阶段 ==========
        # DNS、DGA、同形字、WHOIS 可以并行执行
        def task_dns():
            return self.dns_lookup.lookup(domain, ['A', 'AAAA', 'MX', 'NS', 'TXT'])

        def task_dga():
            return self.dga_detector.detect(domain)

        def task_homograph():
            return self.homograph_detector.detect(domain)

        def task_whois():
            if not self.whois_checker:
                return None
            reg_domain = validation.get('registered_domain', domain)
            return self.whois_checker.query(reg_domain)

        tasks = {
            'dns': task_dns,
            'dga': task_dga,
            'homograph': task_homograph,
            'whois': task_whois,
        }

        results_map = {}
        executor = ThreadPoolExecutor(max_workers=4)
        try:
            futures = {executor.submit(fn): name for name, fn in tasks.items()}
            try:
                for future in as_completed(futures, timeout=self.timeout):
                    name = futures[future]
                    try:
                        results_map[name] = future.result(timeout=1)
                    except Exception as e:
                        result['errors'].append(f"{name}: {str(e)}")
                        results_map[name] = None
            except TimeoutError:
                # 处理整体超时：记录未完成的任务
                for future, name in futures.items():
                    if name not in results_map:
                        result['errors'].append(f"{name}: 查询超时")
                        results_map[name] = None
        finally:
            # 不等待超时的线程，立即返回
            executor.shutdown(wait=False, cancel_futures=True)

        # ========== 处理 DNS 结果 ==========
        dns_result = results_map.get('dns', {})
        result['dns_records'] = dns_result
        if dns_result:
            a_records = dns_result.get('records', {}).get('A', [])
            aaaa_records = dns_result.get('records', {}).get('AAAA', [])
            result['related_iocs']['ips'] = a_records + aaaa_records

            # 邮件安全检查（快速，依赖已有 DNS 数据）
            result['spf_check'] = self.dns_lookup.check_spf(domain)
            result['dmarc_check'] = self.dns_lookup.check_dmarc(domain)

        # ========== 处理 WHOIS 结果 ==========
        whois_result = results_map.get('whois')
        if whois_result:
            if whois_result.success:
                result['whois_info'] = {
                    'success': True,
                    'domain': whois_result.domain,
                    'registrar': whois_result.registrar,
                    'creation_date': str(whois_result.creation_date) if whois_result.creation_date else None,
                    'expiration_date': str(whois_result.expiration_date) if whois_result.expiration_date else None,
                    'domain_age_days': whois_result.domain_age_days,
                    'domain_age_text': whois_result.domain_age_text,
                    'is_new_domain': whois_result.is_new_domain,
                    'is_young_domain': whois_result.is_young_domain,
                    'age_risk_level': whois_result.age_risk_level,
                    'age_risk_score': whois_result.age_risk_score,
                    'name_servers': whois_result.name_servers[:3] if whois_result.name_servers else [],
                    'privacy_protected': whois_result.privacy_protected,
                }

                # 根据域名年龄添加风险因素
                if whois_result.age_risk_level == 'critical':
                    result['risk_factors'].append({
                        'factor': 'domain_age_critical',
                        'description': f"极新域名 (<7天): {whois_result.domain_age_text}",
                        'score': 30,
                    })
                elif whois_result.age_risk_level == 'high':
                    result['risk_factors'].append({
                        'factor': 'domain_age_high',
                        'description': f"新注册域名 (<30天): {whois_result.domain_age_text}",
                        'score': self.THREAT_SCORES['new_domain'],
                    })
                elif whois_result.age_risk_level == 'medium':
                    result['risk_factors'].append({
                        'factor': 'domain_age_medium',
                        'description': f"较新域名 (<90天): {whois_result.domain_age_text}",
                        'score': 10,
                    })

                # 隐私保护 + 年轻域名 = 额外风险
                if whois_result.privacy_protected and whois_result.is_young_domain:
                    result['risk_factors'].append({
                        'factor': 'privacy_protected_young',
                        'description': "年轻域名 + 隐私保护: 钓鱼站点常见特征",
                        'score': 5,
                    })
            else:
                # 区分不同类型的 WHOIS 失败
                error_msg = whois_result.error or ''
                is_module_missing = '未安装' in error_msg
                is_timeout = '超时' in error_msg

                if is_module_missing:
                    # 模块未安装是环境问题，不计入风险分数
                    result['whois_info'] = {
                        'success': False,
                        'status': 'MODULE_UNAVAILABLE',
                        'reason': error_msg,
                        'install_command': 'pip install python-whois',
                    }
                    result['analysis_limitations'] = result.get('analysis_limitations', [])
                    result['analysis_limitations'].append({
                        'type': 'missing_dependency',
                        'component': 'python-whois',
                        'impact': '无法分析域名年龄（钓鱼检测的核心指标）',
                        'fix': 'pip install python-whois',
                    })
                elif is_timeout:
                    # 超时是网络问题，不计入风险分数
                    result['whois_info'] = {
                        'success': False,
                        'status': 'TIMEOUT',
                        'error': error_msg,
                    }
                    result['analysis_limitations'] = result.get('analysis_limitations', [])
                    result['analysis_limitations'].append({
                        'type': 'query_timeout',
                        'component': 'whois',
                        'impact': '无法分析域名年龄',
                    })
                else:
                    # 真正的查询失败（被拒绝、无记录等），计入风险分数
                    result['whois_info'] = {
                        'success': False,
                        'error': error_msg,
                    }
                    result['risk_factors'].append({
                        'factor': 'no_whois',
                        'description': f"无法获取 WHOIS 信息: {error_msg}",
                        'score': self.THREAT_SCORES['no_whois'],
                    })
        elif not self.whois_checker:
            # 模块未安装是环境问题，不是域名风险，不计入风险分数
            result['whois_info'] = {
                'success': False,
                'status': 'MODULE_UNAVAILABLE',
                'reason': 'python-whois 未安装',
                'install_command': 'pip install python-whois',
                'fallback_suggestion': {
                    'method': 'system_whois',
                    'command': f'whois {domain} | grep -i "creation\\|created\\|registrar"',
                    'note': '使用系统 whois 命令作为替代'
                }
            }
            # 仅记录为分析局限性，不加风险分数
        else:
            # WHOIS 查询超时或返回 None
            result['whois_info'] = {
                'success': False,
                'status': 'TIMEOUT',
                'error': 'WHOIS 查询超时',
            }
            result['analysis_limitations'] = result.get('analysis_limitations', [])
            result['analysis_limitations'].append({
                'type': 'query_timeout',
                'component': 'whois',
                'impact': '无法分析域名年龄',
            })

        # ========== 处理 DGA 结果 ==========
        dga_result = results_map.get('dga', {})
        result['dga_detection'] = dga_result
        if dga_result:
            if dga_result.get('is_dga') or dga_result.get('dga_probability') == 'high':
                result['risk_factors'].append({
                    'factor': 'dga_detected',
                    'description': f"疑似 DGA 域名 (评分: {dga_result.get('dga_score', 0):.0f})",
                    'score': self.THREAT_SCORES['dga_detected'],
                })
            elif dga_result.get('dga_probability') == 'medium':
                result['risk_factors'].append({
                    'factor': 'dga_suspected',
                    'description': "DGA 特征中等",
                    'score': 15,
                })

        # ========== 处理同形字结果 ==========
        homograph_result = results_map.get('homograph', {})
        result['homograph_detection'] = homograph_result
        if homograph_result:
            is_homograph = homograph_result.get('is_homograph', False)
            has_mixed_scripts = homograph_result.get('has_mixed_scripts', False)
            target_brand = homograph_result.get('target_brand')
            brand_similarity = homograph_result.get('brand_similarity', 0)

            # 同形字攻击检测
            if is_homograph:
                result['risk_factors'].append({
                    'factor': 'homograph_attack',
                    'description': "检测到同形字攻击",
                    'score': self.THREAT_SCORES['homograph_attack'],
                })

            # 品牌仿冒检测 - 更严格的条件
            # 只有当存在同形字/混合脚本 + 高相似度时，才认定为品牌仿冒
            if target_brand and brand_similarity >= 0.8:
                if is_homograph or has_mixed_scripts:
                    # 真正的仿冒攻击：使用同形字/混合脚本 + 高相似度
                    result['risk_factors'].append({
                        'factor': 'brand_impersonation',
                        'description': f"品牌仿冒攻击: {target_brand} ({brand_similarity:.0%})",
                        'score': 25,
                    })
                elif brand_similarity >= 0.9:
                    # 纯 ASCII 但极高相似度（如 micr0soft.com）
                    # 可能是 leetspeak 仿冒，较低风险
                    result['risk_factors'].append({
                        'factor': 'brand_typosquat',
                        'description': f"疑似品牌抢注/拼写错误: {target_brand} ({brand_similarity:.0%})",
                        'score': 10,
                    })
                # 低于 90% 相似度的纯 ASCII 域名不计入风险（可能是巧合）

            # 混合脚本检测
            if has_mixed_scripts:
                result['risk_factors'].append({
                    'factor': 'mixed_scripts',
                    'description': "混合脚本域名",
                    'score': self.THREAT_SCORES['mixed_scripts'],
                })

        # ========== 威胁情报提示 ==========
        if not self.local_only:
            result['threat_intel'] = {
                'status': 'pending',
                'message': '需要调用 MCP 查询威胁情报',
                'mcp_calls': [
                    {
                        'server': 'cybersec-cloud',
                        'tool': 'risk_insight',
                        'params': {
                            'indicator': domain,
                            'kind': 'domain',
                        }
                    }
                ]
            }

            # 如果是中国域名，添加 ICP 查询
            if validation.get('tld') in ('cn', 'com.cn', 'net.cn', 'org.cn'):
                result['threat_intel']['mcp_calls'].append({
                    'server': 'cybersec-cloud',
                    'tool': 'intel_icp_lookup',
                    'params': {
                        'domain': domain,
                    }
                })

        # 计算当前风险分数
        result['risk_score'] = sum(f['score'] for f in result['risk_factors'])
        result['risk_level'] = self._calculate_risk_level(result['risk_score'])

        # 生成建议
        result['recommendations'] = self._generate_recommendations(result)

        return result

    def _calculate_risk_level(self, score: int) -> str:
        """根据分数计算风险等级"""
        if score >= 61:
            return 'critical'
        elif score >= 41:
            return 'high'
        elif score >= 21:
            return 'medium'
        else:
            return 'low'

    def _generate_recommendations(self, result: Dict) -> List[str]:
        """生成处置建议"""
        recommendations = []
        risk_level = result['risk_level']

        if risk_level == 'critical':
            recommendations.append("立即在 DNS/防火墙中阻断该域名")
            recommendations.append("检查内网是否有主机访问过该域名")
            recommendations.append("如有访问记录，进行主机取证")
        elif risk_level == 'high':
            recommendations.append("建议阻断该域名")
            recommendations.append("检查 DNS 日志，确认访问记录")
        elif risk_level == 'medium':
            recommendations.append("加入监控列表")
            recommendations.append("如无正常业务需求，考虑阻断")
        else:
            recommendations.append("风险较低，可持续监控")

        # 根据检测结果添加建议
        if result.get('homograph_detection', {}).get('is_homograph'):
            recommendations.append("警告用户注意同形字钓鱼攻击")

        if result.get('dga_detection', {}).get('is_dga'):
            recommendations.append("该域名可能由恶意软件自动生成，检查是否有相关感染")

        # 关联 IP 建议
        ips = result.get('related_iocs', {}).get('ips', [])
        if ips:
            recommendations.append(f"建议分析解析到的 {len(ips)} 个 IP 地址")

        return recommendations


def format_result(result: Dict, output_format: str = 'text') -> str:
    """格式化输出结果（符合 Markdown 规范）"""
    if output_format == 'json':
        return json.dumps(result, ensure_ascii=False, indent=2)

    # Markdown 格式
    lines = []

    # 风险等级显示
    risk_display = {
        'critical': '[CRITICAL]',
        'high': '[HIGH]',
        'medium': '[MEDIUM]',
        'low': '[LOW]',
    }

    risk_tag = {'critical': '[!]', 'high': '[!]', 'medium': '[*]', 'low': '[+]'}.get(result['risk_level'], '[-]')

    lines.append(f"# {risk_tag} 域名威胁分析报告")
    lines.append("")
    lines.append(f"**威胁等级**: {risk_display.get(result['risk_level'], result['risk_level'])} (评分: {result['risk_score']})")
    lines.append("")
    lines.append(f"**分析时间**: {result.get('analysis_time', '')[:19].replace('T', ' ')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 验证信息
    validation = result.get('validation', {})
    if not validation.get('valid'):
        lines.append(f"**错误**: 域名格式无效 - {validation.get('error')}")
        return '\n'.join(lines)

    # 1. 基础信息（列表格式）
    lines.append("## 1. 域名基本信息")
    lines.append("")
    lines.append(f"- **域名**: {result['domain']}")
    lines.append(f"- **TLD**: .{validation.get('tld')}")
    lines.append(f"- **类型**: {validation.get('domain_type')}")

    if validation.get('is_idn'):
        lines.append(f"- **IDN**: 是 (Punycode: {validation.get('punycode')})")

    # WHOIS 信息
    whois = result.get('whois_info') or {}
    if whois.get('success'):
        if whois.get('registrar'):
            lines.append(f"- **注册商**: {whois['registrar']}")
        if whois.get('creation_date'):
            lines.append(f"- **注册日期**: {whois['creation_date'][:10]}")
        if whois.get('domain_age_text'):
            risk_indicator = {'critical': '[!]', 'high': '[!]', 'medium': '[*]', 'low': '[+]', 'safe': '[+]'}.get(whois.get('age_risk_level'), '[-]')
            lines.append(f"- **域名年龄**: {whois['domain_age_text']} {risk_indicator}")
        if whois.get('privacy_protected'):
            lines.append("- **隐私保护**: 是 [!]")

    lines.append("")
    lines.append("---")
    lines.append("")

    # 2. DNS 记录（表格格式 - 多条记录）
    lines.append("## 2. DNS 记录")
    lines.append("")

    dns = result.get('dns_records', {})
    if dns.get('records'):
        lines.append("| 类型 | 值 |")
        lines.append("|------|-----|")
        for rtype, records in dns['records'].items():
            for record in records[:3]:
                lines.append(f"| {rtype} | {record} |")
            if len(records) > 3:
                lines.append(f"| {rtype} | ... 还有 {len(records) - 3} 条 |")
    else:
        lines.append("无 DNS 记录")

    # 邮件安全配置
    spf = result.get('spf_check', {})
    dmarc = result.get('dmarc_check', {})
    if spf or dmarc:
        lines.append("")
        lines.append("**DNS 安全配置**:")
        if spf:
            spf_status = "[+] 已配置" if spf.get('has_spf') else "[!] 未配置"
            lines.append(f"- **SPF**: {spf_status}")
        if dmarc:
            dmarc_status = "[+] 已配置" if dmarc.get('has_dmarc') else "[!] 未配置"
            lines.append(f"- **DMARC**: {dmarc_status}")

    lines.append("")
    lines.append("---")
    lines.append("")

    # 3. 威胁情报
    lines.append("## 3. 威胁情报")
    lines.append("")

    threat_intel = result.get('threat_intel') or {}
    if threat_intel.get('status') == 'pending':
        lines.append("**状态**: 待查询")
        lines.append("")
        lines.append("**MCP 调用**:")
        for call in threat_intel.get('mcp_calls', []):
            lines.append(f"- {call['server']}.{call['tool']}")
    elif threat_intel.get('status') == 'completed':
        lines.append("**状态**: 已查询")
    else:
        lines.append("**状态**: 无数据")

    lines.append("")
    lines.append("---")
    lines.append("")

    # 4. 特殊检测
    lines.append("## 4. 特殊检测")
    lines.append("")

    # DGA 检测
    dga = result.get('dga_detection', {})
    if dga:
        dga_result = "[!] 疑似 DGA 域名" if dga.get('is_dga') else "[-] 非 DGA 域名"
        lines.append(f"**DGA 检测**: {dga_result}")
        if dga.get('entropy'):
            lines.append(f"- 熵值: {dga.get('entropy', 0):.3f}")
            lines.append(f"- 概率: {dga.get('dga_probability', 'unknown')}")
        lines.append("")

    # 同形字检测
    homo = result.get('homograph_detection', {})
    if homo:
        homo_result = "[!] 检测到同形字攻击" if homo.get('is_homograph') else "[-] 未检测到同形字攻击"
        lines.append(f"**同形字检测**: {homo_result}")
        if homo.get('is_homograph'):
            if homo.get('target_brand'):
                lines.append(f"- 仿冒品牌: {homo['target_brand']} ({homo.get('brand_similarity', 0):.0%})")
            if homo.get('has_mixed_scripts'):
                lines.append("- 混合脚本: 是")
        lines.append("")

    lines.append("---")
    lines.append("")

    # 5. IOC 提取
    lines.append("## 5. IOC 提取")
    lines.append("")

    related = result.get('related_iocs', {})
    ips = related.get('ips', [])
    if ips:
        lines.append(f"**解析 IP** ({len(ips)} 个):")
        for ip in ips[:5]:
            lines.append(f"- {ip}")
        if len(ips) > 5:
            lines.append(f"- ... 还有 {len(ips) - 5} 个")
        lines.append("")

    subdomains = related.get('subdomains', [])
    if subdomains:
        lines.append(f"**关联子域名** ({len(subdomains)} 个):")
        for sub in subdomains[:5]:
            lines.append(f"- {sub}")
        if len(subdomains) > 5:
            lines.append(f"- ... 还有 {len(subdomains) - 5} 个")
        lines.append("")

    if not ips and not subdomains:
        lines.append("无关联 IOC")
        lines.append("")

    lines.append("---")
    lines.append("")

    # 6. 风险评估（表格格式）
    lines.append("## 6. 风险评估")
    lines.append("")

    if result['risk_factors']:
        lines.append("| 指标 | 结果 | 分值 |")
        lines.append("|------|------|------|")
        for factor in result['risk_factors']:
            lines.append(f"| {factor['factor']} | {factor['description']} | +{factor['score']} |")
        lines.append(f"| **总分** | | **{result['risk_score']}** |")
    else:
        lines.append("无风险因素")

    lines.append("")
    lines.append("---")
    lines.append("")

    # 7. 分析存在的问题
    lines.append("## 7. 分析存在的问题")
    lines.append("")

    limitations = result.get('analysis_limitations', [])
    whois = result.get('whois_info', {})

    has_limitations = False

    # 显示依赖缺失问题
    for lim in limitations:
        if lim.get('type') == 'missing_dependency':
            has_limitations = True
            lines.append(f"- **{lim['component']} 未安装**: {lim['impact']}")
            lines.append(f"  - 安装命令: `{lim['fix']}`")

    # WHOIS 查询失败（非模块缺失）
    if whois.get('success') is False and whois.get('status') != 'MODULE_UNAVAILABLE':
        has_limitations = True
        lines.append(f"- **WHOIS 查询失败**: {whois.get('error', '未知错误')}")

    if not has_limitations:
        lines.append("无")

    lines.append("")
    lines.append("---")
    lines.append("")

    # 8. 结论
    lines.append("## 8. 结论")
    lines.append("")
    lines.append(f"**风险等级**: {risk_display.get(result['risk_level'], result['risk_level'])}")
    lines.append("")

    if result.get('recommendations'):
        lines.append("**处置建议**:")
        for i, rec in enumerate(result['recommendations'], 1):
            lines.append(f"{i}. {rec}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='域名综合威胁分析工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s example.com
  %(prog)s --local-only suspicious.tk
  %(prog)s -f domains.txt -o json
        '''
    )
    parser.add_argument('domain', nargs='?', help='要分析的域名')
    parser.add_argument('-f', '--file', help='从文件读取域名列表')
    parser.add_argument('-o', '--output', choices=['text', 'json'],
                        default='text', help='输出格式')
    parser.add_argument('--local-only', action='store_true',
                        help='仅本地分析，不查询威胁情报')
    parser.add_argument('--min-risk', choices=['low', 'medium', 'high', 'critical'],
                        help='只输出指定风险等级以上的结果')
    parser.add_argument('--include-parent', action='store_true',
                        help='分析子域名时同时分析主域名')
    parser.add_argument('-t', '--timeout', type=int, default=TOTAL_TIMEOUT,
                        help=f'总体超时时间（秒），默认 {TOTAL_TIMEOUT}s')

    args = parser.parse_args()

    if not args.domain and not args.file:
        parser.print_help()
        sys.exit(1)

    analyzer = DomainAnalyzer(local_only=args.local_only, timeout=args.timeout)

    risk_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
    min_risk_level = risk_order.get(args.min_risk, -1)

    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        results = []
        for domain in domains:
            result = analyzer.analyze(domain)
            if risk_order.get(result['risk_level'], 0) >= min_risk_level:
                results.append(result)

        if args.output == 'json':
            print(json.dumps(results, ensure_ascii=False, indent=2))
        else:
            for result in results:
                print(format_result(result, args.output))
                print()
    else:
        result = analyzer.analyze(args.domain)
        print(format_result(result, args.output))

        risk_level = result.get('risk_level', 'unknown')
        if risk_level in ('critical', 'high'):
            sys.exit(2)
        elif risk_level == 'medium':
            sys.exit(1)
        else:
            sys.exit(0)


if __name__ == '__main__':
    main()
