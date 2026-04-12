#!/usr/bin/env python3
"""
DNS缓存探测威胁检测器 V2 - 性能优化版
新增功能：
1. 权威TTL缓存
2. 优化超时处理
3. 自动验证机制
4. 实时告警（钉钉）
"""

import logging
import os
import sys
from typing import List, Dict, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml
import time

# 导入同目录下的模块
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from dns_probe import DNSProbe, ProbeResult, analyze_probe_results
from threat_intel import ThreatIntelManager, IOC

logger = logging.getLogger(__name__)


class ThreatDetectorV2:
    """DNS缓存探测威胁检测器 V2"""

    def __init__(self, config_file: str = "config.yaml"):
        """
        初始化检测器

        Args:
            config_file: 配置文件路径
        """
        # 加载配置
        with open(config_file, 'r', encoding='utf-8') as f:
            self.config = yaml.safe_load(f)

        # 初始化DNS探测器
        timeout = self.config['probe']['timeout']
        self.probe = DNSProbe(timeout=timeout)

        # 初始化威胁情报
        self.threat_intel = ThreatIntelManager(self.config.get('threat_intel', {}))

        # 检测结果
        self.detections: List[Dict] = []

        # ========== 新增: 权威TTL缓存 ==========
        self.auth_ttl_cache: Dict[str, int] = {}  # {domain: ttl}
        self.cache_expiry: Dict[str, float] = {}   # {domain: timestamp}
        self.cache_ttl_seconds = 300  # 缓存5分钟

        # ========== 新增: 失效域名黑名单 ==========
        self.failed_domains: set = set()  # 超时域名，下次跳过

        # ========== 新增: 性能统计 ==========
        self.stats = {
            'auth_ttl_cache_hits': 0,
            'auth_ttl_cache_misses': 0,
            'failed_domains_skipped': 0,
            'auto_verifications': 0,
            'verified_threats': 0
        }

    def get_cached_auth_ttl(self, domain: str, auth_dns: str) -> Optional[int]:
        """
        获取权威TTL（带缓存）

        Args:
            domain: 域名
            auth_dns: 权威DNS

        Returns:
            TTL值，失败返回None
        """
        now = time.time()

        # 检查黑名单
        if domain in self.failed_domains:
            self.stats['failed_domains_skipped'] += 1
            logger.debug(f"[TTL缓存] {domain}: 跳过（已失效）")
            return None

        # 检查缓存
        if domain in self.auth_ttl_cache:
            if now < self.cache_expiry[domain]:
                self.stats['auth_ttl_cache_hits'] += 1
                logger.debug(f"[TTL缓存] {domain}: 命中 (TTL={self.auth_ttl_cache[domain]})")
                return self.auth_ttl_cache[domain]

        # 获取新的权威TTL（优化超时）
        self.stats['auth_ttl_cache_misses'] += 1
        ttl = self.probe.get_authoritative_ttl(domain, auth_dns, timeout=2)  # 超时缩短到2秒

        if ttl is None:
            # 标记为失效域名
            self.failed_domains.add(domain)
            logger.warning(f"[TTL缓存] {domain}: 获取失败，加入黑名单")
            return None

        # 更新缓存
        self.auth_ttl_cache[domain] = ttl
        self.cache_expiry[domain] = now + self.cache_ttl_seconds
        logger.debug(f"[TTL缓存] {domain}: 更新缓存 (TTL={ttl})")

        return ttl

    def verify_threat(self, domain: str, dns_server: str, initial_result: ProbeResult, auth_dns: str) -> bool:
        """
        自动验证威胁

        当发现缓存命中时，自动进行二次验证：
        1. 等待2秒后再次探测
        2. 连续观察TTL衰减（3次，间隔2秒）
        3. 验证TTL衰减是否正常

        Args:
            domain: 域名
            dns_server: DNS服务器
            initial_result: 初次探测结果
            auth_dns: 权威DNS

        Returns:
            True表示威胁确认，False表示可能误报
        """
        self.stats['auto_verifications'] += 1
        logger.info(f"[自动验证] 开始验证 {domain} @ {dns_server}")

        # 获取缓存的权威TTL
        auth_ttl = self.get_cached_auth_ttl(domain, auth_dns)
        if auth_ttl is None:
            logger.warning(f"[自动验证] {domain}: 无法获取权威TTL")
            return False

        # 等待2秒
        time.sleep(2)

        # 二次探测（使用缓存的auth_ttl）
        result2 = self.probe.probe_ttl_compare(domain, dns_server, auth_dns, cached_auth_ttl=auth_ttl)

        if not result2.is_cached:
            logger.warning(f"[自动验证] {domain}: 二次探测未命中，可能为误报")
            return False

        logger.info(f"[自动验证] {domain}: 二次探测仍命中 (TTL={result2.cached_ttl})")

        # 连续观察TTL衰减（3次，间隔2秒）
        ttls = [result2.cached_ttl]

        for i in range(2):
            time.sleep(2)
            result = self.probe.probe_ttl_compare(domain, dns_server, auth_dns, cached_auth_ttl=auth_ttl)
            if result.is_cached and result.cached_ttl:
                ttls.append(result.cached_ttl)

        if len(ttls) < 2:
            logger.warning(f"[自动验证] {domain}: TTL数据不足")
            return False

        # 验证TTL衰减
        decay = ttls[0] - ttls[-1]
        expected = len(ttls) * 2  # 每次间隔2秒

        logger.info(f"[自动验证] {domain}: TTL衰减 {decay}秒 (期望{expected}秒)")
        logger.debug(f"[自动验证] {domain}: TTL序列 {ttls}")

        if abs(decay - expected) <= 2:  # 允许2秒误差
            logger.info(f"[自动验证] {domain}: [+] 威胁确认! TTL衰减正常")
            self.stats['verified_threats'] += 1
            return True
        else:
            logger.warning(f"[自动验证] {domain}: [!] TTL衰减异常，需人工复核")
            return False

    def load_threat_intel(self):
        """加载威胁情报"""
        sources = self.config.get('threat_intel', {}).get('sources', [])

        total_loaded = 0
        for source in sources:
            if not source.get('enabled', True):
                continue

            if source['type'] == 'file':
                count = self.threat_intel.load_from_file(source['path'])
                total_loaded += count

        logger.info(f"威胁情报加载完成: 共 {total_loaded} 个IOC")
        return total_loaded

    def stage1_quick_probe(
        self,
        domains: List[str],
        dns_servers: List[str]
    ) -> List[Dict]:
        """
        Stage 1: 快速探测（优化版）

        改进:
        1. 使用权威TTL缓存
        2. 跳过已失效域名
        3. 自动验证缓存命中

        Args:
            domains: 待探测域名列表
            dns_servers: 企业DNS服务器列表

        Returns:
            检测结果列表
        """
        logger.info(f"[Stage 1] 开始快速探测: {len(domains)} 个域名 x {len(dns_servers)} 个DNS")

        results = []
        use_rd0 = self.config['probe']['use_rd0']
        use_ttl = self.config['probe']['use_ttl_compare']
        auth_dns = self.config['dns']['authoritative']['primary']

        # 并发探测
        max_workers = self.config['probe']['threads']

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []

            for domain in domains:
                # 跳过失效域名
                if domain in self.failed_domains:
                    continue

                for dns_server in dns_servers:
                    if use_ttl:
                        future = executor.submit(
                            self._probe_with_cache,
                            domain, dns_server, auth_dns
                        )
                        futures.append(future)
                    elif use_rd0:
                        future = executor.submit(
                            self.probe.probe_rd0,
                            domain, dns_server
                        )
                        futures.append(future)

            # 收集结果
            for future in as_completed(futures):
                try:
                    probe_result = future.result()
                    if probe_result is None:
                        continue

                    results.append(probe_result)

                    # 记录缓存命中
                    if probe_result.is_cached:
                        ioc = self.threat_intel.get_ioc(probe_result.domain)

                        # ========== 新增: 自动验证 ==========
                        auto_verify = self.config.get('advanced', {}).get('auto_verify_threats', True)
                        is_verified = False

                        if auto_verify:
                            is_verified = self.verify_threat(
                                probe_result.domain,
                                probe_result.dns_server,
                                probe_result,
                                auth_dns
                            )

                        detection = {
                            'stage': 1,
                            'timestamp': probe_result.timestamp,
                            'domain': probe_result.domain,
                            'dns_server': probe_result.dns_server,
                            'is_cached': True,
                            'cache_age_seconds': probe_result.cache_age_seconds,
                            'ioc': ioc.__dict__ if ioc else None,
                            'severity': self._calculate_severity(probe_result, ioc),
                            'auto_verified': is_verified  # 新增字段
                        }
                        self.detections.append(detection)

                        logger.warning(
                            f"[检测] {probe_result.domain} 在 {probe_result.dns_server} 发现缓存! "
                            f"类别: {ioc.category if ioc else 'unknown'} "
                            f"验证: {'[+]通过' if is_verified else '[!]未验证'}"
                        )

                except Exception as e:
                    logger.error(f"探测任务执行失败: {e}")

        cached_count = sum(1 for r in results if r.is_cached)
        logger.info(f"[Stage 1] 完成: {len(results)} 次探测, {cached_count} 次缓存命中")

        # 输出性能统计
        logger.info(f"[性能统计] TTL缓存命中: {self.stats['auth_ttl_cache_hits']}, "
                   f"未命中: {self.stats['auth_ttl_cache_misses']}, "
                   f"跳过失效域名: {self.stats['failed_domains_skipped']}")

        return results

    def _probe_with_cache(self, domain: str, dns_server: str, auth_dns: str) -> Optional[ProbeResult]:
        """
        使用缓存的权威TTL进行探测

        Args:
            domain: 域名
            dns_server: DNS服务器
            auth_dns: 权威DNS

        Returns:
            探测结果
        """
        # 获取缓存的权威TTL
        auth_ttl = self.get_cached_auth_ttl(domain, auth_dns)
        if auth_ttl is None:
            return None

        # 执行探测（使用缓存的auth_ttl，避免重复查询）
        result = self.probe.probe_ttl_compare(domain, dns_server, auth_dns, cached_auth_ttl=auth_ttl)
        return result

    def stage2_log_analysis(self, detections: List[Dict]) -> List[Dict]:
        """
        Stage 2: 日志分析（占位实现）
        """
        logger.info(f"[Stage 2] 日志分析（占位）: {len(detections)} 个检测事件")

        enriched = []
        for detection in detections:
            detection['log_analysis'] = {
                'status': 'not_implemented',
                'message': '日志分析功能需要集成企业SIEM系统'
            }
            enriched.append(detection)

        return enriched

    def stage3_response(self, detections: List[Dict]):
        """Stage 3: 响应和处置"""
        logger.info(f"[Stage 3] 响应处置: {len(detections)} 个检测事件")

        if not detections:
            logger.info("无检测事件，无需响应")
            return

        # 告警
        if self.config.get('alerting', {}).get('enabled', True):
            self._send_alerts(detections)

    def run_detection(self, mode: str = 'quick'):
        """运行检测"""
        logger.info(f"========== 开始DNS缓存探测威胁检测 (V2优化版) ==========")
        logger.info(f"模式: {mode}")
        logger.info(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # 重置统计
        self.stats = {k: 0 for k in self.stats}

        # 加载威胁情报
        self.load_threat_intel()

        # 获取待检测域名
        domains = self.threat_intel.get_domains()
        if not domains:
            logger.error("无IOC数据，退出")
            return

        # 获取企业DNS服务器
        dns_servers = self.config['dns']['enterprise']

        logger.info(f"待检测: {len(domains)} 个威胁域名")
        logger.info(f"目标DNS: {dns_servers}")

        # Stage 1: 快速探测
        start_time = time.time()
        probe_results = self.stage1_quick_probe(domains, dns_servers)
        elapsed = time.time() - start_time

        # Stage 2: 日志分析
        if self.detections:
            enriched = self.stage2_log_analysis(self.detections)
            self.detections = enriched

        # Stage 3: 响应
        self.stage3_response(self.detections)

        # 汇总
        logger.info(f"========== 检测完成 ==========")
        logger.info(f"探测次数: {len(probe_results)}")
        logger.info(f"威胁检测: {len(self.detections)}")
        logger.info(f"耗时: {elapsed:.1f}秒")
        logger.info(f"速度: {len(probe_results)/elapsed:.1f} 次/秒")
        logger.info(f"自动验证: {self.stats['auto_verifications']} 次")
        logger.info(f"验证通过: {self.stats['verified_threats']} 次")

        return self.detections

    def _calculate_severity(self, probe_result: ProbeResult, ioc: IOC) -> str:
        """计算威胁严重程度"""
        if not ioc:
            return 'low'

        if ioc.category in ['apt', 'ransomware']:
            return 'critical'
        elif ioc.category in ['c2', 'malware']:
            return 'high'
        elif ioc.category in ['phishing']:
            return 'medium'
        else:
            return 'low'

    def _send_alerts(self, detections: List[Dict]):
        """发送告警"""
        methods = self.config.get('alerting', {}).get('methods', [])

        for method in methods:
            if not method.get('enabled', True):
                continue

            if method['type'] == 'console':
                self._alert_console(detections)
            elif method['type'] == 'file':
                self._alert_file(detections, method['path'])
            elif method['type'] == 'dingtalk':
                self._alert_dingtalk(detections, method.get('webhook'))

    def _alert_console(self, detections: List[Dict]):
        """控制台告警"""
        print("\n" + "="*70)
        print("[ALERT] DNS缓存探测威胁检测告警 (V2)")
        print("="*70)
        print(f"检测时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"威胁数量: {len(detections)}")
        print("-"*70)

        for det in detections:
            ioc_info = det.get('ioc', {}) or {}
            verified = det.get('auto_verified', False)

            print(f"\n域名: {det['domain']}")
            print(f"DNS服务器: {det['dns_server']}")
            print(f"类别: {ioc_info.get('category', 'unknown')}")
            print(f"严重程度: {det['severity']}")
            print(f"自动验证: {'[+] 通过' if verified else '[!] 未验证'}")
            if det.get('cache_age_seconds'):
                print(f"缓存年龄: {det['cache_age_seconds']} 秒前解析")

        print("="*70 + "\n")

    def _alert_file(self, detections: List[Dict], file_path: str):
        """文件告警"""
        import os
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(f"\n[{datetime.now().isoformat()}] 检测到 {len(detections)} 个威胁\n")
            for det in detections:
                verified = "[+]verified" if det.get('auto_verified') else "[!]unverified"
                f.write(f"  - {det['domain']} @ {det['dns_server']} "
                       f"[{det['severity']}] {verified}\n")

    def _alert_dingtalk(self, detections: List[Dict], webhook: str):
        """钉钉告警"""
        if not webhook:
            logger.warning("[钉钉告警] 未配置webhook，跳过")
            return

        try:
            import requests

            # 构造钉钉消息
            verified_count = sum(1 for d in detections if d.get('auto_verified'))

            text = f"### [ALERT] DNS威胁检测告警\n\n"
            text += f"**检测时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            text += f"**威胁数量**: {len(detections)} 个\n\n"
            text += f"**自动验证**: {verified_count}/{len(detections)} 通过\n\n"
            text += f"---\n\n"

            for det in detections[:5]:  # 最多显示5个
                ioc_info = det.get('ioc', {}) or {}
                verified = "[+]" if det.get('auto_verified') else "[!]"
                text += f"**{verified} {det['domain']}**\n"
                text += f"- DNS: {det['dns_server']}\n"
                text += f"- 类别: {ioc_info.get('category', 'unknown')}\n"
                text += f"- 严重: {det['severity']}\n\n"

            if len(detections) > 5:
                text += f"*...还有 {len(detections)-5} 个威胁，请查看详细报告*\n"

            message = {
                "msgtype": "markdown",
                "markdown": {
                    "title": "DNS威胁检测告警",
                    "text": text
                }
            }

            response = requests.post(webhook, json=message, timeout=5)
            if response.status_code == 200:
                logger.info(f"[钉钉告警] 发送成功")
            else:
                logger.error(f"[钉钉告警] 发送失败: {response.text}")

        except Exception as e:
            logger.error(f"[钉钉告警] 发送异常: {e}")


if __name__ == "__main__":
    # 测试代码
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )

    detector = ThreatDetectorV2()
    detector.run_detection()
