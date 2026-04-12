#!/usr/bin/env python3
"""
DNS缓存探测威胁检测器
整合DNS探测和威胁情报，执行三阶段检测
"""

import logging
import os
import sys
from typing import List, Dict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml

# 导入同目录下的模块
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from dns_probe import DNSProbe, ProbeResult, analyze_probe_results
from threat_intel import ThreatIntelManager, IOC

logger = logging.getLogger(__name__)


class ThreatDetector:
    """DNS缓存探测威胁检测器"""

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
        Stage 1: 快速探测

        使用RD=0或TTL对比快速判断域名是否在企业DNS缓存中

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
                for dns_server in dns_servers:
                    if use_ttl:
                        future = executor.submit(
                            self.probe.probe_ttl_compare,
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
                    results.append(probe_result)

                    # 记录缓存命中
                    if probe_result.is_cached:
                        ioc = self.threat_intel.get_ioc(probe_result.domain)
                        detection = {
                            'stage': 1,
                            'timestamp': probe_result.timestamp,
                            'domain': probe_result.domain,
                            'dns_server': probe_result.dns_server,
                            'is_cached': True,
                            'cache_age_seconds': probe_result.cache_age_seconds,
                            'ioc': ioc.__dict__ if ioc else None,
                            'severity': self._calculate_severity(probe_result, ioc)
                        }
                        self.detections.append(detection)

                        logger.warning(
                            f"[检测] {probe_result.domain} 在 {probe_result.dns_server} 发现缓存! "
                            f"类别: {ioc.category if ioc else 'unknown'}"
                        )

                except Exception as e:
                    logger.error(f"探测任务执行失败: {e}")

        cached_count = sum(1 for r in results if r.is_cached)
        logger.info(f"[Stage 1] 完成: {len(results)} 次探测, {cached_count} 次缓存命中")

        return results

    def stage2_log_analysis(self, detections: List[Dict]) -> List[Dict]:
        """
        Stage 2: 日志分析（占位实现）

        当Stage 1检测到缓存命中时，触发日志分析：
        - 查询DNS日志确认解析时间
        - 提取源IP地址
        - 关联其他威胁情报

        注: 需要集成企业SIEM/日志系统

        Args:
            detections: Stage 1的检测结果

        Returns:
            增强的检测结果
        """
        logger.info(f"[Stage 2] 日志分析（占位）: {len(detections)} 个检测事件")

        # TODO: 实际实现需要：
        # 1. 连接企业日志系统（Splunk/ELK/等）
        # 2. 根据域名和时间范围查询DNS日志
        # 3. 提取客户端IP、查询时间等元数据
        # 4. 关联资产信息（IP -> 主机名 -> 用户）

        enriched = []
        for detection in detections:
            # 模拟日志查询结果
            detection['log_analysis'] = {
                'status': 'not_implemented',
                'message': '日志分析功能需要集成企业SIEM系统'
            }
            enriched.append(detection)

        return enriched

    def stage3_response(self, detections: List[Dict]):
        """
        Stage 3: 响应和处置

        根据检测结果采取行动：
        - 生成告警
        - 隔离主机
        - 阻断域名

        Args:
            detections: 检测结果
        """
        logger.info(f"[Stage 3] 响应处置: {len(detections)} 个检测事件")

        if not detections:
            logger.info("无检测事件，无需响应")
            return

        # 告警
        if self.config.get('alerting', {}).get('enabled', True):
            self._send_alerts(detections)

        # TODO: 集成响应动作
        # - 调用防火墙API阻断域名
        # - 调用EDR隔离主机
        # - 发送工单到安全运营中心

    def run_detection(self, mode: str = 'quick'):
        """
        运行检测

        Args:
            mode: 检测模式（quick/full/continuous）
        """
        logger.info(f"========== 开始DNS缓存探测威胁检测 ==========")
        logger.info(f"模式: {mode}")
        logger.info(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

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
        probe_results = self.stage1_quick_probe(domains, dns_servers)

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

        return self.detections

    def _calculate_severity(self, probe_result: ProbeResult, ioc: IOC) -> str:
        """
        计算威胁严重程度

        Args:
            probe_result: 探测结果
            ioc: IOC信息

        Returns:
            严重程度：critical/high/medium/low
        """
        if not ioc:
            return 'low'

        # 根据IOC类别判断
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

    def _alert_console(self, detections: List[Dict]):
        """控制台告警"""
        print("\n" + "="*70)
        print("[ALERT] DNS缓存探测威胁检测告警")
        print("="*70)
        print(f"检测时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"威胁数量: {len(detections)}")
        print("-"*70)

        for det in detections:
            ioc_info = det.get('ioc', {}) or {}
            print(f"\n域名: {det['domain']}")
            print(f"DNS服务器: {det['dns_server']}")
            print(f"类别: {ioc_info.get('category', 'unknown')}")
            print(f"严重程度: {det['severity']}")
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
                f.write(f"  - {det['domain']} @ {det['dns_server']} "
                       f"[{det['severity']}]\n")


if __name__ == "__main__":
    # 测试代码
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )

    detector = ThreatDetector()
    detector.run_detection()
