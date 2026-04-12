#!/usr/bin/env python3
"""
测试detector_v2.py的性能改进
对比V1和V2的性能差异
"""

import time
import logging
import os
import sys

# 导入同目录下的模块
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from detector_v2 import ThreatDetectorV2

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def test_v2_performance():
    """测试V2版本的性能改进"""
    logger.info("========== 测试 Detector V2 性能改进 ==========")

    # 初始化检测器
    detector = ThreatDetectorV2(config_file='config_soe.yaml')

    # 记录开始时间
    start_time = time.time()

    # 运行检测（quick模式）
    detector.run_detection(mode='quick')

    # 记录结束时间
    end_time = time.time()
    elapsed = end_time - start_time

    # 输出性能统计
    logger.info(f"\n========== 性能统计 ==========")
    logger.info(f"总耗时: {elapsed:.2f} 秒")
    logger.info(f"\n缓存命中统计:")
    logger.info(f"  权威TTL缓存命中: {detector.stats['auth_ttl_cache_hits']}")
    logger.info(f"  权威TTL缓存未命中: {detector.stats['auth_ttl_cache_misses']}")

    # 计算缓存命中率
    total_queries = detector.stats['auth_ttl_cache_hits'] + detector.stats['auth_ttl_cache_misses']
    if total_queries > 0:
        hit_rate = detector.stats['auth_ttl_cache_hits'] / total_queries * 100
        logger.info(f"  缓存命中率: {hit_rate:.1f}%")

    logger.info(f"\n优化统计:")
    logger.info(f"  失效域名已跳过: {detector.stats['failed_domains_skipped']}")
    logger.info(f"  自动验证次数: {detector.stats['auto_verifications']}")
    logger.info(f"  验证确认威胁: {detector.stats['verified_threats']}")

    # 检测结果
    logger.info(f"\n检测结果:")
    logger.info(f"  缓存命中总数: {len(detector.detections)}")

    if detector.detections:
        logger.info(f"\n威胁详情:")
        for det in detector.detections:
            verified = "[+] 已验证" if det.get('auto_verified') else "[!] 未验证"
            logger.info(
                f"  {verified} {det['domain']} @ {det['dns_server']} "
                f"(缓存年龄: {det.get('cache_age_seconds', 0)}秒)"
            )

    # 性能对比估算
    logger.info(f"\n========== 性能改进估算 ==========")

    # V1预估：每个域名都需要查询权威TTL
    # V2实际：使用缓存，大幅减少权威TTL查询次数

    total_probes = total_queries
    saved_queries = detector.stats['auth_ttl_cache_hits']

    if saved_queries > 0:
        improvement = saved_queries / total_probes * 100
        logger.info(f"权威TTL查询减少: {saved_queries}/{total_probes} ({improvement:.1f}%)")

    # 失效域名跳过
    if detector.stats['failed_domains_skipped'] > 0:
        logger.info(f"失效域名跳过: {detector.stats['failed_domains_skipped']} 次探测")

    logger.info(f"\n测试完成!")

    return detector


def test_auto_verification():
    """测试自动验证功能"""
    logger.info("\n========== 测试自动验证功能 ==========")

    # 读取配置，确保auto_verify_threats启用
    import yaml
    with open('config_soe.yaml', 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    # 检查是否启用自动验证
    auto_verify = config.get('advanced', {}).get('auto_verify_threats', False)

    if auto_verify:
        logger.info("[+] 自动验证已启用")
    else:
        logger.warning("[!] 自动验证未启用，在config_soe.yaml中添加:")
        logger.warning("""
advanced:
  auto_verify_threats: true
        """)

    return auto_verify


if __name__ == '__main__':
    # 测试自动验证配置
    test_auto_verification()

    # 运行性能测试
    detector = test_v2_performance()

    # 输出最终报告
    logger.info("\n========== 最终总结 ==========")
    logger.info("Detector V2 改进点:")
    logger.info("[+] 1. 权威TTL缓存 - 避免重复查询")
    logger.info("[+] 2. 失效域名黑名单 - 跳过超时域名")
    logger.info("[+] 3. 优化超时时间 - 从5秒降至2秒")
    logger.info("[+] 4. 自动验证机制 - 自动确认威胁")
    logger.info("[+] 5. 钉钉实时告警 - 快速响应")

    if detector.detections:
        logger.info(f"\n[!] 发现 {len(detector.detections)} 个潜在威胁，请查看详细报告")
