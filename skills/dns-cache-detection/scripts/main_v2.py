#!/usr/bin/env python3
"""
DNS缓存探测威胁检测系统 V2 - 主程序
运行: python3 main_v2.py --config config_soe.yaml
"""

import argparse
import logging
import sys
import os
from pathlib import Path

# 导入同目录下的模块
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from detector_v2 import ThreatDetectorV2


def setup_logging(level: str = "INFO", log_file: str = None):
    """配置日志系统"""
    log_level = getattr(logging, level.upper(), logging.INFO)

    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='DNS缓存探测威胁检测系统 V2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用央企DNS配置运行快速检测
  python3 main_v2.py --config config_soe.yaml

  # 深度检测模式
  python3 main_v2.py --config config_soe.yaml --mode deep

  # 启用详细日志
  python3 main_v2.py --config config_soe.yaml --verbose

V2版本改进:
  [+] 权威TTL缓存 - 避免重复查询，提升性能
  [+] 失效域名黑名单 - 自动跳过超时域名
  [+] 超时优化 - 从5秒降至2秒
  [+] 自动验证机制 - 缓存命中自动二次验证
  [+] 钉钉实时告警 - 威胁快速响应

配置文件说明:
  config_soe.yaml - 央企DNS服务器配置（7家央企，19台DNS）
  config.yaml     - 本地测试配置
        """
    )

    parser.add_argument(
        '--config', '-c',
        default='config.yaml',
        help='配置文件路径 (默认: config.yaml)'
    )

    parser.add_argument(
        '--mode', '-m',
        choices=['quick', 'deep'],
        default='quick',
        help='检测模式 (quick=快速探测, deep=深度检测)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='启用详细日志输出'
    )

    args = parser.parse_args()

    # 配置日志
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(level=log_level, log_file="logs/dns_detector_v2.log")

    logger = logging.getLogger(__name__)

    try:
        # 打印启动信息
        logger.info("=" * 70)
        logger.info("DNS缓存探测威胁检测系统 V2 (优化版)")
        logger.info("=" * 70)
        logger.info(f"配置文件: {args.config}")
        logger.info(f"检测模式: {args.mode}")
        logger.info(f"日志级别: {log_level}")
        logger.info("")

        # 初始化检测器
        detector = ThreatDetectorV2(config_file=args.config)

        # 运行检测
        detector.run_detection(mode=args.mode)

        # 输出性能统计
        logger.info("")
        logger.info("=" * 70)
        logger.info("性能统计 (V2优化效果)")
        logger.info("=" * 70)

        stats = detector.stats
        logger.info(f"权威TTL缓存命中: {stats['auth_ttl_cache_hits']}")
        logger.info(f"权威TTL缓存未命中: {stats['auth_ttl_cache_misses']}")

        total_queries = stats['auth_ttl_cache_hits'] + stats['auth_ttl_cache_misses']
        if total_queries > 0:
            hit_rate = stats['auth_ttl_cache_hits'] / total_queries * 100
            logger.info(f"缓存命中率: {hit_rate:.1f}%")

        logger.info(f"失效域名已跳过: {stats['failed_domains_skipped']}")
        logger.info(f"自动验证次数: {stats['auto_verifications']}")
        logger.info(f"验证确认威胁: {stats['verified_threats']}")

        # 输出检测结果
        logger.info("")
        logger.info("=" * 70)
        logger.info("检测结果")
        logger.info("=" * 70)

        if detector.detections:
            logger.warning(f"[!] 发现 {len(detector.detections)} 个潜在威胁!")

            for i, det in enumerate(detector.detections, 1):
                verified = "[+] 已验证" if det.get('auto_verified') else "[!] 未验证"
                ioc_info = det.get('ioc', {}) or {}
                category = ioc_info.get('category', 'unknown')

                logger.warning(
                    f"  [{i}] {verified} {det['domain']}\n"
                    f"      DNS服务器: {det['dns_server']}\n"
                    f"      威胁类别: {category}\n"
                    f"      缓存年龄: {det.get('cache_age_seconds', 0)} 秒\n"
                    f"      严重程度: {det.get('severity', 'unknown')}"
                )

            logger.warning(f"\n详细报告已保存至 reports/ 目录")

        else:
            logger.info("[+] 未发现威胁，所有检测均正常")

        logger.info("")
        logger.info("=" * 70)
        logger.info("检测完成")
        logger.info("=" * 70)

    except FileNotFoundError as e:
        logger.error(f"配置文件不存在: {e}")
        sys.exit(1)

    except KeyboardInterrupt:
        logger.warning("\n检测被用户中断")
        sys.exit(130)

    except Exception as e:
        logger.error(f"检测过程发生错误: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
