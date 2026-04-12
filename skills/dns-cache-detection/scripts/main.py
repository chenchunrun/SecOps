#!/usr/bin/env python3
"""
DNS缓存探测威胁检测系统 - 主程序
"""

import argparse
import logging
import sys
import os
from datetime import datetime

# 导入同目录下的模块
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from detector import ThreatDetector
from reporter import ReportGenerator
from threat_intel import create_sample_iocs


def setup_logging(level: str = "INFO", log_file: str = None):
    """配置日志"""
    log_level = getattr(logging, level.upper(), logging.INFO)

    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=handlers
    )


def main():
    parser = argparse.ArgumentParser(
        description='DNS缓存探测威胁检测系统',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 快速检测
  python main.py --mode quick

  # 指定配置文件
  python main.py --config custom_config.yaml

  # 创建示例IOC文件
  python main.py --init

  # 详细日志输出
  python main.py --mode quick --verbose

  # 生成HTML报告
  python main.py --mode quick --format json csv html
        """
    )

    parser.add_argument(
        '--config', '-c',
        default='config.yaml',
        help='配置文件路径（默认: config.yaml）'
    )

    parser.add_argument(
        '--mode', '-m',
        choices=['quick', 'full', 'continuous'],
        default='quick',
        help='检测模式: quick=快速检测, full=完整检测, continuous=持续监控（默认: quick）'
    )

    parser.add_argument(
        '--format', '-f',
        nargs='+',
        choices=['json', 'csv', 'html'],
        default=['json', 'csv'],
        help='报告输出格式（默认: json csv）'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='详细日志输出'
    )

    parser.add_argument(
        '--init',
        action='store_true',
        help='初始化：创建示例配置和IOC文件'
    )

    parser.add_argument(
        '--test-dns',
        metavar='DNS_SERVER',
        help='测试DNS服务器是否支持RD=0'
    )

    args = parser.parse_args()

    # 初始化模式
    if args.init:
        print("[*] 初始化DNS缓存探测系统...")
        create_sample_iocs()
        print("[+] 已创建示例IOC文件: iocs/malware_domains.txt")
        print("[*] 请编辑 config.yaml 配置企业DNS服务器地址")
        print("[*] 运行: python main.py --mode quick")
        return

    # 配置日志
    log_level = 'DEBUG' if args.verbose else 'INFO'
    log_file = 'logs/dns_detector.log'
    setup_logging(log_level, log_file)

    logger = logging.getLogger(__name__)
    logger.info("="*70)
    logger.info("DNS缓存探测威胁检测系统 v1.0")
    logger.info("="*70)

    # 测试DNS模式
    if args.test_dns:
        from dns_probe import DNSProbe
        probe = DNSProbe()
        is_supported = probe.check_rd0_support(args.test_dns)

        if is_supported:
            print(f"[+] DNS服务器 {args.test_dns} 支持RD=0探测")
        else:
            print(f"[-] DNS服务器 {args.test_dns} 不支持RD=0（请使用TTL对比模式）")
        return

    # 检查配置文件
    if not os.path.exists(args.config):
        logger.error(f"配置文件不存在: {args.config}")
        logger.info("提示: 运行 'python main.py --init' 初始化")
        sys.exit(1)

    try:
        # 创建检测器
        detector = ThreatDetector(args.config)

        # 运行检测
        detections = detector.run_detection(mode=args.mode)

        # 生成报告
        if detections:
            logger.info("正在生成检测报告...")
            reporter = ReportGenerator(detector.config.get('reporting', {}))
            generated_files = reporter.generate(
                detections,
                formats=args.format
            )

            print("\n" + "="*70)
            print("[*] 检测报告已生成:")
            for fmt, path in generated_files.items():
                print(f"  {fmt.upper()}: {path}")
            print("="*70 + "\n")

        else:
            logger.info("[+] 未检测到威胁")

    except KeyboardInterrupt:
        logger.info("用户中断检测")
        sys.exit(0)

    except Exception as e:
        logger.error(f"检测过程出错: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
