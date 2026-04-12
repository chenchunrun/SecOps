#!/usr/bin/env python3
"""
验证真实C2域名IOC
测试这些域名是否可以被解析（验证IOC有效性）
"""

import logging
import os
import sys

# 导入同目录下的模块
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from dns_probe import DNSProbe
from threat_intel import ThreatIntelManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

logger = logging.getLogger(__name__)


def verify_iocs():
    """验证真实IOC的可解析性"""
    print("\n" + "="*70)
    print("[*] 验证真实C2域名IOC")
    print("="*70)

    # 加载IOC
    print("\n1. 加载真实C2域名IOC...")
    manager = ThreatIntelManager()
    count = manager.load_from_file("iocs/real_c2_domains.txt")
    print(f"   [+] 加载了 {count} 个C2域名")

    # 获取域名列表
    domains = manager.get_domains()

    # 统计信息
    stats = manager.get_statistics()
    print(f"\n2. IOC统计:")
    print(f"   总计: {stats['total']} 个")
    print(f"   域名: {stats['domains']} 个")

    # 测试域名解析
    print(f"\n3. 测试域名可解析性 (使用阿里云DNS)...")
    print(f"   注意: 可解析不代表域名仍然活跃，只是验证IOC格式正确")

    probe = DNSProbe(timeout=5)
    test_domains = domains[:10]  # 测试前10个

    resolvable = []
    unresolvable = []
    errors = []

    for i, domain in enumerate(test_domains, 1):
        print(f"\n   [{i}/{len(test_domains)}] 测试: {domain}")

        # 尝试获取TTL（验证域名是否可解析）
        ttl = probe.get_authoritative_ttl(domain, "223.5.5.5")

        if ttl is not None:
            resolvable.append(domain)
            print(f"       [+] 可解析 (TTL: {ttl}秒)")
        else:
            # 可能是已失效的域名或格式错误
            unresolvable.append(domain)
            print(f"       [-] 无法解析 (可能已失效)")

    # 统计结果
    print("\n" + "="*70)
    print("[*] 验证结果汇总:")
    print("="*70)
    print(f"测试域名数: {len(test_domains)}")
    print(f"可解析: {len(resolvable)} ({len(resolvable)/len(test_domains)*100:.1f}%)")
    print(f"不可解析: {len(unresolvable)} ({len(unresolvable)/len(test_domains)*100:.1f}%)")

    if resolvable:
        print(f"\n[+] 可解析域名示例:")
        for domain in resolvable[:5]:
            print(f"   - {domain}")

    if unresolvable:
        print(f"\n[!] 不可解析域名 (可能已失效或被封禁):")
        for domain in unresolvable[:5]:
            print(f"   - {domain}")

    print("\n" + "="*70)
    print("说明:")
    print("- [+] 可解析: 域名仍然存在于DNS系统中")
    print("- [-] 不可解析: 域名可能已失效、被封禁或IOC格式错误")
    print("- 即使可解析，也不代表C2服务器仍在运行")
    print("- 这些是真实的恶意域名，请勿访问！")
    print("="*70)


def demo_detection():
    """演示使用真实IOC进行检测"""
    print("\n" + "="*70)
    print("[*] 演示: 使用真实IOC进行DNS缓存探测")
    print("="*70)

    print("\n注意:")
    print("- 以下演示使用公共DNS (223.5.5.5) 模拟企业DNS")
    print("- 实际使用时应配置真实的企业内网DNS")
    print("- 如果检测到缓存命中，说明该域名近期被解析过")

    from detector import ThreatDetector

    print("\n开始检测...")
    print("-"*70)

    try:
        detector = ThreatDetector('config.yaml')

        # 修改配置使用公共DNS（演示用）
        detector.config['dns']['enterprise'] = ['223.5.5.5']

        # 运行检测（只测试前5个域名以节省时间）
        detector.load_threat_intel()
        domains = detector.threat_intel.get_domains()[:5]

        print(f"\n测试域名: {len(domains)} 个")
        for domain in domains:
            print(f"  - {domain}")

        print("\n正在探测...")
        results = detector.stage1_quick_probe(
            domains,
            detector.config['dns']['enterprise']
        )

        # 分析结果
        cached_results = [r for r in results if r.is_cached]

        print("\n" + "="*70)
        print("检测结果:")
        print("="*70)
        print(f"总探测: {len(results)} 次")
        print(f"缓存命中: {len(cached_results)} 次")

        if cached_results:
            print("\n[!] 发现缓存命中:")
            for r in cached_results:
                print(f"  - {r.domain}")
                print(f"    缓存TTL: {r.cached_ttl}秒")
        else:
            print("\n[+] 未发现缓存命中（正常）")

    except Exception as e:
        logger.error(f"检测失败: {e}", exc_info=True)


if __name__ == "__main__":
    print("\n" + "="*70)
    print("[*] DNS缓存探测系统 - 真实IOC验证")
    print("="*70)

    try:
        # 验证IOC
        verify_iocs()

        # 演示检测
        demo_detection()

        print("\n" + "="*70)
        print("[+] 验证完成!")
        print("="*70)
        print("\n下一步:")
        print("1. 配置你的企业DNS: 编辑 config.yaml")
        print("2. 运行完整检测: python main.py --mode quick")
        print("3. 查看检测报告: reports/")
        print()

    except KeyboardInterrupt:
        print("\n\n用户中断")
    except Exception as e:
        logger.error(f"验证失败: {e}", exc_info=True)
