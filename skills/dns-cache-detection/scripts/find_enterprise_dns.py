#!/usr/bin/env python3
"""
查找央企DNS服务器
通过cyberspace搜索到的央企IP，反向查询其DNS服务器
"""

import dns.resolver
import dns.reversename
import logging
from typing import List, Dict, Set
import socket

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


# 从cyberspace搜索到的央企IP
ENTERPRISE_IPS = {
    "中国移动": [
        "183.207.44.251",  # www.10086.cn
        "36.160.2.81",
        "36.160.2.82",
        "36.160.2.83",
        "218.205.68.11",  # zj.10086.cn
        "218.205.68.12",
        "218.205.68.13",
        "221.178.251.155", # www.js.10086.cn
        "211.141.0.165",   # jl.10086.cn
        "117.134.60.51",   # hl.10086.cn
    ],
    "建设银行": [
        "42.240.11.133",   # mall.ccb.com
        "42.240.11.186",   # sft.ccb.com
        "42.240.10.230",
        "58.49.73.39",     # bjxffp.ccb.com
        "114.251.248.95",  # search.ccb.com
    ],
    "中石化": [
        "36.112.48.132",   # 多个sinopec.com子域
        "123.114.232.64",
        "111.56.240.24",   # chat.sinopec.com
        "111.56.240.49",   # job.sinopec.com
        "1.180.19.71",     # thy.sinopec.com
    ],
}


def get_dns_servers_from_resolv_conf() -> List[str]:
    """从系统配置获取DNS服务器（仅Linux/macOS）"""
    dns_servers = []
    try:
        with open('/etc/resolv.conf', 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns_server = line.split()[1]
                    dns_servers.append(dns_server)
    except:
        pass
    return dns_servers


def reverse_dns_lookup(ip: str) -> str:
    """
    反向DNS查询
    返回PTR记录（域名）
    """
    try:
        addr = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(addr, 'PTR')
        return str(answers[0]) if answers else None
    except Exception as e:
        logger.debug(f"反向DNS查询失败 {ip}: {e}")
        return None


def query_ns_records(domain: str) -> List[str]:
    """
    查询域名的NS记录（权威DNS服务器）
    """
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        ns_records = [str(rdata) for rdata in answers]
        return ns_records
    except Exception as e:
        logger.debug(f"NS查询失败 {domain}: {e}")
        return []


def resolve_ns_to_ip(ns_domain: str) -> List[str]:
    """
    将NS域名解析为IP地址
    """
    ips = []
    try:
        answers = dns.resolver.resolve(ns_domain, 'A')
        ips = [str(rdata) for rdata in answers]
    except:
        pass

    # 尝试AAAA记录
    try:
        answers = dns.resolver.resolve(ns_domain, 'AAAA')
        ips.extend([str(rdata) for rdata in answers])
    except:
        pass

    return ips


def check_dns_port(ip: str, port: int = 53, timeout: int = 2) -> bool:
    """
    检查IP的DNS端口是否开放
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'\x00' * 12, (ip, port))  # 简单的DNS查询包
        sock.recvfrom(512)
        sock.close()
        return True
    except:
        return False


def find_enterprise_dns_servers():
    """
    查找央企的DNS服务器
    """
    print("\n" + "="*70)
    print("[*] 查找央企DNS服务器")
    print("="*70)

    all_dns_servers: Dict[str, Set[str]] = {}

    for enterprise, ips in ENTERPRISE_IPS.items():
        print(f"\n【{enterprise}】")
        print(f"已知IP: {len(ips)} 个")

        dns_servers = set()
        domains = set()

        # 1. 反向DNS查询获取域名
        print("\n1. 反向DNS查询...")
        for ip in ips[:3]:  # 只测试前3个以节省时间
            ptr = reverse_dns_lookup(ip)
            if ptr:
                domains.add(ptr.rstrip('.'))
                print(f"   {ip} → {ptr}")

        # 2. 从域名查询NS记录
        print("\n2. 查询NS记录...")
        for domain in list(domains)[:2]:  # 只测试前2个域名
            # 提取主域名
            parts = domain.split('.')
            if len(parts) >= 2:
                main_domain = '.'.join(parts[-2:])
                print(f"   查询 {main_domain} 的NS记录...")

                ns_records = query_ns_records(main_domain)
                if ns_records:
                    print(f"   NS记录: {ns_records}")

                    # 3. 将NS域名解析为IP
                    for ns in ns_records[:2]:  # 只解析前2个NS
                        ns_ips = resolve_ns_to_ip(ns)
                        if ns_ips:
                            dns_servers.update(ns_ips)
                            print(f"      {ns} → {ns_ips}")

        # 4. 尝试常见的DNS IP段
        print("\n3. 探测常见DNS服务器...")
        # 基于已知IP推测DNS服务器（通常在同一网段）
        for ip in ips[:2]:
            parts = ip.split('.')
            base = '.'.join(parts[:3])

            # 尝试 .1, .2, .53 等常见DNS IP
            for last in ['1', '2', '53', '253', '254']:
                test_ip = f"{base}.{last}"
                if check_dns_port(test_ip, timeout=1):
                    dns_servers.add(test_ip)
                    print(f"   [+] 发现DNS服务器: {test_ip}")

        all_dns_servers[enterprise] = dns_servers

        # 汇总
        print(f"\n[*] {enterprise} DNS服务器:")
        if dns_servers:
            for dns_ip in sorted(dns_servers):
                print(f"   - {dns_ip}")
        else:
            print(f"   未找到（可能受防火墙限制）")

    return all_dns_servers


def generate_config(dns_servers: Dict[str, Set[str]]):
    """
    生成配置文件
    """
    print("\n" + "="*70)
    print("[*] 生成配置文件")
    print("="*70)

    # 整合所有DNS服务器
    all_dns = set()
    for servers in dns_servers.values():
        all_dns.update(servers)

    if not all_dns:
        print("[!] 未找到任何DNS服务器")
        print("\n建议:")
        print("1. 这些央企可能使用内网DNS（外部无法访问）")
        print("2. 可以使用公共DNS模拟测试: 223.5.5.5, 119.29.29.29")
        print("3. 如有企业内网访问权限，请手动配置内网DNS")
        return

    print(f"\n找到 {len(all_dns)} 个DNS服务器:")
    for dns_ip in sorted(all_dns):
        print(f"  - {dns_ip}")

    print("\n可以将以下配置添加到 config.yaml:")
    print("-"*70)
    print("dns:")
    print("  enterprise:")
    for dns_ip in sorted(all_dns):
        print(f"    - \"{dns_ip}\"")
    print("-"*70)


def test_dns_resolution(dns_server: str):
    """
    测试DNS服务器是否可用
    """
    print(f"\n测试DNS服务器: {dns_server}")

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    resolver.timeout = 3
    resolver.lifetime = 3

    test_domains = ['www.baidu.com', 'www.qq.com']

    for domain in test_domains:
        try:
            answers = resolver.resolve(domain, 'A')
            print(f"  [+] {domain} -> {answers[0]}")
            return True
        except Exception as e:
            print(f"  [-] {domain}: {e}")

    return False


if __name__ == "__main__":
    print("\n" + "="*70)
    print("[*] 央企DNS服务器查找工具")
    print("="*70)
    print("\n说明:")
    print("- 基于cyberspace搜索结果，查找央企的DNS服务器")
    print("- 包含: 中国移动、建设银行、中石化")
    print("- 方法: 反向DNS查询 + NS记录查询 + 端口探测")

    try:
        # 查找DNS服务器
        dns_servers = find_enterprise_dns_servers()

        # 生成配置
        generate_config(dns_servers)

        print("\n" + "="*70)
        print("[+] 查找完成")
        print("="*70)
        print("\n[!] 重要提示:")
        print("1. 央企内网DNS通常不对外开放")
        print("2. 即使找到IP，也可能受防火墙限制无法访问")
        print("3. 建议在企业内网环境中运行DNS缓存探测")
        print("4. 可使用公共DNS (223.5.5.5) 模拟测试系统功能")

    except KeyboardInterrupt:
        print("\n\n用户中断")
    except Exception as e:
        logger.error(f"查找失败: {e}", exc_info=True)
