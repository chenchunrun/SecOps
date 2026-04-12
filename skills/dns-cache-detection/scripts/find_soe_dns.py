#!/usr/bin/env python3
"""
查找央企DNS服务器
通过查询企业域名的NS记录来获取其DNS服务器
"""

import dns.resolver
import dns.query
import dns.message
import logging
from typing import List, Dict, Tuple
import socket

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)


# 央企域名列表
SOE_DOMAINS = {
    "国家电网": "sgcc.com.cn",
    "中国石油": "petrochina.com.cn",
    "南方电网": "csg.cn",
    "工商银行": "icbc.com.cn",
    "中国海油": "cnooc.com.cn",
    # 额外测试
    "建设银行": "ccb.com",
    "中国移动": "10086.cn",
    "中石化": "sinopec.com",
    "中国建筑": "cscec.com",
}


def query_ns_records(domain: str) -> List[str]:
    """查询域名的NS记录"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, 'NS')
        return [str(rdata).rstrip('.') for rdata in answers]
    except Exception as e:
        logger.debug(f"NS查询失败 {domain}: {e}")
        return []


def resolve_to_ip(hostname: str) -> List[str]:
    """将域名解析为IP"""
    ips = []
    try:
        # A记录
        answers = dns.resolver.resolve(hostname, 'A', lifetime=5)
        ips.extend([str(rdata) for rdata in answers])
    except:
        pass

    try:
        # AAAA记录
        answers = dns.resolver.resolve(hostname, 'AAAA', lifetime=5)
        ips.extend([str(rdata) for rdata in answers])
    except:
        pass

    return ips


def test_dns_server(dns_ip: str, test_domain: str = 'www.baidu.com') -> bool:
    """测试DNS服务器是否可用"""
    try:
        query = dns.message.make_query(test_domain, dns.rdatatype.A)
        response = dns.query.udp(query, dns_ip, timeout=3)
        return response.answer is not None and len(response.answer) > 0
    except:
        return False


def check_dns_port(ip: str, port: int = 53) -> bool:
    """检查DNS端口是否开放"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        # 发送简单的DNS查询
        query = dns.message.make_query('test.com', dns.rdatatype.A)
        sock.sendto(query.to_wire(), (ip, port))
        data, _ = sock.recvfrom(512)
        sock.close()
        return len(data) > 0
    except:
        return False


def find_soe_dns():
    """查找央企DNS服务器"""
    print("\n" + "="*80)
    print("[*] 央企DNS服务器查找工具")
    print("="*80)

    all_results = {}

    for company, domain in SOE_DOMAINS.items():
        print(f"\n【{company}】 {domain}")
        print("-" * 80)

        # 1. 查询NS记录
        print("  [*] 查询NS记录...")
        ns_records = query_ns_records(domain)

        if not ns_records:
            print("  [-] 未找到NS记录（可能域名不存在或被保护）")
            all_results[company] = {
                'domain': domain,
                'ns_records': [],
                'dns_servers': []
            }
            continue

        print(f"  [+] 找到 {len(ns_records)} 个NS记录:")
        for ns in ns_records:
            print(f"     - {ns}")

        # 2. 解析NS记录到IP
        print("\n  [*] 解析NS域名到IP...")
        dns_servers = []

        for ns in ns_records:
            ips = resolve_to_ip(ns)
            if ips:
                print(f"     {ns}")
                for ip in ips:
                    # 测试DNS服务器
                    is_accessible = check_dns_port(ip)
                    status = "[+] 可访问" if is_accessible else "[x] 受限"
                    print(f"       → {ip} [{status}]")

                    dns_servers.append({
                        'ns_domain': ns,
                        'ip': ip,
                        'accessible': is_accessible
                    })

        all_results[company] = {
            'domain': domain,
            'ns_records': ns_records,
            'dns_servers': dns_servers
        }

    return all_results


def generate_summary(results: Dict):
    """生成汇总报告"""
    print("\n\n" + "="*80)
    print("[*] 央企DNS服务器汇总")
    print("="*80)

    accessible_dns = []
    restricted_dns = []

    for company, data in results.items():
        if not data['dns_servers']:
            continue

        print(f"\n【{company}】")
        print(f"  域名: {data['domain']}")
        print(f"  NS记录: {', '.join(data['ns_records'][:3])}")
        print(f"  DNS服务器:")

        for server in data['dns_servers']:
            ip = server['ip']
            status = "[+]" if server['accessible'] else "[x]"
            print(f"    {status} {ip} ({server['ns_domain']})")

            if server['accessible']:
                accessible_dns.append((company, ip))
            else:
                restricted_dns.append((company, ip))

    # 可用DNS列表
    print("\n\n" + "="*80)
    print("[*] 可用于测试的DNS服务器")
    print("="*80)

    if accessible_dns:
        print("\n[+] 可访问的DNS服务器:")
        for company, ip in accessible_dns:
            print(f"  - {ip:20s} ({company})")

        print("\n[*] 添加到 config.yaml:")
        print("-" * 80)
        print("dns:")
        print("  enterprise:")
        for company, ip in accessible_dns[:5]:  # 只显示前5个
            print(f'    - "{ip}"  # {company}')
        print("-" * 80)

    else:
        print("\n[!] 未找到可访问的央企DNS服务器")
        print("\n可能原因:")
        print("  1. 这些DNS服务器仅限内网访问")
        print("  2. 被防火墙阻止外部查询")
        print("  3. 企业安全策略限制")

    if restricted_dns:
        print(f"\n[x] 受限访问的DNS服务器 ({len(restricted_dns)}个):")
        for company, ip in restricted_dns[:10]:
            print(f"  - {ip:20s} ({company})")

    # 推荐使用公共DNS测试
    print("\n\n" + "="*80)
    print("[*] 推荐测试方案")
    print("="*80)
    print("""
由于央企DNS服务器通常不对外开放，建议采用以下测试方案:

1. **使用公共DNS模拟测试**
   - 阿里云DNS: 223.5.5.5
   - 腾讯DNSPod: 119.29.29.29
   - Google DNS: 8.8.8.8

2. **内网环境测试**
   - 如果你有央企内网访问权限
   - 使用内网DNS服务器IP（通常是10.x.x.x或192.168.x.x）

3. **运行测试**
   ```bash
   # 编辑 config.yaml 配置DNS
   python main.py --mode quick
   ```
""")


if __name__ == "__main__":
    try:
        results = find_soe_dns()
        generate_summary(results)

        print("\n" + "="*80)
        print("[+] 查找完成")
        print("="*80)

    except KeyboardInterrupt:
        print("\n\n用户中断")
    except Exception as e:
        logger.error(f"查找失败: {e}", exc_info=True)
