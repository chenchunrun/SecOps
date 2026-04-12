#!/usr/bin/env python3
"""
CDN 检测器 - 识别 IP 是否属于已知 CDN 提供商
用于减少域名分析中的误报（CDN 域名 IP 频繁变化是正常行为）
"""

import ipaddress
import argparse
import json
import sys
from typing import Optional

# CDN IP 段数据库
# 来源: 各 CDN 官方文档 (2025年1月更新)
# Cloudflare: https://www.cloudflare.com/ips-v4
# Fastly: https://api.fastly.com/public-ip-list
# CloudFront: https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips
# Akamai: AS20940 via ipinfo.io, networksdb.io
CDN_RANGES = {
    # Akamai - AS20940 (来源: ipinfo.io/AS20940, networksdb.io)
    # 主要 IP 段，覆盖全球边缘节点
    "Akamai": [
        "104.64.0.0/10",    # 104.64.0.0 - 104.127.255.255 (4,194,304 IPs) - 主要段
        "23.32.0.0/11",     # 23.32.0.0 - 23.63.255.255 (2,097,152 IPs)
        "23.192.0.0/11",    # 23.192.0.0 - 23.223.255.255 (2,097,152 IPs)
        "23.0.0.0/12",      # 23.0.0.0 - 23.15.255.255 (1,048,576 IPs)
        "23.64.0.0/14",     # 23.64.0.0 - 23.67.255.255
        "184.24.0.0/13",    # 184.24.0.0 - 184.31.255.255
        "184.50.0.0/15",    # 184.50.0.0 - 184.51.255.255
        "184.84.0.0/14",    # 184.84.0.0 - 184.87.255.255
        "2.16.0.0/13",      # 欧洲节点 (2.16.0.0 - 2.23.255.255)
        "2.20.0.0/14",      # 欧洲节点 (部分重叠，保留以确保覆盖)
    ],

    # Cloudflare - AS13335 (来源: https://www.cloudflare.com/ips-v4 官方)
    "Cloudflare": [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",    # 104.16.0.0 - 104.23.255.255
        "104.24.0.0/14",    # 104.24.0.0 - 104.27.255.255
        "172.64.0.0/13",    # 172.64.0.0 - 172.71.255.255
        "131.0.72.0/22",
    ],

    # Fastly - AS54113 (来源: https://api.fastly.com/public-ip-list 官方)
    "Fastly": [
        "23.235.32.0/20",
        "43.249.72.0/22",
        "103.244.50.0/24",
        "103.245.222.0/23",
        "103.245.224.0/24",
        "104.156.80.0/20",
        "140.248.64.0/18",
        "140.248.128.0/17",
        "146.75.0.0/17",
        "151.101.0.0/16",   # 主要段
        "157.52.64.0/18",
        "167.82.0.0/17",
        "167.82.128.0/20",
        "167.82.160.0/20",
        "167.82.224.0/20",
        "172.111.64.0/18",
        "185.31.16.0/22",
        "199.27.72.0/21",
        "199.232.0.0/16",   # 主要段
    ],

    # AWS CloudFront - AS16509 (来源: https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips 官方)
    # 仅列出主要段，完整列表有 230+ 个 CIDR
    "CloudFront": [
        "13.32.0.0/15",
        "13.35.0.0/16",
        "13.224.0.0/14",
        "13.249.0.0/16",
        "52.84.0.0/14",
        "52.124.128.0/17",
        "54.182.0.0/16",
        "54.192.0.0/16",
        "54.230.0.0/16",
        "54.239.128.0/18",
        "54.239.192.0/19",
        "70.132.0.0/18",
        "99.84.0.0/16",
        "99.86.0.0/16",
        "143.204.0.0/16",
        "204.246.164.0/22",
        "204.246.168.0/22",
        "205.251.200.0/21",
        "205.251.249.0/24",
        "205.251.250.0/23",
        "205.251.252.0/23",
        "205.251.254.0/24",
        "3.165.0.0/16",
        "3.168.0.0/14",
        "65.9.0.0/17",
        "65.9.128.0/18",
        "120.52.22.96/27",
        "18.64.0.0/14",
        "18.68.0.0/16",
        "18.154.0.0/15",
        "18.160.0.0/15",
        "18.238.0.0/15",
        "18.244.0.0/15",
    ],

    # Google Cloud CDN - AS15169
    "Google": [
        "34.64.0.0/10",
        "35.184.0.0/13",
        "35.192.0.0/14",
        "35.196.0.0/15",
        "35.198.0.0/16",
        "35.199.0.0/16",
        "35.200.0.0/13",
        "35.208.0.0/12",
        "35.224.0.0/12",
        "35.240.0.0/13",
    ],

    # Microsoft Azure CDN - AS8075
    "Microsoft_Azure": [
        "13.64.0.0/11",
        "13.104.0.0/14",
        "20.33.0.0/16",
        "20.34.0.0/15",
        "20.36.0.0/14",
        "20.40.0.0/13",
        "20.48.0.0/12",
        "40.64.0.0/10",
        "52.224.0.0/11",
        "104.40.0.0/13",
        "104.208.0.0/13",
    ],

    # 阿里云 CDN - AS45102 (来源: 阿里云官方文档 + 社区整理)
    # 注意: 阿里云 CDN IP 会动态变化，此列表仅供参考
    "Alibaba_CDN": [
        "47.74.0.0/15",
        "47.88.0.0/14",
        "47.92.0.0/14",
        "47.96.0.0/11",
        "47.244.0.0/16",    # 香港
        "47.52.0.0/16",     # 香港
        "47.246.0.0/16",    # 美国
        "101.132.0.0/14",
        "101.200.0.0/16",
        "106.11.0.0/16",
        "106.15.0.0/16",
        "112.124.0.0/14",
        "114.55.0.0/16",
        "114.215.0.0/16",
        "115.28.0.0/15",
        "116.62.0.0/15",
        "118.31.0.0/16",
        "119.23.0.0/16",
        "120.24.0.0/14",
        "121.40.0.0/13",
        "139.196.0.0/14",
        "140.205.0.0/16",
        "161.117.0.0/16",   # 新加坡
        "182.92.0.0/15",
        "198.11.0.0/16",    # 美国
        "203.107.0.0/17",
    ],

    # 腾讯云 CDN - AS45090 (来源: 腾讯云开发者社区)
    "Tencent_CDN": [
        "58.250.143.0/24",
        "58.251.121.0/24",
        "59.36.120.0/24",
        "61.151.163.0/24",
        "101.227.163.0/24",
        "111.161.109.0/24",
        "116.128.128.0/24",
        "119.28.0.0/15",
        "123.151.76.0/24",
        "125.39.46.0/24",
        "129.204.0.0/14",
        "140.143.0.0/16",
        "140.207.120.0/24",
        "148.70.0.0/16",
        "175.24.0.0/14",
        "175.27.0.0/16",
        "180.163.22.0/24",
        "183.3.254.0/24",
        "211.159.128.0/17",
        "223.166.151.0/24",
    ],

    # 网宿 CDN (ChinaNetCenter) - AS17816 (来源: 社区整理)
    "Wangsu_CDN": [
        "36.27.0.0/16",
        "42.236.0.0/14",
        "58.215.0.0/16",
        "58.250.0.0/15",
        "59.36.0.0/14",
        "61.151.0.0/16",
        "101.71.0.0/16",
        "101.226.0.0/15",
        "103.25.156.0/22",
        "112.65.0.0/16",
        "113.105.0.0/16",
        "113.207.0.0/16",
        "116.140.0.0/14",
        "116.211.0.0/16",
        "118.212.0.0/16",
        "119.84.0.0/14",
        "119.188.0.0/14",
        "120.52.0.0/15",
        "122.226.0.0/15",
        "125.39.0.0/16",
        "183.60.0.0/14",
        "183.232.0.0/14",
        "218.65.0.0/16",
    ],

    # 华为云 CDN - AS136907
    "Huawei_CDN": [
        "110.238.0.0/15",
        "114.116.0.0/14",
        "117.78.0.0/16",
        "119.3.0.0/16",
        "121.36.0.0/14",
        "122.112.0.0/14",
        "139.9.0.0/16",
        "139.159.0.0/16",
    ],
}

# 预编译 IP 网络对象以提高性能
_CDN_NETWORKS: dict[str, list[ipaddress.IPv4Network]] = {}

def _init_networks():
    """初始化 IP 网络对象"""
    global _CDN_NETWORKS
    if not _CDN_NETWORKS:
        for cdn_name, ranges in CDN_RANGES.items():
            _CDN_NETWORKS[cdn_name] = []
            for cidr in ranges:
                try:
                    _CDN_NETWORKS[cdn_name].append(
                        ipaddress.ip_network(cidr, strict=False)
                    )
                except ValueError:
                    pass

def detect_cdn(ip: str) -> tuple[bool, str]:
    """
    检测 IP 是否属于已知 CDN

    Args:
        ip: IP 地址字符串

    Returns:
        tuple: (是否CDN, CDN提供商名称)
    """
    _init_networks()

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False, ""

    for cdn_name, networks in _CDN_NETWORKS.items():
        for network in networks:
            if ip_obj in network:
                return True, cdn_name

    return False, ""


def analyze_dns_history(records: list[dict]) -> dict:
    """
    分析 DNS 历史记录，区分 CDN 和非 CDN 场景

    Args:
        records: DNS 历史记录列表，每条记录包含 'value' (IP) 和 'date'

    Returns:
        dict: 分析结果
    """
    cdn_ips = []
    non_cdn_ips = []
    cdn_providers: set[str] = set()

    for record in records:
        ip = record.get("value", "")
        if not ip:
            continue

        is_cdn, cdn_name = detect_cdn(ip)
        if is_cdn:
            cdn_ips.append(ip)
            cdn_providers.add(cdn_name)
        else:
            non_cdn_ips.append(ip)

    total_ips = len(cdn_ips) + len(non_cdn_ips)
    if total_ips == 0:
        return {
            "is_cdn": False,
            "cdn_providers": [],
            "cdn_ratio": 0,
            "cdn_ip_count": 0,
            "non_cdn_ip_count": 0,
            "risk_adjustment": 0,
            "analysis_note": "无有效 IP 记录"
        }

    cdn_ratio = len(cdn_ips) / total_ips
    is_cdn_domain = cdn_ratio >= 0.6  # CDN IP 占比 >= 60% 则认为是 CDN 域名

    # 风险调整：CDN 域名降低 IP 变化相关的风险分数
    risk_adjustment = 0
    if is_cdn_domain:
        risk_adjustment = -15  # 降低 15 分

    return {
        "is_cdn": is_cdn_domain,
        "cdn_providers": sorted(cdn_providers),
        "cdn_ratio": round(cdn_ratio * 100, 1),
        "cdn_ip_count": len(cdn_ips),
        "non_cdn_ip_count": len(non_cdn_ips),
        "risk_adjustment": risk_adjustment,
        "analysis_note": (
            f"CDN 域名 ({', '.join(cdn_providers)})，IP 变化为正常行为"
            if is_cdn_domain
            else "非 CDN 域名，IP 频繁变化需关注"
        )
    }


def main():
    parser = argparse.ArgumentParser(
        description="CDN 检测器 - 识别 IP 是否属于已知 CDN",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s 23.64.114.42           # 单个 IP 检测
  %(prog)s 23.64.114.42 104.16.1.1  # 多个 IP 检测
  %(prog)s -f ips.txt             # 从文件批量检测
  %(prog)s --list-cdns            # 列出支持的 CDN
"""
    )

    parser.add_argument(
        "ips",
        nargs="*",
        help="要检测的 IP 地址"
    )
    parser.add_argument(
        "-f", "--file",
        help="从文件读取 IP 列表（每行一个）"
    )
    parser.add_argument(
        "-o", "--output",
        choices=["text", "json"],
        default="text",
        help="输出格式 (默认: text)"
    )
    parser.add_argument(
        "--list-cdns",
        action="store_true",
        help="列出支持的 CDN 提供商"
    )
    parser.add_argument(
        "--dns-history",
        help="分析 DNS 历史 JSON 文件"
    )

    args = parser.parse_args()

    # 列出支持的 CDN
    if args.list_cdns:
        print("支持的 CDN 提供商：")
        for cdn_name, ranges in sorted(CDN_RANGES.items()):
            print(f"  {cdn_name}: {len(ranges)} 个 IP 段")
        return

    # 分析 DNS 历史
    if args.dns_history:
        try:
            with open(args.dns_history, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
                # 支持两种格式：{"records": [...]} 或直接 [...]
                if isinstance(data, list):
                    records = data
                else:
                    records = data.get("records", [])
                result = analyze_dns_history(records)
                if args.output == "json":
                    print(json.dumps(result, ensure_ascii=False, indent=2))
                else:
                    print(f"CDN 域名: {'是' if result['is_cdn'] else '否'}")
                    if result['cdn_providers']:
                        print(f"CDN 提供商: {', '.join(result['cdn_providers'])}")
                    print(f"CDN IP 比例: {result['cdn_ratio']}%")
                    print(f"CDN IP 数量: {result['cdn_ip_count']}")
                    print(f"非 CDN IP 数量: {result['non_cdn_ip_count']}")
                    print(f"风险调整: {result['risk_adjustment']}")
                    print(f"分析备注: {result['analysis_note']}")
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # 收集要检测的 IP
    ips = list(args.ips)
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                ips.extend(line.strip() for line in f if line.strip())
        except Exception as e:
            print(f"读取文件错误: {e}", file=sys.stderr)
            sys.exit(1)

    if not ips:
        parser.print_help()
        sys.exit(1)

    # 检测 IP
    results = []
    for ip in ips:
        is_cdn, cdn_name = detect_cdn(ip)
        results.append({
            "ip": ip,
            "is_cdn": is_cdn,
            "cdn_provider": cdn_name
        })

    # 输出结果
    if args.output == "json":
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for r in results:
            if r["is_cdn"]:
                print(f"[+] {r['ip']}: {r['cdn_provider']}")
            else:
                print(f"[-] {r['ip']}: 非 CDN")


if __name__ == "__main__":
    main()
