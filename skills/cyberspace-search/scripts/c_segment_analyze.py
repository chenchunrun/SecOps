#!/usr/bin/env python3
"""
C段环境分析工具

用法:
    python c_segment_analyze.py 1.2.3.4
    python c_segment_analyze.py 1.2.3.0/24
    python c_segment_analyze.py results.json --from-file
"""

import argparse
import ipaddress
import json
import sys
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional


def ip_to_c_segment(ip: str) -> str:
    """将 IP 转换为 C 段"""
    try:
        addr = ipaddress.ip_address(ip)
        # 取前 24 位
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(network)
    except ValueError:
        return ""


def parse_cidr(cidr: str) -> str:
    """解析 CIDR 格式"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return str(network)
    except ValueError:
        return ""


def analyze_c_segment(assets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """分析 C 段资产"""
    if not assets:
        return {"error": "无资产数据"}

    # 基础统计
    total = len(assets)
    unique_ips = set(a.get("ip", "") for a in assets)

    # 端口分布
    port_counter = Counter(a.get("port", 0) for a in assets)

    # 组件分布
    app_counter = Counter(a.get("app", "unknown") for a in assets if a.get("app"))

    # 操作系统分布
    os_counter = Counter(a.get("os", "unknown") for a in assets if a.get("os"))

    # 域名/主机名收集
    hostnames = set()
    domains = set()
    for a in assets:
        if a.get("hostname"):
            hostnames.add(a["hostname"])
        if a.get("site"):
            domains.add(a["site"])

    # 敏感端口检测
    sensitive_ports = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch",
        445: "SMB",
        21: "FTP",
    }

    exposed_sensitive = []
    for a in assets:
        port = a.get("port", 0)
        if port in sensitive_ports:
            exposed_sensitive.append(
                {"ip": a.get("ip"), "port": port, "service": sensitive_ports[port]}
            )

    # 按 IP 聚合服务
    ip_services = defaultdict(list)
    for a in assets:
        ip = a.get("ip", "")
        port = a.get("port", 0)
        app = a.get("app", "")
        if ip:
            ip_services[ip].append({"port": port, "app": app})

    # 多服务主机（可能是重点目标）
    multi_service_hosts = {
        ip: services for ip, services in ip_services.items() if len(services) >= 3
    }

    return {
        "summary": {
            "total_records": total,
            "unique_ips": len(unique_ips),
            "ip_density": f"{len(unique_ips)}/256 ({len(unique_ips) * 100 / 256:.1f}%)",
        },
        "port_distribution": dict(port_counter.most_common(15)),
        "app_distribution": dict(app_counter.most_common(10)),
        "os_distribution": dict(os_counter.most_common(5)),
        "domains_found": list(domains)[:20],
        "hostnames_found": list(hostnames)[:20],
        "sensitive_services": exposed_sensitive[:20],
        "multi_service_hosts": {
            ip: services for ip, services in list(multi_service_hosts.items())[:10]
        },
    }


def print_analysis(analysis: Dict[str, Any], c_segment: str):
    """打印分析结果"""
    print("=" * 60)
    print(f"C 段环境分析报告: {c_segment}")
    print("=" * 60)

    # 摘要
    summary = analysis.get("summary", {})
    print("\n【基础统计】")
    print(f"  记录总数: {summary.get('total_records', 0)}")
    print(f"  唯一 IP:  {summary.get('unique_ips', 0)}")
    print(f"  IP 密度:  {summary.get('ip_density', 'N/A')}")

    # 端口分布
    ports = analysis.get("port_distribution", {})
    if ports:
        print("\n【端口分布 Top 15】")
        for port, count in list(ports.items())[:15]:
            bar = "█" * min(count, 20)
            print(f"  {port:>6}: {count:>4} {bar}")

    # 组件分布
    apps = analysis.get("app_distribution", {})
    if apps:
        print("\n【组件分布 Top 10】")
        for app, count in list(apps.items())[:10]:
            print(f"  {app:<20}: {count}")

    # 操作系统
    os_dist = analysis.get("os_distribution", {})
    if os_dist:
        print("\n【操作系统分布】")
        for os_name, count in os_dist.items():
            print(f"  {os_name:<15}: {count}")

    # 敏感服务
    sensitive = analysis.get("sensitive_services", [])
    if sensitive:
        print("\n【敏感服务暴露】[!]")
        for s in sensitive[:10]:
            print(f"  {s['ip']}:{s['port']} ({s['service']})")
        if len(sensitive) > 10:
            print(f"  ... 共 {len(sensitive)} 个敏感服务")

    # 多服务主机
    multi = analysis.get("multi_service_hosts", {})
    if multi:
        print("\n【多服务主机（重点目标）】")
        for ip, services in list(multi.items())[:5]:
            ports_str = ", ".join(str(s["port"]) for s in services)
            print(f"  {ip}: [{ports_str}]")

    # 域名
    domains = analysis.get("domains_found", [])
    if domains:
        print("\n【发现的域名】")
        for d in domains[:10]:
            print(f"  - {d}")

    print("\n" + "=" * 60)


def generate_follow_up_queries(analysis: Dict[str, Any], c_segment: str) -> List[str]:
    """生成后续查询建议"""
    queries = []

    # 敏感服务深入查询
    sensitive = analysis.get("sensitive_services", [])
    if sensitive:
        ports = set(s["port"] for s in sensitive)
        ports_str = ",".join(str(p) for p in sorted(ports))
        queries.append(f"# 敏感服务详查\ncidr:{c_segment} port:{ports_str}")

    # 域名关联
    domains = analysis.get("domains_found", [])
    if domains:
        for d in domains[:3]:
            queries.append(f"# 域名资产扩展\nsite:{d}")

    # 主要组件漏洞检测
    apps = analysis.get("app_distribution", {})
    vuln_apps = ["apache", "nginx", "tomcat", "thinkphp", "struts2", "weblogic"]
    for app in vuln_apps:
        if app in str(apps).lower():
            queries.append(f"# {app} 漏洞资产\ncidr:{c_segment} app:{app}")
            break

    return queries


def main():
    parser = argparse.ArgumentParser(description="C段环境分析工具")
    parser.add_argument("target", help="目标 IP 或 CIDR，或 JSON 文件路径")
    parser.add_argument(
        "--from-file", "-f", action="store_true", help="从 JSON 文件读取搜索结果"
    )
    parser.add_argument(
        "--output", "-o", choices=["text", "json"], default="text", help="输出格式"
    )
    parser.add_argument(
        "--suggest", "-s", action="store_true", help="生成后续查询建议"
    )

    args = parser.parse_args()

    if args.from_file:
        # 从文件读取
        with open(args.target, "r", encoding="utf-8") as f:
            data = json.load(f)
        assets = data.get("matches", data.get("results", data.get("data", [])))

        # 尝试确定 C 段
        if assets:
            first_ip = assets[0].get("ip", "")
            c_segment = ip_to_c_segment(first_ip)
        else:
            c_segment = "unknown"
    else:
        # 从命令行参数
        if "/" in args.target:
            c_segment = parse_cidr(args.target)
        else:
            c_segment = ip_to_c_segment(args.target)

        if not c_segment:
            print(f"无效的 IP 或 CIDR: {args.target}", file=sys.stderr)
            sys.exit(1)

        # 输出查询语句
        print(f"请使用以下查询获取 C 段数据:\n")
        print(f"  cidr:{c_segment}")
        print(f"\n然后使用 --from-file 分析结果")
        sys.exit(0)

    # 分析
    analysis = analyze_c_segment(assets)

    if args.output == "json":
        print(json.dumps(analysis, ensure_ascii=False, indent=2))
    else:
        print_analysis(analysis, c_segment)

        if args.suggest:
            queries = generate_follow_up_queries(analysis, c_segment)
            if queries:
                print("\n【后续查询建议】")
                for q in queries:
                    print(q)
                    print()


if __name__ == "__main__":
    main()
