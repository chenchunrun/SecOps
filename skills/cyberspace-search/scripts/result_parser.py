#!/usr/bin/env python3
"""
ZoomEye 搜索结果解析器

用法:
    python result_parser.py results.json
    python result_parser.py results.json --format table
    python result_parser.py results.json --stats
    python result_parser.py results.json --risk-filter high
"""

import argparse
import json
import sys
from collections import Counter
from typing import Any, Dict, List, Optional


# 高风险端口列表
HIGH_RISK_PORTS = {
    23: "Telnet",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    502: "Modbus",
    102: "S7comm",
}

# 中风险端口列表
MEDIUM_RISK_PORTS = {
    22: "SSH",
    3389: "RDP",
    5900: "VNC",
    21: "FTP",
    1433: "MSSQL",
    1521: "Oracle",
    8080: "HTTP-Alt",
}


def calculate_risk_score(asset: Dict[str, Any]) -> int:
    """计算资产风险评分"""
    score = 0

    port = asset.get("port", 0)
    app = asset.get("app", "").lower()
    banner = asset.get("banner", "").lower()

    # 端口风险
    if port in HIGH_RISK_PORTS:
        score += 30
    elif port in MEDIUM_RISK_PORTS:
        score += 15

    # 组件风险
    high_risk_apps = ["redis", "mongodb", "elasticsearch", "memcached"]
    medium_risk_apps = ["mysql", "postgresql", "mssql", "oracle"]

    for app_name in high_risk_apps:
        if app_name in app:
            score += 20
            break
    for app_name in medium_risk_apps:
        if app_name in app:
            score += 10
            break

    # Banner 风险特征
    if "noauth" in banner or "anonymous" in banner:
        score += 25
    if "password" in banner or "unauthorized" in banner:
        score += 15
    if "debug" in banner or "phpinfo" in banner:
        score += 10

    return score


def get_risk_level(score: int) -> str:
    """根据分数返回风险等级"""
    if score >= 60:
        return "[!] 严重"
    elif score >= 40:
        return "[!] 高"
    elif score >= 20:
        return "[*] 中"
    else:
        return "[+] 低"


def parse_results(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """解析搜索结果"""
    assets = []

    # 尝试不同的数据结构
    results = data.get("matches", data.get("results", data.get("data", [])))

    for item in results:
        asset = {
            "ip": item.get("ip", "N/A"),
            "port": item.get("port", 0),
            "app": item.get("app", item.get("product", "N/A")),
            "version": item.get("version", item.get("ver", "N/A")),
            "country": item.get("country", item.get("geoinfo", {}).get("country", "N/A")),
            "city": item.get("city", item.get("geoinfo", {}).get("city", "N/A")),
            "banner": item.get("banner", item.get("raw_data", ""))[:200],
            "hostname": item.get("hostname", item.get("host", "N/A")),
            "os": item.get("os", item.get("operating_system", "N/A")),
        }

        # 计算风险评分
        asset["risk_score"] = calculate_risk_score(asset)
        asset["risk_level"] = get_risk_level(asset["risk_score"])

        assets.append(asset)

    return assets


def print_table(assets: List[Dict[str, Any]]):
    """以表格形式输出"""
    if not assets:
        print("无结果")
        return

    # 表头
    print("=" * 100)
    print(
        f"{'IP':<18} {'端口':<7} {'组件':<15} {'国家/城市':<15} {'风险等级':<10}"
    )
    print("-" * 100)

    for asset in assets:
        location = f"{asset['country']}/{asset['city']}"[:14]
        app = str(asset["app"])[:14]
        print(
            f"{asset['ip']:<18} {asset['port']:<7} {app:<15} {location:<15} {asset['risk_level']:<10}"
        )

    print("=" * 100)


def print_stats(assets: List[Dict[str, Any]]):
    """输出统计信息"""
    if not assets:
        print("无结果")
        return

    print("\n=== 资产统计 ===\n")
    print(f"总数: {len(assets)} 个\n")

    # 国家分布
    countries = Counter(a["country"] for a in assets)
    print("按国家分布:")
    for country, count in countries.most_common(10):
        print(f"  - {country}: {count} 个")

    # 端口分布
    ports = Counter(a["port"] for a in assets)
    print("\n按端口分布:")
    for port, count in ports.most_common(10):
        print(f"  - {port}: {count} 个")

    # 组件分布
    apps = Counter(a["app"] for a in assets if a["app"] != "N/A")
    print("\n按组件分布:")
    for app, count in apps.most_common(10):
        print(f"  - {app}: {count} 个")

    # 风险分布
    risk_counts = Counter(a["risk_level"] for a in assets)
    print("\n风险等级分布:")
    for level in ["[!] 严重", "[!] 高", "[*] 中", "[+] 低"]:
        count = risk_counts.get(level, 0)
        print(f"  - {level}: {count} 个")


def filter_by_risk(assets: List[Dict[str, Any]], level: str) -> List[Dict[str, Any]]:
    """按风险等级过滤"""
    level_map = {
        "critical": "[!] 严重",
        "high": "[!] 高",
        "medium": "[*] 中",
        "low": "[+] 低",
    }

    target_levels = []
    if level == "critical":
        target_levels = ["[!] 严重"]
    elif level == "high":
        target_levels = ["[!] 严重", "[!] 高"]
    elif level == "medium":
        target_levels = ["[!] 严重", "[!] 高", "[*] 中"]
    else:
        return assets

    return [a for a in assets if a["risk_level"] in target_levels]


def main():
    parser = argparse.ArgumentParser(description="ZoomEye 搜索结果解析器")
    parser.add_argument("input", nargs="?", help="输入 JSON 文件 (可选，也可从 stdin 读取)")
    parser.add_argument(
        "--format",
        "-f",
        choices=["table", "json", "csv"],
        default="table",
        help="输出格式",
    )
    parser.add_argument("--stats", "-s", action="store_true", help="显示统计信息")
    parser.add_argument(
        "--risk-filter",
        "-r",
        choices=["critical", "high", "medium"],
        help="按风险等级过滤",
    )

    args = parser.parse_args()

    # 读取输入
    if args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = json.load(sys.stdin)

    # 解析结果
    assets = parse_results(data)

    # 风险过滤
    if args.risk_filter:
        assets = filter_by_risk(assets, args.risk_filter)

    # 输出
    if args.stats:
        print_stats(assets)
    elif args.format == "table":
        print_table(assets)
    elif args.format == "json":
        print(json.dumps(assets, ensure_ascii=False, indent=2))
    elif args.format == "csv":
        print("IP,端口,组件,版本,国家,城市,风险分数,风险等级")
        for a in assets:
            print(
                f"{a['ip']},{a['port']},{a['app']},{a['version']},{a['country']},{a['city']},{a['risk_score']},{a['risk_level']}"
            )


if __name__ == "__main__":
    main()
