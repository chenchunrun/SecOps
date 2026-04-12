#!/usr/bin/env python3
"""
资产导出工具

用法:
    python asset_export.py results.json -o assets.csv
    python asset_export.py results.json -o assets.json --format json
    python asset_export.py results.json -o ips.txt --ips-only
"""

import argparse
import csv
import json
import sys
from typing import Any, Dict, List


def parse_assets(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """解析资产数据"""
    results = data.get("matches", data.get("results", data.get("data", [])))
    assets = []

    for item in results:
        asset = {
            "ip": item.get("ip", ""),
            "port": item.get("port", 0),
            "protocol": item.get("protocol", "tcp"),
            "app": item.get("app", item.get("product", "")),
            "version": item.get("version", item.get("ver", "")),
            "os": item.get("os", item.get("operating_system", "")),
            "hostname": item.get("hostname", item.get("host", "")),
            "country": item.get("country", item.get("geoinfo", {}).get("country", "")),
            "city": item.get("city", item.get("geoinfo", {}).get("city", "")),
            "asn": item.get("asn", ""),
            "org": item.get("org", item.get("organization", "")),
            "banner": item.get("banner", item.get("raw_data", ""))[:500],
            "update_time": item.get("timestamp", item.get("update_time", "")),
        }
        assets.append(asset)

    return assets


def export_csv(assets: List[Dict[str, Any]], output_file: str):
    """导出为 CSV"""
    if not assets:
        print("无资产数据", file=sys.stderr)
        return

    fieldnames = list(assets[0].keys())

    with open(output_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(assets)

    print(f"已导出 {len(assets)} 条记录到 {output_file}")


def export_json(assets: List[Dict[str, Any]], output_file: str):
    """导出为 JSON"""
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(assets, f, ensure_ascii=False, indent=2)

    print(f"已导出 {len(assets)} 条记录到 {output_file}")


def export_ips(assets: List[Dict[str, Any]], output_file: str, with_port: bool = False):
    """导出 IP 列表"""
    with open(output_file, "w", encoding="utf-8") as f:
        for asset in assets:
            if with_port:
                f.write(f"{asset['ip']}:{asset['port']}\n")
            else:
                f.write(f"{asset['ip']}\n")

    print(f"已导出 {len(assets)} 个 IP 到 {output_file}")


def export_nmap_targets(assets: List[Dict[str, Any]], output_file: str):
    """导出为 Nmap 目标格式"""
    # 按 IP 分组端口
    ip_ports: Dict[str, List[int]] = {}
    for asset in assets:
        ip = asset["ip"]
        port = asset["port"]
        if ip not in ip_ports:
            ip_ports[ip] = []
        if port not in ip_ports[ip]:
            ip_ports[ip].append(port)

    with open(output_file, "w", encoding="utf-8") as f:
        for ip, ports in ip_ports.items():
            ports_str = ",".join(str(p) for p in sorted(ports))
            f.write(f"{ip} -p {ports_str}\n")

    print(f"已导出 {len(ip_ports)} 个目标到 {output_file}")


def export_markdown_table(assets: List[Dict[str, Any]], output_file: str):
    """导出为 Markdown 表格"""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("| IP | 端口 | 组件 | 版本 | 国家/城市 |\n")
        f.write("|---|---|---|---|---|\n")
        for asset in assets:
            location = f"{asset['country']}/{asset['city']}"
            f.write(
                f"| {asset['ip']} | {asset['port']} | {asset['app']} | {asset['version']} | {location} |\n"
            )

    print(f"已导出 {len(assets)} 条记录到 {output_file}")


def main():
    parser = argparse.ArgumentParser(description="资产导出工具")
    parser.add_argument("input", help="输入 JSON 文件")
    parser.add_argument("-o", "--output", required=True, help="输出文件路径")
    parser.add_argument(
        "--format",
        "-f",
        choices=["csv", "json", "ips", "nmap", "markdown"],
        default="csv",
        help="输出格式 (默认: csv)",
    )
    parser.add_argument(
        "--ips-only", action="store_true", help="仅导出 IP 列表"
    )
    parser.add_argument(
        "--with-port", action="store_true", help="IP 列表包含端口 (ip:port 格式)"
    )
    parser.add_argument(
        "--unique-ips", action="store_true", help="去重 IP"
    )

    args = parser.parse_args()

    # 读取输入
    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 解析资产
    assets = parse_assets(data)

    if not assets:
        print("无资产数据", file=sys.stderr)
        sys.exit(1)

    # 去重
    if args.unique_ips:
        seen_ips = set()
        unique_assets = []
        for asset in assets:
            if asset["ip"] not in seen_ips:
                seen_ips.add(asset["ip"])
                unique_assets.append(asset)
        assets = unique_assets

    # 导出
    if args.ips_only or args.format == "ips":
        export_ips(assets, args.output, args.with_port)
    elif args.format == "csv":
        export_csv(assets, args.output)
    elif args.format == "json":
        export_json(assets, args.output)
    elif args.format == "nmap":
        export_nmap_targets(assets, args.output)
    elif args.format == "markdown":
        export_markdown_table(assets, args.output)


if __name__ == "__main__":
    main()
