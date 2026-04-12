#!/usr/bin/env python3
"""
ZoomEye 查询语句构建器

用法:
    python query_builder.py --app nginx --country CN --port 80
    python query_builder.py --site example.com
    python query_builder.py --cidr 192.168.1.0/24 --service ssh
    python query_builder.py --interactive
"""

import argparse
import sys
from typing import List, Optional


class QueryBuilder:
    """ZoomEye 查询语句构建器"""

    def __init__(self):
        self.conditions: List[str] = []
        self.excludes: List[str] = []

    def add_condition(self, key: str, value: str) -> "QueryBuilder":
        """添加搜索条件"""
        if value:
            self.conditions.append(f"{key}:{value}")
        return self

    def add_exclude(self, key: str, value: str) -> "QueryBuilder":
        """添加排除条件"""
        if value:
            self.excludes.append(f"-{key}:{value}")
        return self

    def app(self, name: str, version: Optional[str] = None) -> "QueryBuilder":
        """添加组件条件"""
        self.add_condition("app", name)
        if version:
            self.add_condition("ver", version)
        return self

    def port(self, port: str) -> "QueryBuilder":
        """添加端口条件"""
        return self.add_condition("port", port)

    def service(self, service: str) -> "QueryBuilder":
        """添加服务条件"""
        return self.add_condition("service", service)

    def country(self, code: str) -> "QueryBuilder":
        """添加国家条件"""
        return self.add_condition("country", code.upper())

    def city(self, name: str) -> "QueryBuilder":
        """添加城市条件"""
        return self.add_condition("city", name)

    def site(self, domain: str) -> "QueryBuilder":
        """添加域名条件"""
        return self.add_condition("site", domain)

    def ip(self, ip_addr: str) -> "QueryBuilder":
        """添加 IP 条件"""
        return self.add_condition("ip", ip_addr)

    def cidr(self, network: str) -> "QueryBuilder":
        """添加 CIDR 条件"""
        return self.add_condition("cidr", network)

    def os(self, os_name: str) -> "QueryBuilder":
        """添加操作系统条件"""
        return self.add_condition("os", os_name)

    def title(self, text: str) -> "QueryBuilder":
        """添加网页标题条件"""
        if " " in text:
            text = f'"{text}"'
        return self.add_condition("title", text)

    def hostname(self, name: str) -> "QueryBuilder":
        """添加主机名条件"""
        return self.add_condition("hostname", name)

    def asn(self, asn_number: str) -> "QueryBuilder":
        """添加 ASN 条件"""
        return self.add_condition("asn", asn_number)

    def org(self, org_name: str) -> "QueryBuilder":
        """添加组织条件"""
        return self.add_condition("org", org_name)

    def build(self) -> str:
        """构建最终查询语句"""
        all_conditions = self.conditions + self.excludes
        return " ".join(all_conditions)


def interactive_mode():
    """交互式查询构建"""
    builder = QueryBuilder()
    print("=== ZoomEye 查询构建器 (交互模式) ===")
    print("输入条件值，留空跳过。输入 'done' 完成。\n")

    prompts = [
        ("app", "组件名称 (如 nginx, apache)"),
        ("ver", "组件版本 (如 2.4)"),
        ("port", "端口号 (如 80,443 或 8000-9000)"),
        ("service", "服务类型 (如 http, ssh)"),
        ("country", "国家代码 (如 CN, US)"),
        ("city", "城市名称 (如 Beijing)"),
        ("site", "域名 (如 example.com)"),
        ("ip", "IP 地址或范围"),
        ("cidr", "CIDR 网段 (如 192.168.0.0/24)"),
        ("os", "操作系统 (如 Linux, Windows)"),
        ("title", "网页标题关键词"),
        ("hostname", "主机名"),
        ("org", "组织名称"),
    ]

    for key, desc in prompts:
        value = input(f"{desc}: ").strip()
        if value.lower() == "done":
            break
        if value:
            builder.add_condition(key, value)

    query = builder.build()
    if query:
        print(f"\n生成的查询语句:\n{query}")
    else:
        print("\n未添加任何条件")

    return query


def main():
    parser = argparse.ArgumentParser(
        description="ZoomEye 查询语句构建器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --app nginx --country CN
  %(prog)s --site example.com --port 80,443
  %(prog)s --cidr 192.168.1.0/24 --service ssh
  %(prog)s --interactive
        """,
    )

    parser.add_argument("--app", help="组件名称")
    parser.add_argument("--ver", help="组件版本")
    parser.add_argument("--port", help="端口号")
    parser.add_argument("--service", help="服务类型")
    parser.add_argument("--country", help="国家代码")
    parser.add_argument("--city", help="城市名称")
    parser.add_argument("--site", help="域名")
    parser.add_argument("--ip", help="IP 地址")
    parser.add_argument("--cidr", help="CIDR 网段")
    parser.add_argument("--os", help="操作系统")
    parser.add_argument("--title", help="网页标题")
    parser.add_argument("--hostname", help="主机名")
    parser.add_argument("--org", help="组织名称")
    parser.add_argument("--asn", help="AS 号码")
    parser.add_argument(
        "--exclude-country", help="排除的国家代码", dest="exclude_country"
    )
    parser.add_argument("--interactive", "-i", action="store_true", help="交互模式")

    args = parser.parse_args()

    if args.interactive:
        interactive_mode()
        return

    builder = QueryBuilder()

    if args.app:
        builder.app(args.app, args.ver)
    if args.port:
        builder.port(args.port)
    if args.service:
        builder.service(args.service)
    if args.country:
        builder.country(args.country)
    if args.city:
        builder.city(args.city)
    if args.site:
        builder.site(args.site)
    if args.ip:
        builder.ip(args.ip)
    if args.cidr:
        builder.cidr(args.cidr)
    if args.os:
        builder.os(args.os)
    if args.title:
        builder.title(args.title)
    if args.hostname:
        builder.hostname(args.hostname)
    if args.org:
        builder.org(args.org)
    if args.asn:
        builder.asn(args.asn)
    if args.exclude_country:
        builder.add_exclude("country", args.exclude_country)

    query = builder.build()

    if query:
        print(query)
    else:
        print("未指定任何搜索条件。使用 --help 查看帮助。", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
