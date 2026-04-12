#!/usr/bin/env python3
"""
威胁狩猎查询生成器

用法:
    python threat_hunt.py --ddns duckdns.org
    python threat_hunt.py --malware asyncrat
    python threat_hunt.py --ioc-expand 1.2.3.4
    python threat_hunt.py --c2 cobalt-strike
"""

import argparse
import json
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class MalwareFamily:
    """恶意软件家族配置"""
    name: str
    ports: List[int]
    ddns_services: List[str]
    banner_keywords: List[str]
    ssl_signatures: List[str]
    description: str


# 恶意软件家族数据库
MALWARE_FAMILIES: Dict[str, MalwareFamily] = {
    "asyncrat": MalwareFamily(
        name="AsyncRAT",
        ports=[6606, 7707, 8808],
        ddns_services=["duckdns.org"],
        banner_keywords=["asyncrat"],
        ssl_signatures=[],
        description=".NET RAT, 键盘记录/屏幕捕获/远程控制"
    ),
    "xworm": MalwareFamily(
        name="Xworm",
        ports=[7000, 7777, 8888],
        ddns_services=["ydns.eu"],
        banner_keywords=["xworm"],
        ssl_signatures=[],
        description=".NET后门, 键盘记录/勒索/DDoS"
    ),
    "njrat": MalwareFamily(
        name="NjRAT",
        ports=[5552, 1177, 5555],
        ddns_services=["linkpc.net"],
        banner_keywords=["njrat", "bladabindi"],
        ssl_signatures=[],
        description="C#远程访问木马, 文件管理/远程Shell"
    ),
    "remcos": MalwareFamily(
        name="RemCos",
        ports=[2404, 2405, 4782],
        ddns_services=["didns.ru"],
        banner_keywords=["remcos"],
        ssl_signatures=[],
        description="商业RAT, 键盘记录/截图/凭据窃取"
    ),
    "cobalt-strike": MalwareFamily(
        name="Cobalt Strike",
        ports=[50050, 443, 8443],
        ddns_services=[],
        banner_keywords=[],
        ssl_signatures=["6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C"],
        description="红队工具/APT常用"
    ),
    "metasploit": MalwareFamily(
        name="Metasploit",
        ports=[4444, 4445, 5555],
        ddns_services=[],
        banner_keywords=["meterpreter"],
        ssl_signatures=[],
        description="渗透测试框架/Meterpreter"
    ),
    "mirai": MalwareFamily(
        name="Mirai",
        ports=[23, 2323, 6667],
        ddns_services=["cantdown.space"],
        banner_keywords=["mirai"],
        ssl_signatures=[],
        description="IoT僵尸网络, Telnet暴力破解"
    ),
    "gafgyt": MalwareFamily(
        name="Gafgyt/BASHLITE",
        ports=[23, 6667, 6668],
        ddns_services=[],
        banner_keywords=["gafgyt", "bashlite"],
        ssl_signatures=[],
        description="IRC僵尸网络"
    ),
    "moobot": MalwareFamily(
        name="MooBot",
        ports=[23, 37215, 52869],
        ddns_services=["xxbot.co"],
        banner_keywords=["moobot"],
        ssl_signatures=[],
        description="Mirai变种僵尸网络"
    ),
    "xorddos": MalwareFamily(
        name="XorDDoS",
        ports=[22],
        ddns_services=[],
        banner_keywords=["xor"],
        ssl_signatures=[],
        description="Linux僵尸网络, SSH暴力破解"
    ),
}

# 动态DNS服务数据库
DDNS_SERVICES = {
    "duckdns.org": {"risk": "high", "common_malware": ["AsyncRAT", "RemCos", "NjRAT"]},
    "ydns.eu": {"risk": "high", "common_malware": ["Xworm", "AgentTesla"]},
    "linkpc.net": {"risk": "high", "common_malware": ["NjRAT", "RemCos"]},
    "ddns.net": {"risk": "high", "common_malware": ["多种RAT"]},
    "no-ip.org": {"risk": "high", "common_malware": ["僵尸网络"]},
    "hopto.org": {"risk": "medium", "common_malware": ["RAT"]},
    "zapto.org": {"risk": "medium", "common_malware": ["RAT"]},
    "didns.ru": {"risk": "high", "common_malware": ["RemCos"]},
    "xxbot.co": {"risk": "high", "common_malware": ["MooBot"]},
    "cantdown.space": {"risk": "high", "common_malware": ["Mirai"]},
}


def generate_ddns_query(service: str) -> Dict:
    """生成动态DNS服务搜索查询"""
    queries = []

    if service == "all":
        for svc in DDNS_SERVICES:
            queries.append({
                "service": svc,
                "query": f'domain="{svc}"',
                "risk": DDNS_SERVICES[svc]["risk"],
                "common_malware": DDNS_SERVICES[svc]["common_malware"]
            })
    else:
        if service in DDNS_SERVICES:
            info = DDNS_SERVICES[service]
            queries.append({
                "service": service,
                "query": f'domain="{service}"',
                "risk": info["risk"],
                "common_malware": info["common_malware"]
            })
        else:
            queries.append({
                "service": service,
                "query": f'domain="{service}"',
                "risk": "unknown",
                "common_malware": []
            })

    return {"type": "ddns_scan", "queries": queries}


def generate_malware_query(family: str) -> Dict:
    """生成恶意软件家族C2搜索查询"""
    if family not in MALWARE_FAMILIES:
        return {"error": f"未知的恶意软件家族: {family}", "available": list(MALWARE_FAMILIES.keys())}

    mf = MALWARE_FAMILIES[family]
    queries = []

    # 端口搜索
    if mf.ports:
        port_query = " || ".join([f'port="{p}"' for p in mf.ports])
        queries.append({
            "type": "port",
            "query": port_query,
            "description": f"{mf.name} 常见端口"
        })

    # 端口+DDNS组合
    for ddns in mf.ddns_services:
        for port in mf.ports[:2]:  # 取前两个常见端口
            queries.append({
                "type": "ddns_port",
                "query": f'domain="{ddns}" && port="{port}"',
                "description": f"{mf.name} on {ddns}"
            })

    # SSL证书
    for sig in mf.ssl_signatures:
        queries.append({
            "type": "ssl",
            "query": f'ssl="{sig}"',
            "description": f"{mf.name} 默认证书"
        })

    # Banner关键词
    for kw in mf.banner_keywords:
        queries.append({
            "type": "banner",
            "query": f'body="{kw}"',
            "description": f"{mf.name} Banner特征"
        })

    return {
        "type": "malware_hunt",
        "family": mf.name,
        "description": mf.description,
        "queries": queries
    }


def generate_ioc_expand_plan(ioc: str) -> Dict:
    """生成IOC关联分析计划"""
    steps = []

    # 判断IOC类型
    if ioc.replace(".", "").isdigit():  # 简单IP判断
        ioc_type = "ip"
        steps = [
            {"step": 1, "action": "查询IP信息", "query": f'ip="{ioc}"', "output": "绑定域名、端口、证书"},
            {"step": 2, "action": "威胁情报", "tool": "risk_insight", "input": ioc, "output": "家族标签、恶意评分"},
            {"step": 3, "action": "证书关联", "query": 'ssl="从步骤1提取的证书CN"', "output": "关联IP"},
            {"step": 4, "action": "域名追踪", "query": 'domain="从步骤1提取的域名"', "output": "历史IP"},
            {"step": 5, "action": "防弹托管判断", "criteria": "域名数>100为可疑", "output": "托管类型"},
        ]
    else:  # 域名
        ioc_type = "domain"
        steps = [
            {"step": 1, "action": "查询域名", "query": f'domain="{ioc}"', "output": "解析IP、端口"},
            {"step": 2, "action": "威胁情报", "tool": "risk_insight", "input": ioc, "output": "恶意评分"},
            {"step": 3, "action": "同IP域名", "query": 'ip="从步骤1获取的IP"', "output": "同IP所有域名"},
            {"step": 4, "action": "动态DNS扩展", "query": 'domain="提取根域名"', "output": "同服务其他域名"},
            {"step": 5, "action": "基础设施规模", "criteria": "统计同IP域名数量", "output": "是否防弹托管"},
        ]

    return {
        "type": "ioc_expansion",
        "ioc": ioc,
        "ioc_type": ioc_type,
        "steps": steps
    }


def generate_c2_hunt_query(c2_type: str) -> Dict:
    """生成C2基础设施狩猎查询"""
    c2_templates = {
        "cobalt-strike": {
            "name": "Cobalt Strike",
            "queries": [
                {"query": 'ssl="6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C"', "desc": "默认证书"},
                {"query": 'port="50050"', "desc": "默认端口"},
                {"query": 'body="HTTP/1.1 404 Not Found" && header="Content-Length: 0"', "desc": "Team Server特征"},
            ]
        },
        "sliver": {
            "name": "Sliver C2",
            "queries": [
                {"query": 'port="8888" && ssl="Sliver"', "desc": "默认配置"},
            ]
        },
        "metasploit": {
            "name": "Metasploit",
            "queries": [
                {"query": 'port="4444"', "desc": "Meterpreter默认端口"},
                {"query": 'port="4445"', "desc": "备用端口"},
            ]
        },
        "bruteratel": {
            "name": "Brute Ratel C4",
            "queries": [
                {"query": 'ssl="Brute Ratel"', "desc": "证书特征"},
            ]
        }
    }

    if c2_type not in c2_templates:
        return {"error": f"未知C2类型: {c2_type}", "available": list(c2_templates.keys())}

    return {
        "type": "c2_hunt",
        "c2_type": c2_templates[c2_type]["name"],
        "queries": c2_templates[c2_type]["queries"]
    }


def list_all():
    """列出所有可用模板"""
    print("=== 恶意软件家族 ===")
    for name, mf in MALWARE_FAMILIES.items():
        print(f"  {name}: {mf.description}")

    print("\n=== 动态DNS服务 ===")
    for name, info in DDNS_SERVICES.items():
        print(f"  {name}: 风险={info['risk']}, 常见恶意软件={info['common_malware']}")

    print("\n=== C2框架 ===")
    c2_list = ["cobalt-strike", "sliver", "metasploit", "bruteratel"]
    for c2 in c2_list:
        print(f"  {c2}")


def main():
    parser = argparse.ArgumentParser(
        description="威胁狩猎查询生成器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --ddns duckdns.org      # 扫描DuckDNS域名
  %(prog)s --ddns all               # 扫描所有高风险动态DNS
  %(prog)s --malware asyncrat       # 搜索AsyncRAT C2
  %(prog)s --malware cobalt-strike  # 搜索Cobalt Strike
  %(prog)s --ioc-expand 1.2.3.4     # IOC关联分析计划
  %(prog)s --c2 cobalt-strike       # C2基础设施狩猎
  %(prog)s --list                   # 列出所有可用模板
        """
    )

    parser.add_argument("--ddns", help="动态DNS服务名称或'all'")
    parser.add_argument("--malware", help="恶意软件家族名称")
    parser.add_argument("--ioc-expand", dest="ioc", help="IOC关联分析")
    parser.add_argument("--c2", help="C2框架狩猎")
    parser.add_argument("--list", action="store_true", help="列出所有可用模板")
    parser.add_argument("--json", action="store_true", help="JSON格式输出")

    args = parser.parse_args()

    if args.list:
        list_all()
        return

    result = None

    if args.ddns:
        result = generate_ddns_query(args.ddns)
    elif args.malware:
        result = generate_malware_query(args.malware)
    elif args.ioc:
        result = generate_ioc_expand_plan(args.ioc)
    elif args.c2:
        result = generate_c2_hunt_query(args.c2)
    else:
        parser.print_help()
        return

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        # 友好格式输出
        if "error" in result:
            print(f"错误: {result['error']}")
            if "available" in result:
                print(f"可用选项: {', '.join(result['available'])}")
        else:
            print(f"类型: {result.get('type', 'unknown')}")
            if "family" in result:
                print(f"家族: {result['family']}")
                print(f"描述: {result['description']}")
            if "queries" in result:
                print("\n生成的查询:")
                for i, q in enumerate(result["queries"], 1):
                    if isinstance(q, dict):
                        desc = q.get("description") or q.get("desc", "")
                        query = q.get("query", "")
                        print(f"  {i}. [{desc}] {query}")
                    else:
                        print(f"  {i}. {q}")
            if "steps" in result:
                print("\n分析步骤:")
                for step in result["steps"]:
                    print(f"  步骤{step['step']}: {step['action']}")
                    if "query" in step:
                        print(f"    查询: {step['query']}")
                    if "tool" in step:
                        print(f"    工具: {step['tool']}")
                    print(f"    输出: {step['output']}")


if __name__ == "__main__":
    main()
