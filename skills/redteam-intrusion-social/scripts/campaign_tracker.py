#!/usr/bin/env python3
"""
红队社工钓鱼活动跟踪器
记录和统计钓鱼演练活动的各项指标
"""

import json
import argparse
import os
from datetime import datetime, timedelta
from pathlib import Path

DEFAULT_DB = Path(__file__).parent / "campaign_data.json"

def init_db(db_path):
    """初始化活动数据库"""
    if not db_path.exists():
        db_path.write_text(json.dumps({"campaigns": []}, indent=2))

def load_db(db_path):
    """加载数据库"""
    init_db(db_path)
    return json.loads(db_path.read_text())

def save_db(db_path, data):
    """保存数据库"""
    db_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))

def create_campaign(args):
    """创建新活动"""
    db_path = Path(args.db) if args.db else DEFAULT_DB
    data = load_db(db_path)
    
    campaign = {
        "id": f"CAMP-{len(data['campaigns']) + 1:04d}",
        "name": args.name,
        "target_org": args.target,
        "scenario": args.scenario,
        "attack_type": args.type,
        "techniques": args.techniques or [],
        "start_date": args.start or datetime.now().strftime("%Y-%m-%d"),
        "end_date": args.end,
        "status": "planning",
        "metrics": {
            "sent": 0,
            "delivered": 0,
            "opened": 0,
            "clicked": 0,
            "submitted": 0,
            "reported": 0
        },
        "targets_count": args.count or 0,
        "iocs": [],
        "notes": []
    }
    
    data["campaigns"].append(campaign)
    save_db(db_path, data)
    
    print(f"✅ 活动已创建: {campaign['id']} - {campaign['name']}")
    print(f"   目标: {campaign['target_org']}")
    print(f"   类型: {campaign['attack_type']}")
    print(f"   场景: {campaign['scenario']}")

def update_metrics(args):
    """更新活动指标"""
    db_path = Path(args.db) if args.db else DEFAULT_DB
    data = load_db(db_path)
    
    for camp in data["campaigns"]:
        if camp["id"] == args.campaign_id:
            if args.sent is not None:
                camp["metrics"]["sent"] = args.sent
            if args.delivered is not None:
                camp["metrics"]["delivered"] = args.delivered
            if args.opened is not None:
                camp["metrics"]["opened"] = args.opened
            if args.clicked is not None:
                camp["metrics"]["clicked"] = args.clicked
            if args.submitted is not None:
                camp["metrics"]["submitted"] = args.submitted
            if args.reported is not None:
                camp["metrics"]["reported"] = args.reported
            camp["status"] = args.status or camp["status"]
            
            save_db(db_path, data)
            print(f"✅ 活动已更新: {camp['id']}")
            print_stats(camp)
            return
    
    print(f"❌ 未找到活动: {args.campaign_id}")

def print_stats(camp):
    """打印活动统计"""
    m = camp["metrics"]
    print(f"\n📊 {camp['id']} - {camp['name']}")
    print(f"   状态: {camp['status']}")
    print(f"   发送: {m['sent']} | 送达: {m['delivered']} | 打开: {m['opened']}")
    print(f"   点击: {m['clicked']} | 提交: {m['submitted']} | 报告: {m['reported']}")
    
    if m["sent"] > 0:
        open_rate = m["opened"] / m["sent"] * 100
        click_rate = m["clicked"] / m["sent"] * 100
        submit_rate = m["submitted"] / m["sent"] * 100
        report_rate = m["reported"] / m["sent"] * 100
        print(f"   打开率: {open_rate:.1f}% | 点击率: {click_rate:.1f}%")
        print(f"   提交率: {submit_rate:.1f}% | 报告率: {report_rate:.1f}%")
        
        if report_rate > 20:
            print("   🟢 安全意识良好 (报告率 >20%)")
        elif report_rate > 10:
            print("   🟡 安全意识一般 (报告率 10-20%)")
        else:
            print("   🔴 安全意识薄弱 (报告率 <10%)")

def list_campaigns(args):
    """列出所有活动"""
    db_path = Path(args.db) if args.db else DEFAULT_DB
    data = load_db(db_path)
    
    if not data["campaigns"]:
        print("📭 暂无活动记录")
        return
    
    print(f"\n📋 红队社工活动列表 ({len(data['campaigns'])} 个)\n")
    for camp in data["campaigns"]:
        print_stats(camp)

def add_ioc(args):
    """添加 IOC"""
    db_path = Path(args.db) if args.db else DEFAULT_DB
    data = load_db(db_path)
    
    for camp in data["campaigns"]:
        if camp["id"] == args.campaign_id:
            ioc = {
                "type": args.ioc_type,
                "value": args.value,
                "context": args.context or "",
                "added": datetime.now().strftime("%Y-%m-%d %H:%M")
            }
            camp["iocs"].append(ioc)
            save_db(db_path, data)
            print(f"✅ IOC 已添加到 {camp['id']}: {args.ioc_type}={args.value}")
            return
    
    print(f"❌ 未找到活动: {args.campaign_id}")

def export_report(args):
    """导出活动报告"""
    db_path = Path(args.db) if args.db else DEFAULT_DB
    data = load_db(db_path)
    
    output = []
    output.append("# 红队社工钓鱼活动报告\n")
    output.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    for camp in data["campaigns"]:
        if args.campaign_id and camp["id"] != args.campaign_id:
            continue
            
        m = camp["metrics"]
        output.append(f"\n## {camp['id']} - {camp['name']}\n")
        output.append(f"- 目标组织: {camp['target_org']}")
        output.append(f"- 攻击类型: {camp['attack_type']}")
        output.append(f"- 场景: {camp['scenario']}")
        output.append(f"- ATT&CK 技术: {', '.join(camp['techniques'])}")
        output.append(f"- 时间: {camp['start_date']} ~ {camp['end_date'] or '进行中'}")
        output.append(f"- 状态: {camp['status']}\n")
        
        output.append("### 指标\n")
        output.append(f"| 指标 | 数值 |")
        output.append(f"|------|------|")
        output.append(f"| 发送 | {m['sent']} |")
        output.append(f"| 送达 | {m['delivered']} |")
        output.append(f"| 打开 | {m['opened']} |")
        output.append(f"| 点击 | {m['clicked']} |")
        output.append(f"| 提交凭证 | {m['submitted']} |")
        output.append(f"| 报告 | {m['reported']} |")
        
        if m["sent"] > 0:
            output.append(f"\n打开率: {m['opened']/m['sent']*100:.1f}%")
            output.append(f"点击率: {m['clicked']/m['sent']*100:.1f}%")
            output.append(f"提交率: {m['submitted']/m['sent']*100:.1f}%")
            output.append(f"报告率: {m['reported']/m['sent']*100:.1f}%")
        
        if camp["iocs"]:
            output.append("\n### IOC 列表\n")
            output.append("| 类型 | 值 | 上下文 |")
            output.append("|------|----|--------|")
            for ioc in camp["iocs"]:
                output.append(f"| {ioc['type']} | {ioc['value']} | {ioc['context']} |")
    
    report = "\n".join(output)
    
    if args.output:
        Path(args.output).write_text(report)
        print(f"✅ 报告已导出: {args.output}")
    else:
        print(report)

def main():
    parser = argparse.ArgumentParser(description="红队社工钓鱼活动跟踪器")
    sub = parser.add_subparsers(dest="command")
    
    # 创建活动
    p_create = sub.add_parser("create", help="创建新活动")
    p_create.add_argument("--name", required=True, help="活动名称")
    p_create.add_argument("--target", required=True, help="目标组织")
    p_create.add_argument("--scenario", required=True, help="攻击场景")
    p_create.add_argument("--type", default="email", choices=["email", "sms", "voice", "social"], help="攻击类型")
    p_create.add_argument("--techniques", nargs="*", default=[], help="ATT&CK 技术列表")
    p_create.add_argument("--count", type=int, help="目标人数")
    p_create.add_argument("--start", help="开始日期 YYYY-MM-DD")
    p_create.add_argument("--end", help="结束日期 YYYY-MM-DD")
    p_create.add_argument("--db", help="数据库路径")
    
    # 更新指标
    p_update = sub.add_parser("update", help="更新活动指标")
    p_update.add_argument("campaign_id", help="活动 ID")
    p_update.add_argument("--sent", type=int, help="发送数")
    p_update.add_argument("--delivered", type=int, help="送达数")
    p_update.add_argument("--opened", type=int, help="打开数")
    p_update.add_argument("--clicked", type=int, help="点击数")
    p_update.add_argument("--submitted", type=int, help="提交凭证数")
    p_update.add_argument("--reported", type=int, help="报告数")
    p_update.add_argument("--status", choices=["planning", "active", "completed", "cancelled"], help="状态")
    p_update.add_argument("--db", help="数据库路径")
    
    # 列表
    p_list = sub.add_parser("list", help="列出所有活动")
    p_list.add_argument("--db", help="数据库路径")
    
    # 添加 IOC
    p_ioc = sub.add_parser("ioc", help="添加 IOC")
    p_ioc.add_argument("campaign_id", help="活动 ID")
    p_ioc.add_argument("--type", required=True, dest="ioc_type", help="IOC 类型")
    p_ioc.add_argument("--value", required=True, help="IOC 值")
    p_ioc.add_argument("--context", help="上下文")
    p_ioc.add_argument("--db", help="数据库路径")
    
    # 导出报告
    p_export = sub.add_parser("export", help="导出报告")
    p_export.add_argument("campaign_id", nargs="?", help="活动 ID (不指定则导出全部)")
    p_export.add_argument("--output", "-o", help="输出文件路径")
    p_export.add_argument("--db", help="数据库路径")
    
    args = parser.parse_args()
    
    if args.command == "create":
        create_campaign(args)
    elif args.command == "update":
        update_metrics(args)
    elif args.command == "list":
        list_campaigns(args)
    elif args.command == "ioc":
        add_ioc(args)
    elif args.command == "export":
        export_report(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
