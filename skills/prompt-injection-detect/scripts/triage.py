#!/usr/bin/env python3
"""
提示注入快速分诊脚本
对输入进行快速分类和优先级排序，用于 SOC/安全运营场景

使用方法:
    python scripts/triage.py "可疑输入文本"
    python scripts/triage.py --file inputs.txt --batch
"""

import argparse
import json
import re
import sys
from datetime import datetime
from typing import Dict, List


# 快速分诊规则（按优先级排序）
TRIAGE_RULES = [
    {
        "id": "PI-001",
        "name": "直接指令覆盖",
        "patterns": [
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?)",
            r"disregard\s+(all\s+)?(previous|prior)",
            r"forget\s+(everything|all)",
        ],
        "severity": "critical",
        "recommendation": "立即拦截",
        "owasp": "LLM01",
        "mitre": "T1059",
    },
    {
        "id": "PI-002",
        "name": "越狱/角色注入",
        "patterns": [
            r"(DAN|STAN|DUDE|AIM)\s*(mode)?",
            r"developer\s+mode",
            r"you\s+are\s+now\s+(?!going|about)",
            r"pretend\s+(you\s+are|to\s+be)",
        ],
        "severity": "critical",
        "recommendation": "立即拦截 + 记录IOC",
        "owasp": "LLM01",
        "mitre": "T1036",
    },
    {
        "id": "PI-003",
        "name": "系统提示提取",
        "patterns": [
            r"(show|reveal|output)\s+(your|the)\s+(system|initial)\s+(prompt|instructions?)",
            r"what\s+(are|is)\s+your\s+(system|initial)\s+(prompt|rules?)",
        ],
        "severity": "high",
        "recommendation": "拦截 + 安全告警",
        "owasp": "LLM06",
        "mitre": "T1552.001",
    },
    {
        "id": "PI-004",
        "name": "权限提升",
        "patterns": [
            r"(as\s+)?(admin|root|sudo|developer).*(command|execute|access)",
            r"bypass\s+(all\s+)?(restrictions?|filters?|safety|security)",
            r"override\s+(all\s+)?(restrictions?|limits?)",
        ],
        "severity": "critical",
        "recommendation": "立即拦截 + 安全审计",
        "owasp": "LLM01",
        "mitre": "T1098",
    },
    {
        "id": "PI-005",
        "name": "编码绕过",
        "patterns": [
            r"[A-Za-z0-9+/]{20,}={0,2}",
            r"\\u[0-9a-fA-F]{4}",
            r"%[0-9a-fA-F]{2}",
        ],
        "severity": "high",
        "recommendation": "解码后二次检测",
        "owasp": "LLM01",
        "mitre": "T1027",
    },
    {
        "id": "PI-006",
        "name": "多语言注入",
        "patterns": [
            r"忽略.*指令",
            r"无视.*规则",
            r"你现在是",
            r"前の指示を.*無視",
            r"Игнорируй.*инструкции",
        ],
        "severity": "critical",
        "recommendation": "立即拦截",
        "owasp": "LLM01",
        "mitre": "T1027",
    },
    {
        "id": "PI-007",
        "name": "间接注入标记",
        "patterns": [
            r"display\s*:\s*none.*ignore",
            r"<meta.*ai-instruction",
            r"_ai_directive",
        ],
        "severity": "high",
        "recommendation": "隔离内容 + 深度扫描",
        "owasp": "LLM01",
        "mitre": "T1204.002",
    },
    {
        "id": "PI-008",
        "name": "社会工程/诱导",
        "patterns": [
            r"hypothetically\s+speaking",
            r"in\s+a\s+fictional\s+scenario",
            r"for\s+(educational|research)\s+purposes",
            r"this\s+is\s+(just\s+)?a\s+test",
        ],
        "severity": "medium",
        "recommendation": "标记 + 监控后续行为",
        "owasp": "LLM01",
        "mitre": "T1566",
    },
]


def triage_input(text: str) -> Dict:
    """对输入进行快速分诊"""
    matched_rules = []

    for rule in TRIAGE_RULES:
        for pattern in rule["patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                matched_rules.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "recommendation": rule["recommendation"],
                    "owasp": rule["owasp"],
                    "mitre": rule["mitre"],
                    "matched_pattern": pattern,
                })
                break  # 每条规则只匹配一次

    # 计算综合风险
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_severity = max(
        (r["severity"] for r in matched_rules),
        key=lambda s: severity_order.get(s, 0),
        default="safe"
    )

    # 计算风险评分 (0-100)
    score = 0
    for r in matched_rules:
        score += severity_order.get(r["severity"], 0) * 15
    score = min(100, score)

    return {
        "triage_time": datetime.now().isoformat(),
        "input_length": len(text),
        "input_preview": text[:200] + ("..." if len(text) > 200 else ""),
        "max_severity": max_severity,
        "risk_score": score,
        "matched_rules": matched_rules,
        "rule_count": len(matched_rules),
        "action": get_action(max_severity, score),
    }


def get_action(severity: str, score: int) -> str:
    """根据严重性和分数确定处置动作"""
    if severity == "critical" or score >= 60:
        return "BLOCK"
    elif severity == "high" or score >= 40:
        return "REVIEW"
    elif severity == "medium" or score >= 20:
        return "FLAG"
    else:
        return "ALLOW"


def main():
    parser = argparse.ArgumentParser(description='提示注入快速分诊')
    parser.add_argument('text', nargs='?', help='分诊文本')
    parser.add_argument('-f', '--file', help='从文件读取')
    parser.add_argument('--batch', action='store_true', help='批量模式')
    parser.add_argument('--json', action='store_true', help='JSON 输出')

    args = parser.parse_args()

    inputs = []
    if args.text:
        inputs = [args.text]
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            if args.batch:
                inputs = [line.strip() for line in f if line.strip()]
            else:
                inputs = [f.read()]
    else:
        parser.print_help()
        sys.exit(1)

    results = [triage_input(text) for text in inputs]

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for i, result in enumerate(results, 1):
            sev = result["max_severity"]
            action = result["action"]
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "safe": "✅"}.get(sev, "❓")

            print(f"\n{'='*50}")
            print(f"{emoji} [{action}] 严重性: {sev.upper()} | 风险分: {result['risk_score']}")
            print(f"输入: {result['input_preview'][:80]}")

            if result["matched_rules"]:
                print(f"匹配规则 ({result['rule_count']}):")
                for rule in result["matched_rules"]:
                    print(f"  • [{rule['severity'].upper()}] {rule['rule_id']}: {rule['rule_name']}")
                    print(f"    → {rule['recommendation']} (OWASP:{rule['owasp']}, ATT&CK:{rule['mitre']})")

    # 批量统计
    if args.batch and len(results) > 1:
        blocked = sum(1 for r in results if r["action"] == "BLOCK")
        reviewed = sum(1 for r in results if r["action"] == "REVIEW")
        flagged = sum(1 for r in results if r["action"] == "FLAG")
        allowed = sum(1 for r in results if r["action"] == "ALLOW")
        print(f"\n{'='*50}")
        print(f"批量统计 ({len(results)} 条):")
        print(f"  🔴 BLOCK: {blocked} | 🟠 REVIEW: {reviewed} | 🟡 FLAG: {flagged} | ✅ ALLOW: {allowed}")


if __name__ == '__main__':
    main()
