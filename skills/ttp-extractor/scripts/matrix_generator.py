#!/usr/bin/env python3
"""
ATT&CK 矩阵可视化生成器
从文本中提取 TTP 并生成 ATT&CK 矩阵格式的报告

使用方法:
    python scripts/matrix_generator.py --text "安全报告内容..."
    python scripts/matrix_generator.py --file report.txt --format markdown
"""

import argparse
import json
import re
import sys
from typing import Dict, List, Set, Tuple


# ATT&CK 14 战术定义
ATTACK_TACTICS = [
    ("TA0043", "Reconnaissance", "侦察"),
    ("TA0042", "Resource Development", "资源开发"),
    ("TA0001", "Initial Access", "初始访问"),
    ("TA0002", "Execution", "执行"),
    ("TA0003", "Persistence", "持久化"),
    ("TA0004", "Privilege Escalation", "权限提升"),
    ("TA0005", "Defense Evasion", "防御规避"),
    ("TA0006", "Credential Access", "凭据访问"),
    ("TA0007", "Discovery", "发现"),
    ("TA0008", "Lateral Movement", "横向移动"),
    ("TA0009", "Collection", "收集"),
    ("TA0011", "Command and Control", "命令与控制"),
    ("TA0010", "Exfiltration", "数据外发"),
    ("TA0040", "Impact", "影响"),
]

# 技术到战术的映射
TECHNIQUE_TACTIC_MAP = {
    "T1590": "TA0043", "T1592": "TA0043", "T1595": "TA0043", "T1589": "TA0043",
    "T1583": "TA0042", "T1587": "TA0042", "T1588": "TA0042",
    "T1566": "TA0001", "T1190": "TA0001", "T1078": "TA0001", "T1133": "TA0001", "T1195": "TA0001", "T1199": "TA0001",
    "T1059": "TA0002", "T1204": "TA0002", "T1106": "TA0002", "T1053": "TA0002",
    "T1543": "TA0003", "T1547": "TA0003", "T1136": "TA0003", "T1546": "TA0003",
    "T1548": "TA0004", "T1068": "TA0004", "T1134": "TA0004",
    "T1027": "TA0005", "T1036": "TA0005", "T1070": "TA0005", "T1140": "TA0005", "T1218": "TA0005", "T1562": "TA0005",
    "T1110": "TA0006", "T1003": "TA0006", "T1552": "TA0006", "T1056": "TA0006",
    "T1046": "TA0007", "T1087": "TA0007", "T1018": "TA0007", "T1082": "TA0007",
    "T1021": "TA0008", "T1072": "TA0008", "T1570": "TA0008", "T1550": "TA0008",
    "T1560": "TA0009", "T1005": "TA0009", "T1119": "TA0009", "T1213": "TA0009",
    "T1071": "TA0011", "T1573": "TA0011", "T1090": "TA0011", "T1132": "TA0011", "T1571": "TA0011",
    "T1041": "TA0010", "T1567": "TA0010", "T1029": "TA0010", "T1537": "TA0010",
    "T1486": "TA0040", "T1499": "TA0040", "T1485": "TA0040", "T1561": "TA0040",
}


def extract_techniques(text: str) -> List[Dict]:
    """从文本中提取 ATT&CK 技术引用"""
    # 匹配 T+4位数字(.+3位数字) 的模式
    pattern = r'\b(T\d{4}(?:\.\d{3})?)\b'
    matches = re.findall(pattern, text)

    techniques = []
    seen = set()
    for match in matches:
        if match not in seen:
            seen.add(match)
            # 获取父技术
            parent = match.split('.')[0] if '.' in match else match
            # 查找战术
            tactic_id = TECHNIQUE_TACTIC_MAP.get(parent, TECHNIQUE_TACTIC_MAP.get(match, ""))

            techniques.append({
                "technique_id": match,
                "parent_id": parent,
                "tactic_id": tactic_id,
                "mentions": len(re.findall(r'\b' + match + r'\b', text))
            })

    return techniques


def generate_matrix(techniques: List[Dict]) -> Dict:
    """生成 ATT&CK 矩阵"""
    matrix = {}
    for tactic_id, tactic_name, tactic_cn in ATTACK_TACTICS:
        matrix[tactic_id] = {
            "tactic_name": tactic_name,
            "tactic_cn": tactic_cn,
            "techniques": []
        }

    for tech in techniques:
        tac_id = tech["tactic_id"]
        if tac_id in matrix:
            matrix[tac_id]["techniques"].append(tech)

    # 移除空战术
    matrix = {k: v for k, v in matrix.items() if v["techniques"]}

    return matrix


def matrix_to_markdown(matrix: Dict) -> str:
    """Markdown 表格格式"""
    lines = ["## ATT&CK 矩阵映射\n"]
    lines.append("| 战术 | 技术 ID | 出现次数 |")
    lines.append("|------|---------|----------|")

    for tac_id, tac_data in matrix.items():
        for tech in tac_data["techniques"]:
            lines.append(
                f"| {tac_data['tactic_cn']} ({tac_data['tactic_name']}) | "
                f"{tech['technique_id']} | {tech['mentions']} |"
            )

    lines.append("\n### 矩阵可视化\n")
    lines.append("```")
    lines.append("| " + " | ".join(
        f"{tac_data['tactic_cn'][:2]}" for tac_data in matrix.values()
    ) + " |")
    lines.append("|" + "|".join("---" for _ in matrix) + "|")
    lines.append("| " + " | ".join(
        ", ".join(t["technique_id"] for t in tac_data["techniques"])
        for tac_data in matrix.values()
    ) + " |")
    lines.append("```")

    return "\n".join(lines)


def matrix_to_json(matrix: Dict, techniques: List[Dict]) -> str:
    """JSON 格式"""
    return json.dumps({
        "total_techniques": len(techniques),
        "unique_techniques": len(set(t["technique_id"] for t in techniques)),
        "tactics_covered": len(matrix),
        "matrix": matrix,
        "all_techniques": techniques,
    }, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser(description='ATT&CK 矩阵生成器')
    parser.add_argument('--text', '-t', help='分析文本')
    parser.add_argument('--file', '-f', help='从文件读取')
    parser.add_argument('--format', '-F', default='markdown', choices=['markdown', 'json'],
                       help='输出格式')

    args = parser.parse_args()

    if args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            text = f.read()
    elif args.text:
        text = args.text
    else:
        parser.print_help()
        sys.exit(1)

    techniques = extract_techniques(text)
    matrix = generate_matrix(techniques)

    if not matrix:
        print("⚠️ 未在文本中找到 ATT&CK 技术引用")
        sys.exit(0)

    if args.format == 'json':
        print(matrix_to_json(matrix, techniques))
    else:
        print(f"\n📊 共提取 {len(techniques)} 个技术，覆盖 {len(matrix)} 个战术阶段\n")
        print(matrix_to_markdown(matrix))


if __name__ == '__main__':
    main()
