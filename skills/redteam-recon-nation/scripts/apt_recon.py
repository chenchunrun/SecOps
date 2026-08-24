#!/usr/bin/env python3
"""国家级APT攻击侦察工具 - 针对高级持续性威胁的情报收集与分析"""

import argparse
import json
import re
import sys
from datetime import datetime
from typing import Dict, List, Optional

# 已知APT组织数据库
APT_GROUPS = {
    'APT1': {'aliases': ['Comment Crew', 'PLA 61398'], 'country': '中国', 'targets': ['国防', '航空航天', '电信']},
    'APT28': {'aliases': ['Fancy Bear', 'Sofacy', 'STRONTIUM'], 'country': '俄罗斯', 'targets': ['政府', '军事', '外交']},
    'APT29': {'aliases': ['Cozy Bear', 'The Dukes', 'NOBELIUM'], 'country': '俄罗斯', 'targets': ['政府', '智库', 'COVID研究']},
    'APT38': {'aliases': ['Lazarus Group', 'HIDDEN COBRA', 'Zinc'], 'country': '朝鲜', 'targets': ['金融', '国防', '加密货币']},
    'APT41': {'aliases': ['Double Dragon', 'Barium'], 'country': '中国', 'targets': ['游戏', '供应链', '电信']},
    'APT33': {'aliases': ['Elfin', 'Refined Kitten'], 'country': '伊朗', 'targets': ['能源', '航空航天']},
    'APT35': {'aliases': ['Charming Kitten', 'Phosphorus', 'TA453'], 'country': '伊朗', 'targets': ['学术界', '政府', '记者']},
    'APT42': {'aliases': ['UNC787', 'Yellow Garuda'], 'country': '伊朗', 'targets': ['NGO', '学术界', '政府']},
    'MuddyWater': {'aliases': ['TEMP.Zagros', 'Mercury', 'Static Kitten'], 'country': '伊朗', 'targets': ['政府', '电信', '能源']},
    'Turla': {'aliases': ['Snake', 'KRYPTON', 'Venomous Bear'], 'country': '俄罗斯', 'targets': ['政府', '外交', '军事']},
    'FIN7': {'aliases': ['Carbanak', 'Anunak'], 'country': '俄罗斯', 'targets': ['零售', '餐饮', '金融']},
    'Volt Typhoon': {'aliases': ['BRONZE SILHOUETTE', 'Vanguard Panda'], 'country': '中国', 'targets': ['关键基础设施', '通信']},
}

# ATT&CK战术到APT行为模式映射
APT_BEHAVIORS = {
    'initial_access': ['T1566.001', 'T1566.002', 'T1190', 'T1078', 'T1189'],
    'execution': ['T1059.001', 'T1059.003', 'T1204', 'T1053', 'T1559'],
    'persistence': ['T1053', 'T1547', 'T1133', 'T1505', 'T1574'],
    'c2': ['T1071', 'T1573', 'T1105', 'T1090', 'T1008'],
    'exfil': ['T1041', 'T1048', 'T1567', 'T1011'],
}

def identify_apt(iocs: Dict[str, List[str]], behavior: List[str] = None) -> List[Dict]:
    """根据IoC和行为模式识别可能的APT组织"""
    matches = []
    for name, info in APT_GROUPS.items():
        score = 0
        reasons = []

        # 基于行为匹配
        if behavior:
            for tactic, techniques in APT_BEHAVIORS.items():
                overlap = set(techniques) & set(behavior)
                if overlap:
                    score += len(overlap) * 2
                    reasons.append(f'{tactic}: {len(overlap)} 个技术匹配')

        if score > 0:
            matches.append({
                'group': name,
                'score': score,
                'reasons': reasons,
                'country': info['country'],
                'targets': info['targets'],
                'aliases': info['aliases'],
            })

    return sorted(matches, key=lambda x: x['score'], reverse=True)

def analyze_attack_pattern(attack_data: str) -> Dict:
    """分析攻击模式并关联APT组织"""
    # 提取技术指标
    techniques = re.findall(r'T\d{4}(?:\.\d{3})?', attack_data)

    # 提取IoC
    ipv4s = re.findall(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b', attack_data)
    domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', attack_data)
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', attack_data)

    iocs = {
        'ipv4': list(set(ipv4s)),
        'domain': list(set(domains)),
        'hash': list(set(hashes)),
        'techniques': list(set(techniques)),
    }

    # 识别APT
    apt_matches = identify_apt(iocs, techniques)

    return {
        'timestamp': datetime.now().isoformat(),
        'iocs': iocs,
        'techniques_found': list(set(techniques)),
        'apt_attribution': apt_matches[:5],
        'summary': {
            'total_iocs': sum(len(v) for v in iocs.values() if isinstance(v, list)),
            'total_techniques': len(set(techniques)),
            'top_attribution': apt_matches[0] if apt_matches else None,
        }
    }

def generate_threatIntel_report(analysis: Dict) -> str:
    """生成威胁情报报告"""
    lines = [
        f"{'='*60}",
        f"🦅 国家级APT威胁情报分析",
        f"{'='*60}",
        f"时间: {analysis['timestamp']}",
        f"",
        f"📊 指标统计:",
        f"  IoC总数: {analysis['summary']['total_iocs']}",
        f"  ATT&CK技术: {analysis['summary']['total_techniques']}",
    ]

    if analysis['iocs'].get('techniques'):
        lines.append(f"\n🎯 发现的ATT&CK技术:")
        for t in analysis['iocs'].get('techniques', []):
            lines.append(f"  • {t}")

    if analysis['apt_attribution']:
        lines.append(f"\n🕵️ APT归因分析:")
        for match in analysis['apt_attribution']:
            lines.append(f"  [{match['score']}分] {match['group']} ({match['country']})")
            lines.append(f"    别名: {', '.join(match['aliases'][:3])}")
            lines.append(f"    目标: {', '.join(match['targets'])}")
            for r in match['reasons'][:3]:
                lines.append(f"    匹配: {r}")
    else:
        lines.append(f"\n🕵️ APT归因: 未找到明确匹配")

    return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser(description='国家级APT攻击侦察工具')
    parser.add_argument('-f', '--file', help='攻击数据文件')
    parser.add_argument('-t', '--text', help='攻击描述文本')
    parser.add_argument('--group', help='查询特定APT组织信息')
    parser.add_argument('--json', action='store_true', help='JSON输出')
    args = parser.parse_args()

    if args.group:
        group = args.group.upper()
        info = APT_GROUPS.get(group)
        if info:
            result = {'group': group, **info}
        else:
            # 模糊搜索
            found = []
            for name, data in APT_GROUPS.items():
                if (group.lower() in name.lower() or
                    any(group.lower() in alias.lower() for alias in data['aliases'])):
                    found.append({'group': name, **data})
            result = {'matches': found}
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    content = ''
    if args.file:
        from pathlib import Path
        content = Path(args.file).read_text(errors='ignore')
    elif args.text:
        content = args.text
    else:
        # 列出所有已知APT
        print(f"{'='*50}")
        print(f"已知APT组织 ({len(APT_GROUPS)} 个):")
        print(f"{'='*50}")
        for name, info in APT_GROUPS.items():
            print(f"  {name} ({info['country']}) - 目标: {', '.join(info['targets'])}")
        return

    result = analyze_attack_pattern(content)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(generate_threatIntel_report(result))

if __name__ == '__main__':
    main()
