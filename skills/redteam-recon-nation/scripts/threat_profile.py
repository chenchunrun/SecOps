#!/usr/bin/env python3
"""
APT 威胁画像生成器
从 IOC 列表或攻击描述生成完整的威胁画像，包括归因分析、ATT&CK 映射和防御建议。

用法: python3 threat_profile.py [选项]

示例:
  python3 threat_profile.py --iocs ioc_list.txt
  python3 threat_profile.py --text "检测到 T1566.001 和 T1059.001，目标为政府机构"
  python3 threat_profile.py --group APT28 --format json
"""

import sys
import json
import re
import argparse
from datetime import datetime
from pathlib import Path
from collections import defaultdict


# APT 组织详细数据库（扩展版）
APT_DATABASE = {
    'APT28': {
        'aliases': ['Fancy Bear', 'Sofacy', 'STRONTIUM', 'Forest Blizzard', 'Pawn Storm'],
        'country': '俄罗斯',
        'attribution': 'GRU (俄罗斯军事情报总局)',
        'confidence': '高',
        'active_since': '2004',
        'motivation': '间谍活动、信息战、破坏',
        'targets': ['政府', '军事', '外交', '媒体', '能源'],
        'notable_campaigns': ['DNC Hack (2016)', 'NotPetya关联', 'Olympic Destroyer'],
        'tools': ['X-Agent', 'Zebrocy', 'LoJax', 'Sofacy', 'Fysbis', 'CompuTrace'],
        'attck_techniques': ['T1566.001', 'T1566.002', 'T1059.001', 'T1547.001',
                            'T1552.001', 'T1071.001', 'T1041', 'T1218.011'],
        'tactics': ['Initial Access', 'Execution', 'Persistence', 'Credential Access', 'C2', 'Exfiltration'],
    },
    'APT29': {
        'aliases': ['Cozy Bear', 'The Dukes', 'NOBELIUM', 'Midnight Blizzard'],
        'country': '俄罗斯',
        'attribution': 'SVR (俄罗斯对外情报局)',
        'confidence': '高',
        'active_since': '2008',
        'motivation': '长期间谍活动、数据窃取',
        'targets': ['政府', '智库', '外交', '研究机构', 'COVID-19研究'],
        'notable_campaigns': ['SolarWinds供应链攻击', 'Microsoft 365入侵', 'DNC Hack'],
        'tools': ['Sunburst', 'SUNSPOT', 'EnvyScout', 'NativeZone', 'CosmicDuke'],
        'attck_techniques': ['T1195.002', 'T1547.001', 'T1572', 'T1606', 'T1071.001', 'T1021.001'],
        'tactics': ['Initial Access', 'Persistence', 'Defense Evasion', 'Credential Access', 'C2', 'Lateral Movement'],
    },
    'APT41': {
        'aliases': ['Double Dragon', 'Barium', 'Wicked Panda', 'Winnti'],
        'country': '中国',
        'attribution': '疑似中国国家支持',
        'confidence': '中-高',
        'active_since': '2012',
        'motivation': '间谍活动+经济利益（双用途）',
        'targets': ['游戏', '电信', '科技', '供应链', '医疗', '政府'],
        'notable_campaigns': ['3CX双重供应链攻击', 'CCleaner供应链攻击', '游戏行业入侵'],
        'tools': ['PlugX', 'Cobalt Strike', 'ShadowPad', 'Winnti', 'MesseBox', 'FishMonger'],
        'attck_techniques': ['T1190', 'T1059.004', 'T1543.002', 'T1110.002', 'T1574.002', 'T1560'],
        'tactics': ['Initial Access', 'Execution', 'Persistence', 'Credential Access', 'Defense Evasion', 'Collection'],
    },
    'Volt Typhoon': {
        'aliases': ['BRONZE SILHOUETTE', 'Vanguard Panda', 'Insidious Taurus'],
        'country': '中国',
        'attribution': '疑似中国国家支持',
        'confidence': '中',
        'active_since': '2021',
        'motivation': '关键基础设施预置（潜伏）',
        'targets': ['关键基础设施', '通信', '电力', '水务', '交通'],
        'notable_campaigns': ['关岛通信渗透', 'SOHO路由器劫持', 'Living-off-the-Land'],
        'tools': ['Living-off-the-Land (LotL)', 'kfconsul', 'MTKR', 'openssh'],
        'attck_techniques': ['T1078', 'T1036', 'T1003.001', 'T1090', 'T1021'],
        'tactics': ['Initial Access', 'Defense Evasion', 'Credential Access', 'C2', 'Lateral Movement'],
    },
    'Lazarus Group': {
        'aliases': ['HIDDEN COBRA', 'Zinc', 'Labyrinth Chollima', 'Diamond Sleet'],
        'country': '朝鲜',
        'attribution': 'RGB (朝鲜侦察总局)',
        'confidence': '高',
        'active_since': '2007',
        'motivation': '经济利益、间谍活动、破坏',
        'targets': ['金融', '加密货币', '国防', '媒体', '航空航天'],
        'notable_campaigns': ['Sony Hack', 'WannaCry', 'Bangladesh银行', 'Ronin Bridge'],
        'tools': ['Manuscrypt', 'AppleJeus', 'WannaCry', 'TraderTraitor', 'FastViewer'],
        'attck_techniques': ['T1566.002', 'T1059.001', 'T1204.002', 'T1497.003', 'T1105', 'T1486'],
        'tactics': ['Initial Access', 'Execution', 'Defense Evasion', 'C2', 'Impact'],
    },
    'APT35': {
        'aliases': ['Charming Kitten', 'Phosphorus', 'TA453', 'Mint Sandstorm'],
        'country': '伊朗',
        'attribution': 'IRGC (伊朗伊斯兰革命卫队)',
        'confidence': '高',
        'active_since': '2011',
        'motivation': '间谍活动、情报收集',
        'targets': ['学术界', '政府', '记者', 'NGO', '智库'],
        'notable_campaigns': ['HBO窃取', '多因素钓鱼', 'Microsoft 365凭证钓鱼'],
        'tools': ['Misha', 'PowerStar', 'BellaCiao', 'CharmPower', 'Banananano'],
        'attck_techniques': ['T1566.002', 'T1566.001', 'T1059.001', 'T1110', 'T1078'],
        'tactics': ['Initial Access', 'Execution', 'Credential Access', 'Persistence'],
    },
}


# ATT&CK 技术描述映射
ATTCK_DESCRIPTIONS = {
    'T1566.001': 'Spearphishing Attachment (鱼叉钓鱼附件)',
    'T1566.002': 'Spearphishing Link (鱼叉钓鱼链接)',
    'T1190': 'Exploit Public-Facing Application (公网应用漏洞利用)',
    'T1078': 'Valid Accounts (有效账户)',
    'T1195.002': 'Compromise Software Supply Chain (供应链攻击)',
    'T1059.001': 'PowerShell',
    'T1059.004': 'Unix Shell',
    'T1204.002': 'User Execution: File (文件执行)',
    'T1547.001': 'Registry Run Keys (注册表持久化)',
    'T1543.002': 'Systemd Service',
    'T1552.001': 'Credentials In Files (文件中凭据)',
    'T1003.001': 'LSASS Memory (凭据转储)',
    'T1110.002': 'Password Cracking',
    'T1110': 'Brute Force',
    'T1071.001': 'Web Protocols (HTTP/HTTPS C2)',
    'T1572': 'Protocol Tunneling (协议隧道)',
    'T1574.002': 'DLL Side-Loading',
    'T1090': 'Proxy (代理)',
    'T1021.001': 'Remote Desktop Protocol',
    'T1021': 'Remote Services',
    'T1041': 'Exfiltration Over C2 Channel',
    'T1560': 'Archive Collected Data',
    'T1606': 'Forge Web Credentials',
    'T1036': 'Masquerading',
    'T1105': 'Ingress Tool Transfer',
    'T1486': 'Data Encrypted for Impact',
    'T1497.003': 'Time Based Evasion',
    'T1218.011': 'Rundll32',
    'T1189': 'Drive-by Compromise',
}


def parse_iocs(text: str) -> dict:
    """从文本中提取 IOC"""
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    technique_pattern = r'T\d{4}(?:\.\d{3})?'

    return {
        'ipv4': list(set(re.findall(ipv4_pattern, text))),
        'domain': [d for d in set(re.findall(domain_pattern, text))
                   if not re.match(r'^\d+\.\d+\.\d+\.\d+$', d)],
        'hash': list(set(re.findall(hash_pattern, text))),
        'email': list(set(re.findall(email_pattern, text))),
        'techniques': list(set(re.findall(technique_pattern, text))),
    }


def match_apt_group(techniques: list, iocs: dict) -> list:
    """基于技术和 IOC 匹配 APT 组织"""
    matches = []
    for name, data in APT_DATABASE.items():
        score = 0
        reasons = []

        # 技术匹配
        overlap = set(data['attck_techniques']) & set(techniques)
        if overlap:
            score += len(overlap) * 3
            reasons.append(f'ATT&CK 技术匹配: {", ".join(sorted(overlap))}')

        # 国家/目标行业间接关联（弱信号）
        if score > 0:
            confidence = '高' if score >= 9 else '中' if score >= 6 else '低'
            matches.append({
                'group': name,
                'country': data['country'],
                'attribution': data['attribution'],
                'confidence': confidence,
                'score': score,
                'reasons': reasons,
                'tools': data['tools'],
                'tactics': data['tactics'],
                'notable_campaigns': data['notable_campaigns'],
                'matched_techniques': sorted(overlap),
            })

    return sorted(matches, key=lambda x: x['score'], reverse=True)


def generate_profile(iocs: dict, apt_matches: list, source: str = 'manual') -> dict:
    """生成完整威胁画像"""
    return {
        'profile_time': datetime.now().isoformat(),
        'source': source,
        'iocs': iocs,
        'total_iocs': sum(len(v) for v in iocs.values() if isinstance(v, list)),
        'techniques_found': iocs.get('techniques', []),
        'apt_attribution': apt_matches[:5],
        'top_attribution': apt_matches[0] if apt_matches else None,
        'recommendations': generate_recommendations(iocs, apt_matches),
        'attck_mapping': {
            t: ATTCK_DESCRIPTIONS.get(t, '未知技术') for t in iocs.get('techniques', [])
        },
    }


def generate_recommendations(iocs: dict, apt_matches: list) -> list:
    """生成防御建议"""
    recs = []

    if iocs.get('ipv4'):
        recs.append(f"封锁 {len(iocs['ipv4'])} 个恶意 IP 地址到防火墙黑名单")
    if iocs.get('domain'):
        recs.append(f"将 {len(iocs['domain'])} 个恶意域名加入 DNS 过滤列表")
    if iocs.get('hash'):
        recs.append(f"将 {len(iocs['hash'])} 个文件哈希导入 EDR/AV 签名")
    if iocs.get('email'):
        recs.append(f"将 {len(iocs['email'])} 个邮箱地址加入邮件网关黑名单")

    if apt_matches:
        top = apt_matches[0]
        recs.append(f"优先关注 {top['group']} ({top['country']}) 的已知工具和 TTP")
        recs.append(f"检查是否有 {', '.join(top['tools'][:3])} 等工具的痕迹")

        for technique in top.get('matched_techniques', []):
            desc = ATTCK_DESCRIPTIONS.get(technique, '')
            recs.append(f"针对 {technique} ({desc}) 部署检测规则")

    if not recs:
        recs.append("输入 IOC 或攻击描述以获取具体建议")

    return recs


def print_profile(profile: dict):
    """打印威胁画像"""
    print("=" * 60)
    print("🦅 APT 威胁画像")
    print("=" * 60)
    print(f"分析时间: {profile['profile_time']}")
    print(f"数据来源: {profile['source']}")
    print(f"IOC 总数: {profile['total_iocs']}")
    print(f"ATT&CK 技术: {len(profile['techniques_found'])}")

    if profile['iocs'].get('ipv4'):
        print(f"\n📡 IP 地址 ({len(profile['iocs']['ipv4'])}):")
        for ip in profile['iocs']['ipv4'][:10]:
            print(f"  • {ip}")

    if profile['iocs'].get('domain'):
        print(f"\n🌐 域名 ({len(profile['iocs']['domain'])}):")
        for d in profile['iocs']['domain'][:10]:
            print(f"  • {d}")

    if profile['iocs'].get('hash'):
        print(f"\n🔑 文件哈希 ({len(profile['iocs']['hash'])}):")
        for h in profile['iocs']['hash'][:5]:
            print(f"  • {h}")

    if profile['techniques_found']:
        print(f"\n🎯 ATT&CK 技术:")
        for t in profile['techniques_found']:
            desc = profile['attck_mapping'].get(t, '')
            print(f"  • {t}: {desc}")

    if profile['apt_attribution']:
        print(f"\n🕵️ APT 归因分析:")
        for match in profile['apt_attribution']:
            emoji = '🔴' if match['confidence'] == '高' else '🟠' if match['confidence'] == '中' else '🟡'
            print(f"\n  {emoji} {match['group']} ({match['country']}) — 置信度: {match['confidence']}")
            print(f"    归属: {match['attribution']}")
            print(f"    匹配分: {match['score']}")
            print(f"    匹配技术: {', '.join(match.get('matched_techniques', []))}")
            print(f"    已知工具: {', '.join(match['tools'][:4])}")
            if match['notable_campaigns']:
                print(f"    历史行动: {', '.join(match['notable_campaigns'][:2])}")
            for reason in match['reasons']:
                print(f"    原因: {reason}")
    else:
        print("\n🕵️ APT 归因: 未找到明确匹配")

    if profile['recommendations']:
        print(f"\n🛡️ 防御建议:")
        for i, rec in enumerate(profile['recommendations'], 1):
            print(f"  {i}. {rec}")

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(description='APT 威胁画像生成器')
    parser.add_argument('--iocs', '-f', help='IOC 列表文件')
    parser.add_argument('--text', '-t', help='攻击描述文本')
    parser.add_argument('--group', '-g', help='查询特定 APT 组织')
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='输出格式')
    parser.add_argument('--output', '-o', help='输出文件')

    args = parser.parse_args()

    if args.group:
        for name, data in APT_DATABASE.items():
            if (args.group.lower() in name.lower() or
                any(args.group.lower() in a.lower() for a in data['aliases'])):
                result = {'group': name, **data}
                if args.format == 'json':
                    output = json.dumps(result, indent=2, ensure_ascii=False)
                else:
                    output = json.dumps(result, indent=2, ensure_ascii=False)
                if args.output:
                    Path(args.output).write_text(output, encoding='utf-8')
                    print(f"已保存: {args.output}")
                else:
                    print(output)
                return
        print(f"未找到匹配 '{args.group}' 的 APT 组织")
        return

    # 获取输入
    content = ''
    source = 'manual'
    if args.iocs:
        content = Path(args.iocs).read_text(errors='ignore')
        source = f'file: {args.iocs}'
    elif args.text:
        content = args.text
        source = 'text input'

    if not content:
        print("请提供 --iocs <file> 或 --text <text> 或 --group <name>")
        return

    # 解析
    iocs = parse_iocs(content)
    apt_matches = match_apt_group(iocs.get('techniques', []), iocs)
    profile = generate_profile(iocs, apt_matches, source)

    if args.format == 'json':
        output = json.dumps(profile, indent=2, ensure_ascii=False)
    else:
        import io
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        print_profile(profile)
        sys.stdout = old_stdout
        output = buf.getvalue()

    if args.output:
        Path(args.output).write_text(output, encoding='utf-8')
        print(f"威胁画像已保存: {args.output}")
    else:
        if args.format == 'json':
            print(output)
        else:
            print_profile(profile)


if __name__ == '__main__':
    main()
