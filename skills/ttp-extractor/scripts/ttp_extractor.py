#!/usr/bin/env python3
"""TTP提取工具 - 从威胁报告/攻击日志中提取MITRE ATT&CK技术"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# ATT&CK技术关键词映射
TECHNIQUE_KEYWORDS = {
    'T1566.001': {'name': '钓鱼附件', 'keywords': ['phishing attachment', 'malicious attachment', '钓鱼附件', '恶意附件', '.doc', '.pdf attachment', '.xlsx attachment']},
    'T1566.002': {'name': '钓鱼链接', 'keywords': ['phishing link', 'malicious url', '钓鱼链接', '恶意链接', 'spear.phish']},
    'T1190': {'name': '利用公开应用', 'keywords': ['exploit public-facing application', 'web application vulnerability', '利用公开', 'web漏洞', 'sql injection', 'rce exploit']},
    'T1059.001': {'name': 'PowerShell', 'keywords': ['powershell', 'ps1', 'invoke-', 'powershell.exe', '-encodedcommand', '-executionpolicy']},
    'T1059.003': {'name': 'Windows命令行', 'keywords': ['cmd.exe', 'command prompt', 'batch file', '.bat', 'windows command']},
    'T1059.005': {'name': 'Visual Basic', 'keywords': ['vbscript', 'vba', '.vbs', '.vba', 'macro', 'wscript']},
    'T1059.006': {'name': 'Python', 'keywords': ['python', '.py', 'python.exe', 'pip install']},
    'T1053': {'name': '计划任务', 'keywords': ['scheduled task', 'cron', 'schtasks', 'at.exe', 'crontab', '计划任务', '定时任务']},
    'T1547': {'name': '启动/登录自启动', 'keywords': ['registry run keys', 'startup folder', '自启动', '开机启动', 'run key', 'startup']},
    'T1133': {'name': '外部远程服务', 'keywords': ['external remote services', 'vpn', 'remote desktop', 'rdp', 'teamviewer', 'anydesk']},
    'T1078': {'name': '有效账号', 'keywords': ['valid accounts', 'credential', 'default password', 'stolen credentials', '有效账号', '凭证']},
    'T1003': {'name': '凭证转储', 'keywords': ['credential dumping', 'lsass', 'mimikatz', 'sam', 'lsadump', 'procdump', '凭证转储']},
    'T1110': {'name': '暴力破解', 'keywords': ['brute force', 'password spraying', 'credential stuffing', '暴力破解', '爆破']},
    'T1071': {'name': '应用层协议', 'keywords': ['application layer protocol', 'http', 'https', 'dns', 'c2 communication', 'beacon']},
    'T1573': {'name': '加密信道', 'keywords': ['encrypted channel', 'tls', 'ssl', 'https c2', '加密通信']},
    'T1105': {'name': '入口工具传输', 'keywords': ['ingress tool transfer', 'download file', 'payload download', '下载载荷']},
    'T1041': {'name': '通过C2信道渗出', 'keywords': ['exfiltration over c2', 'data exfiltration', '数据渗出', '数据外传']},
    'T1048': {'name': '替代协议渗出', 'keywords': ['exfiltration over alternative protocol', 'dns exfiltration', 'dns tunneling', 'dns渗出']},
    'T1486': {'name': '数据加密（勒索）', 'keywords': ['ransomware', 'encrypt data', 'data encrypted for impact', '勒索', '加密勒索']},
    'T1498': {'name': '网络拒绝服务', 'keywords': ['ddos', 'denial of service', 'dos attack', '拒绝服务', 'syn flood']},
    'T1562': {'name': '禁用安全工具', 'keywords': ['disable security tools', 'antivirus', 'defender', 'disable firewall', '关闭杀毒', '禁用防火墙']},
    'T1574': {'name': '劫持执行流', 'keywords': ['hijack execution flow', 'dll hijacking', 'dll侧载', 'dll search order']},
    'T1036': {'name': '伪装', 'keywords': ['masquerading', 'rename', '伪装', 'spoof', 'legitimate name']},
    'T1204': {'name': '用户执行', 'keywords': ['user execution', 'malicious file', '用户执行', '点击', '打开附件']},
    'T1021': {'name': '远程服务', 'keywords': ['remote services', 'smb', 'ssh', 'rdp', 'winrm', 'psexec', 'lateral movement', '横向移动']},
    'T1087': {'name': '账号发现', 'keywords': ['account discovery', 'net user', 'domain admin', '账号发现']},
    'T1046': {'name': '网络服务发现', 'keywords': ['network service scanning', 'port scan', 'nmap', '网络扫描', '端口扫描']},
    'T1083': {'name': '文件和目录发现', 'keywords': ['file and directory discovery', 'dir', 'ls', 'find', '文件发现']},
    'T1505.003': {'name': 'Web Shell', 'keywords': ['web shell', 'backdoor', 'webshell', '后门', '一句话木马']},
    'T1195': {'name': '供应链攻击', 'keywords': ['supply chain', 'third-party', '供应链', '第三方', 'dependency confusion']},
}

def extract_ttps(text: str) -> List[Dict]:
    """从文本中提取TTP"""
    findings = []
    text_lower = text.lower()

    for tech_id, info in TECHNIQUE_KEYWORDS.items():
        for keyword in info['keywords']:
            if keyword.lower() in text_lower:
                # 计算上下文位置
                idx = text_lower.find(keyword.lower())
                context_start = max(0, idx - 50)
                context_end = min(len(text), idx + len(keyword) + 50)
                context = text[context_start:context_end].replace('\n', ' ')

                findings.append({
                    'technique_id': tech_id,
                    'name': info['name'],
                    'matched_keyword': keyword,
                    'confidence': 'high' if len(keyword) > 8 else 'medium',
                    'context': context,
                })
                break  # 一个技术只需匹配一个关键词

    # 去重
    seen = set()
    unique_findings = []
    for f in findings:
        key = f['technique_id']
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return sorted(unique_findings, key=lambda x: x['technique_id'])

def map_to_killchain(ttps: List[Dict]) -> Dict:
    """映射到Kill Chain阶段"""
    killchain = {
        '侦察': [],
        '武器化': [],
        '投递': [],
        '利用': [],
        '安装': [],
        '执行': [],
        '命令控制': [],
        '目标达成': [],
    }

    mapping = {
        'T1566': '投递', 'T1190': '利用', 'T1078': '利用',
        'T1059': '执行', 'T1204': '投递',
        'T1053': '安装', 'T1547': '安装', 'T1133': '命令控制',
        'T1562': '安装', 'T1574': '安装',
        'T1071': '命令控制', 'T1573': '命令控制', 'T1105': '安装',
        'T1003': '目标达成', 'T1110': '侦察',
        'T1041': '目标达成', 'T1048': '目标达成', 'T1486': '目标达成',
        'T1021': '命令控制', 'T1036': '安装',
        'T1087': '侦察', 'T1046': '侦察', 'T1083': '侦察',
        'T1505': '安装', 'T1195': '投递',
        'T1498': '目标达成',
    }

    for ttp in ttps:
        tech_id = ttp['technique_id']
        base_id = tech_id.split('.')[0]
        phase = mapping.get(base_id, '利用')
        killchain[phase].append(ttp)

    return killchain

def generate_sigma_rule(ttp: Dict, context: str = '') -> str:
    """生成Sigma检测规则"""
    return f"""title: 检测 {ttp['name']} ({ttp['technique_id']})
status: experimental
description: |
    检测可能的{ttp['name']}行为
    匹配关键词: {ttp['matched_keyword']}
references:
    - https://attack.mitre.org/techniques/{ttp['technique_id'].replace('.', '/')}/
tags:
    - attack.{ttp['technique_id'].split('.')[0].lower()}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '{ttp['matched_keyword']}'
    condition: selection
falsepositives:
    - 正常管理活动
level: high
"""

def main():
    parser = argparse.ArgumentParser(description='TTP提取工具')
    parser.add_argument('-f', '--file', help='输入文件（威胁报告/日志）')
    parser.add_argument('-t', '--text', help='直接输入文本')
    parser.add_argument('--sigma', action='store_true', help='生成Sigma规则')
    parser.add_argument('--killchain', action='store_true', help='映射到Kill Chain')
    parser.add_argument('--json', action='store_true', help='JSON输出')
    args = parser.parse_args()

    content = ''
    if args.file:
        content = Path(args.file).read_text(errors='ignore')
    elif args.text:
        content = args.text
    else:
        parser.print_help()
        sys.exit(1)

    ttps = extract_ttps(content)
    result = {
        'ttp_count': len(ttps),
        'ttps': ttps,
        'timestamp': datetime.now().isoformat(),
    }

    if args.killchain:
        result['killchain'] = map_to_killchain(ttps)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"{'='*60}")
        print(f"🎯 TTP提取分析")
        print(f"{'='*60}")
        print(f"发现 {len(ttps)} 个ATT&CK技术:\n")

        for ttp in ttps:
            conf = '🟢' if ttp['confidence'] == 'high' else '🟡'
            print(f"  {conf} [{ttp['technique_id']}] {ttp['name']}")
            print(f"     匹配: {ttp['matched_keyword']}")

        if args.killchain and 'killchain' in result:
            print(f"\n🔗 Kill Chain 映射:")
            for phase, techs in result['killchain'].items():
                if techs:
                    print(f"\n  [{phase}]")
                    for t in techs:
                        print(f"    → {t['technique_id']} {t['name']}")

        if args.sigma and ttps:
            print(f"\n📝 Sigma检测规则:")
            print(generate_sigma_rule(ttps[0]))

    return result

if __name__ == '__main__':
    main()
