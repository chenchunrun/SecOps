#!/usr/bin/env python3
"""
Sigma 规则生成器
从提取的 ATT&CK 技术自动生成 Sigma 检测规则

使用方法:
    python scripts/sigma_generator.py --technique T1059.001
    python scripts/sigma_generator.py --techniques T1566.001,T1059.001 --output rules/
"""

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, date
from typing import Dict, List, Optional


# ATT&CK 技术到 Sigma 检测的映射库
TECHNIQUE_SIGMA_MAP = {
    "T1059.001": {
        "title": "PowerShell Suspicious Execution",
        "description": "Detects suspicious PowerShell execution patterns",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_fields": {
            "EventID": 1,
            "Image|endswith": "\\powershell.exe",
            "CommandLine|contains": ["-enc", "-encodedcommand", "-exec bypass", "DownloadString", "IEX("]
        },
        "falsepositives": ["Administrative scripts", " legitimate automation"],
        "level": "high",
        "tags": ["attack.execution", "attack.t1059.001", "attack.defense_evasion", "attack.t1027"]
    },
    "T1059.003": {
        "title": "Suspicious Command Shell Execution",
        "description": "Detects suspicious cmd.exe execution from Office apps",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_fields": {
            "EventID": 1,
            "ParentImage|endswith": ["\\winword.exe", "\\excel.exe", "\\outlook.exe", "\\powerpnt.exe"],
            "Image|endswith": "\\cmd.exe"
        },
        "falsepositives": ["Complex Office macros"],
        "level": "critical",
        "tags": ["attack.execution", "attack.t1059.003", "attack.initial_access", "attack.t1566.001"]
    },
    "T1003.001": {
        "title": "LSASS Memory Access - Credential Dumping",
        "description": "Detects processes accessing LSASS memory, consistent with credential dumping",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_fields": {
            "EventID": 10,
            "TargetImage|endswith": "\\lsass.exe",
            "GrantedAccess|contains": ["0x1410", "0x1010", "0x143a"]
        },
        "falsepositives": ["Antivirus scanning", "Credential management tools"],
        "level": "critical",
        "tags": ["attack.credential_access", "attack.t1003.001"]
    },
    "T1566.001": {
        "title": "Suspicious Office Macro Execution",
        "description": "Detects Office applications spawning suspicious child processes",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_fields": {
            "EventID": 1,
            "ParentImage|endswith": ["\\winword.exe", "\\excel.exe"],
            "Image|endswith": ["\\powershell.exe", "\\cmd.exe", "\\wscript.exe", "\\mshta.exe"]
        },
        "falsepositives": ["Complex legitimate Office automation"],
        "level": "critical",
        "tags": ["attack.initial_access", "attack.t1566.001", "attack.execution"]
    },
    "T1071.001": {
        "title": "Suspicious Network Connection to Known C2 Infrastructure",
        "description": "Detects network connections consistent with C2 beaconing patterns",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_fields": {
            "EventID": 3,
            "DestinationPort": [443, 8443, 8080, 4444],
            "Image|endswith": ["\\powershell.exe", "\\cmd.exe", "\\rundll32.exe"]
        },
        "falsepositives": ["Legitimate HTTPS traffic"],
        "level": "medium",
        "tags": ["attack.command_and_control", "attack.t1071.001"]
    },
    "T1053.005": {
        "title": "Scheduled Task Creation via schtasks",
        "description": "Detects scheduled task creation, common persistence mechanism",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_fields": {
            "EventID": 1,
            "Image|endswith": "\\schtasks.exe",
            "CommandLine|contains": ["/create", "/sc"]
        },
        "falsepositives": [" legitimate scheduled tasks"],
        "level": "medium",
        "tags": ["attack.persistence", "attack.t1053.005", "attack.privilege_escalation"]
    },
    "T1218.010": {
        "title": "Suspicious Regsvr32 Execution (Squiblydoo)",
        "description": "Detects regsvr32 with suspicious parameters",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_fields": {
            "EventID": 1,
            "Image|endswith": "\\regsvr32.exe",
            "CommandLine|contains": ["/s", "/u", "scrobj.dll"]
        },
        "falsepositives": [" legitimate DLL registration"],
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1218.010"]
    },
    "T1027": {
        "title": "Obfuscated Code Execution",
        "description": "Detects execution of obfuscated/encoded scripts",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_fields": {
            "EventID": 1,
            "CommandLine|contains": ["base64", "-decode", "[System.Convert]::FromBase64String"]
        },
        "falsepositives": ["Legitimate encoded scripts"],
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1027"]
    },
}


def generate_sigma_rule(technique_id: str, custom_fields: Optional[Dict] = None) -> Dict:
    """为指定 ATT&CK 技术生成 Sigma 规则"""
    if technique_id not in TECHNIQUE_SIGMA_MAP:
        return {
            "error": f"未找到技术 {technique_id} 的 Sigma 模板",
            "available": list(TECHNIQUE_SIGMA_MAP.keys())
        }

    template = TECHNIQUE_SIGMA_MAP[technique_id]
    today = date.today().isoformat()

    rule = {
        "title": template["title"],
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": template["description"],
        "references": [
            f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
        ],
        "date": today,
        "logsource": template["logsource"],
        "detection": {
            "selection": template["detection_fields"],
            "condition": "selection"
        },
        "falsepositives": template["falsepositives"],
        "level": template["level"],
        "tags": template["tags"]
    }

    if custom_fields:
        rule["detection"]["selection"].update(custom_fields)

    return rule


def sigma_to_yaml(rule: Dict) -> str:
    """将 Sigma 规则字典转为 YAML 格式"""
    lines = []
    
    def write_dict(d, indent=0):
        for k, v in d.items():
            prefix = "  " * indent
            if isinstance(v, dict):
                lines.append(f"{prefix}{k}:")
                write_dict(v, indent + 1)
            elif isinstance(v, list):
                lines.append(f"{prefix}{k}:")
                for item in v:
                    lines.append(f"{prefix}  - {item}")
            else:
                lines.append(f"{prefix}{k}: {v}")
    
    write_dict(rule)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description='Sigma 规则生成器')
    parser.add_argument('--technique', '-t', help='单个 ATT&CK 技术 ID (如 T1059.001)')
    parser.add_argument('--techniques', '-T', help='多个技术 ID，逗号分隔')
    parser.add_argument('--output', '-o', help='输出目录')
    parser.add_argument('--json', action='store_true', help='JSON 格式输出')

    args = parser.parse_args()

    techniques = []
    if args.techniques:
        techniques = [t.strip() for t in args.techniques.split(',')]
    elif args.technique:
        techniques = [args.technique]
    else:
        # 列出所有可用模板
        print("可用 ATT&CK 技术模板:")
        for tech_id, info in TECHNIQUE_SIGMA_MAP.items():
            print(f"  {tech_id}: {info['title']}")
        sys.exit(0)

    rules = []
    for tech in techniques:
        rule = generate_sigma_rule(tech)
        if "error" not in rule:
            rules.append(rule)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for rule in rules:
            filename = f"{rule['tags'][-1].replace('.', '_')}.yml"
            filepath = os.path.join(args.output, filename)
            with open(filepath, 'w') as f:
                f.write(sigma_to_yaml(rule))
            print(f"✅ 已生成: {filepath}")
    elif args.json:
        print(json.dumps(rules, ensure_ascii=False, indent=2))
    else:
        for rule in rules:
            print(sigma_to_yaml(rule))
            print("\n---\n")


if __name__ == '__main__':
    main()
