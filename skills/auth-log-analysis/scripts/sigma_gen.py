#!/usr/bin/env python3
"""
Sigma 规则生成器 — 为认证日志威胁生成 Sigma 检测规则
支持将检测规则导出为 Sigma YAML 格式，可导入 Splunk、Elastic Security、Microsoft Sentinel 等 SIEM。

用法: python3 sigma_gen.py [选项]

示例:
  python3 sigma_gen.py --type credential-stuffing
  python3 sigma_gen.py --type brute-force --window 1h --threshold 100
  python3 sigma_gen.py --type impossible-travel --hours 2
  python3 sigma_gen.py --type all --output ./sigma_rules/
"""

import sys
import argparse
from datetime import datetime, timezone


# Sigma 规则模板
SIGMA_TEMPLATES = {
    'credential_stuffing': {
        'title': 'Authentication: Credential Stuffing Detection',
        'id': 'a1b2c3d4-0001-4000-8000-{threshold:04x}{rand:08x}',
        'status': 'experimental',
        'description': 'Detects credential stuffing attacks — single IP accessing multiple user accounts',
        'author': 'sec-skills auth-log-analysis',
        'date': '2026/06/15',
        'references': [
            'https://attack.mitre.org/techniques/T1110/004/',
            'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
        ],
        'tags': ['attack.credential_access', 'attack.t1110.004', 'attack.t1110.003'],
        'logsource': {
            'product': 'os',
            'service': 'authentication',
        },
    },
    'brute_force': {
        'title': 'Authentication: Brute Force Attack Detection',
        'id': 'a1b2c3d4-0002-4000-8000-{threshold:04x}{rand:08x}',
        'status': 'experimental',
        'description': 'Detects brute force attacks — high frequency authentication attempts from single source',
        'author': 'sec-skills auth-log-analysis',
        'date': '2026/06/15',
        'references': [
            'https://attack.mitre.org/techniques/T1110/001/',
            'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
        ],
        'tags': ['attack.credential_access', 'attack.t1110.001'],
        'logsource': {
            'product': 'os',
            'service': 'authentication',
        },
    },
    'impossible_travel': {
        'title': 'Authentication: Impossible Travel Detection',
        'id': 'a1b2c3d4-0003-4000-8000-{hours:04x}{rand:08x}',
        'status': 'experimental',
        'description': 'Detects impossible travel — logins from geographically distant locations in short time',
        'author': 'sec-skills auth-log-analysis',
        'date': '2026/06/15',
        'references': [
            'https://attack.mitre.org/techniques/T1078/',
            'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
        ],
        'tags': ['attack.defense_evasion', 'attack.persistence', 'attack.t1078'],
        'logsource': {
            'product': 'os',
            'service': 'authentication',
        },
    },
    'high_risk_country': {
        'title': 'Authentication: High Risk Country Login',
        'id': 'a1b2c3d4-0004-4000-8000-0000{rand:08x}',
        'status': 'experimental',
        'description': 'Detects authentication attempts from high-risk countries',
        'author': 'sec-skills auth-log-analysis',
        'date': '2026/06/15',
        'references': [
            'https://attack.mitre.org/techniques/T1078/004/',
        ],
        'tags': ['attack.defense_evasion', 'attack.t1078.004'],
        'logsource': {
            'product': 'os',
            'service': 'authentication',
        },
    },
    'off_hours': {
        'title': 'Authentication: Off-Hours Foreign Login',
        'id': 'a1b2c3d4-0005-4000-8000-0000{rand:08x}',
        'status': 'experimental',
        'description': 'Detects late-night authentication from foreign IPs',
        'author': 'sec-skills auth-log-analysis',
        'date': '2026/06/15',
        'references': [
            'https://attack.mitre.org/techniques/T1078/',
        ],
        'tags': ['attack.defense_evasion', 'attack.t1078'],
        'logsource': {
            'product': 'os',
            'service': 'authentication',
        },
    },
}


def generate_credential_stuffing_rule(threshold: int = 5) -> str:
    """生成凭据填充 Sigma 规则"""
    template = SIGMA_TEMPLATES['credential_stuffing']
    rule_id = f"a1b2c3d4-0001-4000-8000-{threshold:04x}{int(datetime.now().timestamp()):08x}"

    return f"""title: {template['title']}
id: {rule_id}
status: {template['status']}
description: '{template['description']} (threshold: {threshold} users per IP)'
author: {template['author']}
date: {template['date']}
references:
  - {template['references'][0]}
  - {template['references'][1]}
tags:
  - {template['tags'][0]}
  - {template['tags'][1]}
  - {template['tags'][2]}
logsource:
  product: {template['logsource']['product']}
  service: {template['logsource']['service']}
detection:
  selection:
    event_type: authentication
  timeframe: 1h
  condition: selection | count(user) by source_ip > {threshold}
  # Aggregated detection: single IP accessing more than {threshold} unique users in 1 hour
falsepositives:
  - Corporate proxy or NAT gateway with many users behind single IP
  - Mail synchronization services (e.g., Exchange Online)
  - VPN gateway with shared egress IP
level: high
---
# Sigma Rule for Credential Stuffing (ATT&CK T1110.004)
# Threshold: single source IP > {threshold} unique users within 1 hour
# ATT&CK: Credential Access → Brute Force: Credential Stuffing
# OWASP: A07:2021 – Identification and Authentication Failures
"""


def generate_brute_force_rule(window: str = '1h', threshold: int = 100) -> str:
    """生成暴力破解 Sigma 规则"""
    template = SIGMA_TEMPLATES['brute_force']
    rule_id = f"a1b2c3d4-0002-4000-8000-{threshold:04x}{int(datetime.now().timestamp()):08x}"

    return f"""title: {template['title']}
id: {rule_id}
status: {template['status']}
description: '{template['description']} (>{threshold} attempts in {window})'
author: {template['author']}
date: {template['date']}
references:
  - {template['references'][0]}
  - {template['references'][1]}
tags:
  - {template['tags'][0]}
  - {template['tags'][1]}
logsource:
  product: {template['logsource']['product']}
  service: {template['logsource']['service']}
detection:
  selection:
    event_type: authentication
    action: login_failed
  timeframe: {window}
  condition: selection | count() by (user, source_ip) > {threshold}
  # Aggregated detection: more than {threshold} failed attempts per user per IP in {window}
falsepositives:
  - Misconfigured application with retry loop
  - Legacy system with stale credentials
  - Scheduled task with expired password
level: high
---
# Sigma Rule for Brute Force (ATT&CK T1110.001)
# Threshold: >{threshold} failed attempts per (user, IP) within {window}
# ATT&CK: Credential Access → Brute Force: Password Guessing
# OWASP: A07:2021 – Identification and Authentication Failures
"""


def generate_impossible_travel_rule(hours: float = 2.0) -> str:
    """生成不可能旅行 Sigma 规则"""
    template = SIGMA_TEMPLATES['impossible_travel']
    rule_id = f"a1b2c3d4-0003-4000-8000-{int(hours*10):04x}{int(datetime.now().timestamp()):08x}"

    return f"""title: {template['title']}
id: {rule_id}
status: {template['status']}
description: '{template['description']} (<{hours}h between different countries)'
author: {template['author']}
date: {template['date']}
references:
  - {template['references'][0]}
  - {template['references'][1]}
tags:
  - {template['tags'][0]}
  - {template['tags'][1]}
  - {template['tags'][2]}
logsource:
  product: {template['logsource']['product']}
  service: {template['logsource']['service']}
detection:
  # Note: This rule requires geographic correlation and is best implemented
  # in SIEM with geoip enrichment (Elastic Maps, Splunk GeoIP, etc.)
  selection:
    event_type: authentication
    action: login_success
  condition: selection
  # Implementation note:
  # 1. Enrich logs with GeoIP (source country)
  # 2. For each user, compare consecutive successful logins
  # 3. Alert if country changes within {hours} hours
  # Splunk SPL example:
  #   ... | stats first(country) as prev_country first(_time) as prev_time by user
  #   | where time_diff < {hours*3600} AND prev_country != current_country
falsepositives:
  - Legitimate business travel (verify with user)
  - VPN connection from different country than physical location
  - Anycast or CDN IP resolving to unexpected country
level: high
---
# Sigma Rule for Impossible Travel (ATT&CK T1078)
# Threshold: successful login from different country within {hours} hours
# ATT&CK: Defense Evasion → Valid Accounts
# Note: Requires GeoIP enrichment in SIEM pipeline
"""


def generate_high_risk_country_rule() -> str:
    """生成高风险国家 Sigma 规则"""
    template = SIGMA_TEMPLATES['high_risk_country']

    return f"""title: {template['title']}
id: a1b2c3d4-0004-4000-8000-{int(datetime.now().timestamp()):012x}
status: {template['status']}
description: '{template['description']}'
author: {template['author']}
date: {template['date']}
references:
  - {template['references'][0]}
tags:
  - {template['tags'][0]}
  - {template['tags'][1]}
logsource:
  product: {template['logsource']['product']}
  service: {template['logsource']['service']}
detection:
  selection_critical:
    source_country:
      - North Korea
      - Iran
  selection_high:
    source_country:
      - Russia
      - Ukraine
      - Belarus
  condition: selection_critical or selection_high
falsepositives:
  - Legitimate business operations in listed countries
  - GeoIP database errors
  - Satellite uplink with incorrect country mapping
level: high
---
# Sigma Rule for High Risk Country Login (ATT&CK T1078.004)
# Countries: North Korea, Iran (critical); Russia, Ukraine, Belarus (high)
# ATT&CK: Defense Evasion → Valid Accounts: Cloud Accounts
"""


def generate_off_hours_rule() -> str:
    """生成非工作时间 Sigma 规则"""
    template = SIGMA_TEMPLATES['off_hours']

    return f"""title: {template['title']}
id: a1b2c3d4-0005-4000-8000-{int(datetime.now().timestamp()):012x}
status: {template['status']}
description: '{template['description']}'
author: {template['author']}
date: {template['date']}
references:
  - {template['references'][0]}
tags:
  - {template['tags'][0]}
  - {template['tags'][1]}
logsource:
  product: {template['logsource']['product']}
  service: {template['logsource']['service']}
detection:
  selection:
    event_type: authentication
    action: login_success
    HourOfEvent:
      gte: 0
      lte: 5
  filter_local:
    source_country: China
  condition: selection and not filter_local
falsepositives:
  - Night shift workers
  - Automated backup or sync jobs
  - Time zone misconfiguration in log source
level: medium
---
# Sigma Rule for Off-Hours Foreign Login (ATT&CK T1078)
# Detection: successful login between 00:00-06:00 from non-domestic IP
# ATT&CK: Defense Evasion → Valid Accounts
"""


def main():
    parser = argparse.ArgumentParser(
        description='Sigma 规则生成器 — 为认证日志威胁生成 Sigma 检测规则'
    )
    parser.add_argument('--type', '-t',
                        choices=['credential-stuffing', 'brute-force', 'impossible-travel',
                                 'high_risk_country', 'off_hours', 'all'],
                        default='credential-stuffing',
                        help='规则类型（默认: credential-stuffing）')
    parser.add_argument('--threshold', type=int, default=5,
                        help='检测阈值（凭据填充: 每IP最大用户数, 暴力破解: 最大尝试次数）')
    parser.add_argument('--window', default='1h',
                        help='时间窗口（暴力破解, 如 1m/1h/1d）')
    parser.add_argument('--hours', type=float, default=2.0,
                        help='不可能旅行时间阈值（小时）')
    parser.add_argument('--output', '-o', help='输出文件或目录（type=all 时为目录）')

    args = parser.parse_args()

    generators = {
        'credential_stuffing': lambda: generate_credential_stuffing_rule(args.threshold),
        'brute_force': lambda: generate_brute_force_rule(args.window, args.threshold),
        'impossible_travel': lambda: generate_impossible_travel_rule(args.hours),
        'high_risk_country': generate_high_risk_country_rule,
        'off_hours': generate_off_hours_rule,
    }

    if args.type == 'all':
        if args.output:
            from pathlib import Path
            outdir = Path(args.output)
            outdir.mkdir(parents=True, exist_ok=True)
            for rule_type, gen_func in generators.items():
                rule_content = gen_func()
                filename = f"auth_{rule_type}.yml"
                filepath = outdir / filename
                filepath.write_text(rule_content, encoding='utf-8')
                print(f"✅ {filename}")
            print(f"\n生成 {len(generators)} 个 Sigma 规则到 {args.output}/")
        else:
            for rule_type, gen_func in generators.items():
                rule_content = gen_func()
                print(rule_content)
                print("---")
            print(f"\n生成 {len(generators)} 个 Sigma 规则")
    else:
        rule_type = args.type.replace('-', '_')
        rule_content = generators[rule_type]()

        if args.output:
            Path(args.output).write_text(rule_content, encoding='utf-8')
            print(f"Sigma 规则已保存到 {args.output}")
        else:
            print(rule_content)


if __name__ == '__main__':
    main()
