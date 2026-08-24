#!/usr/bin/env python3
"""
认证日志快速分诊工具
从认证日志中快速筛选 Critical/High 级别事件，适合批量日志扫描和首次响应。

用法: python3 triage.py [选项] <csv_file>
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

try:
    import pandas as pd
except ImportError:
    print("错误: 需要 pandas 库。请运行: pip install pandas", file=sys.stderr)
    sys.exit(1)


# 默认列名映射
DEFAULT_COLUMNS = {
    'time': '时间',
    'user': '用户名',
    'ip': '源IP地址',
    'location': '地理位置',
    'protocol': '协议',
    'count': '次数',
    'abnormal': '是否异常',
}

# 高风险国家
HIGH_RISK_COUNTRIES = {'Russia', 'Ukraine', 'North Korea', 'Iran', 'Belarus'}

# 分诊阈值 — 只输出 High/Critical
TRIAGE_THRESHOLDS = {
    'credential_stuffing_users': 10,      # 单 IP >= 10 用户 = High+
    'brute_force_count': 100,             # 单记录 >= 100 次 = High+
    'impossible_travel_hours': 1.0,       # < 1 小时跨国 = High+
    'high_risk_country_attempts': 5,      # 高风险国家 >= 5 条 = High+
    'night_foreign': True,                # 深夜 + 国外 = High
}

SEVERITY_EMOJI = {
    'critical': '🔴',
    'high': '🟠',
    'medium': '🟡',
    'low': '🔵',
}


def load_data(filepath: str, columns: dict = None) -> pd.DataFrame:
    """加载并预处理数据"""
    if columns is None:
        columns = DEFAULT_COLUMNS

    df = pd.read_csv(filepath, encoding='utf-8-sig')

    rename_map = {}
    for key, default in DEFAULT_COLUMNS.items():
        col = columns.get(key, default)
        if col in df.columns and col != key:
            rename_map[col] = key

    if rename_map:
        df = df.rename(columns=rename_map)

    time_col = 'time' if 'time' in df.columns else columns.get('time', '时间')
    if time_col in df.columns:
        df['time'] = pd.to_datetime(df[time_col], errors='coerce')

    return df


def triage_credential_stuffing(df: pd.DataFrame) -> list:
    """分诊凭据填充 — 只返回 High+"""
    ip_col = 'ip' if 'ip' in df.columns else '源IP地址'
    user_col = 'user' if 'user' in df.columns else '用户名'
    threshold = TRIAGE_THRESHOLDS['credential_stuffing_users']

    ip_users = df.groupby(ip_col)[user_col].nunique()
    critical_ips = ip_users[ip_users >= threshold * 2]
    high_ips = ip_users[(ip_users >= threshold) & (ip_users < threshold * 2)]

    events = []
    for ip, count in critical_ips.items():
        events.append({
            'severity': 'critical',
            'type': 'credential_stuffing',
            'ip': ip,
            'detail': f'单 IP 访问 {count} 个用户（>= {threshold*2}）',
            'attck': 'T1110.004',
        })
    for ip, count in high_ips.items():
        events.append({
            'severity': 'high',
            'type': 'credential_stuffing',
            'ip': ip,
            'detail': f'单 IP 访问 {count} 个用户（>= {threshold}）',
            'attck': 'T1110.003',
        })
    return events


def triage_brute_force(df: pd.DataFrame) -> list:
    """分诊暴力破解 — 只返回 High+"""
    count_col = 'count' if 'count' in df.columns else '次数'
    user_col = 'user' if 'user' in df.columns else '用户名'
    ip_col = 'ip' if 'ip' in df.columns else '源IP地址'
    threshold = TRIAGE_THRESHOLDS['brute_force_count']

    if count_col not in df.columns:
        return []

    critical = df[df[count_col] >= threshold * 5]
    high = df[(df[count_col] >= threshold) & (df[count_col] < threshold * 5)]

    events = []
    for _, row in critical.iterrows():
        events.append({
            'severity': 'critical',
            'type': 'brute_force',
            'user': row.get(user_col, ''),
            'ip': row.get(ip_col, ''),
            'detail': f'单记录 {int(row[count_col])} 次尝试（>= {threshold*5}）',
            'attck': 'T1110.001',
        })
    for _, row in high.iterrows():
        events.append({
            'severity': 'high',
            'type': 'brute_force',
            'user': row.get(user_col, ''),
            'ip': row.get(ip_col, ''),
            'detail': f'单记录 {int(row[count_col])} 次尝试（>= {threshold}）',
            'attck': 'T1110.001',
        })
    return events


def triage_impossible_travel(df: pd.DataFrame) -> list:
    """分诊不可能旅行 — 只返回 High+"""
    user_col = 'user' if 'user' in df.columns else '用户名'
    location_col = 'location' if 'location' in df.columns else '地理位置'
    ip_col = 'ip' if 'ip' in df.columns else '源IP地址'
    hours_threshold = TRIAGE_THRESHOLDS['impossible_travel_hours']

    if 'time' not in df.columns:
        return []

    df_sorted = df.sort_values([user_col, 'time'])
    events = []

    for user, group in df_sorted.groupby(user_col):
        records = group.to_dict('records')
        for i in range(1, len(records)):
            prev, curr = records[i-1], records[i]
            prev_loc = str(prev.get(location_col, ''))
            curr_loc = str(curr.get(location_col, ''))

            if 'Priv' in prev_loc or 'Priv' in curr_loc:
                continue

            prev_country = prev_loc.split(',')[-1].strip() if ',' in prev_loc else prev_loc
            curr_country = curr_loc.split(',')[-1].strip() if ',' in curr_loc else curr_loc

            if prev_country != curr_country:
                time_diff = (curr['time'] - prev['time']).total_seconds() / 3600
                if 0 < time_diff < hours_threshold:
                    severity = 'critical' if time_diff < 0.5 else 'high'
                    events.append({
                        'severity': severity,
                        'type': 'impossible_travel',
                        'user': user,
                        'detail': f'{prev_country} → {curr_country} in {time_diff:.1f}h',
                        'attck': 'T1078',
                        'first_ip': prev.get(ip_col, ''),
                        'second_ip': curr.get(ip_col, ''),
                    })
    return events


def triage_high_risk_countries(df: pd.DataFrame) -> list:
    """分诊高风险国家登录"""
    location_col = 'location' if 'location' in df.columns else '地理位置'
    count_col = 'count' if 'count' in df.columns else '次数'

    df = df.copy()
    df['country'] = df[location_col].apply(
        lambda x: x.split(',')[-1].strip() if ',' in str(x) else str(x)
    )

    events = []
    for country in HIGH_RISK_COUNTRIES:
        country_data = df[df['country'] == country]
        if len(country_data) >= TRIAGE_THRESHOLDS['high_risk_country_attempts']:
            severity = 'critical' if country in ('North Korea', 'Iran') else 'high'
            total = country_data[count_col].sum() if count_col in df.columns else len(country_data)
            events.append({
                'severity': severity,
                'type': 'high_risk_country',
                'country': country,
                'detail': f'{country}: {len(country_data)} 条登录, {int(total)} 次尝试',
                'attck': 'T1078.004',
            })
    return events


def triage_off_hours(df: pd.DataFrame) -> list:
    """分诊非工作时间 + 国外登录"""
    user_col = 'user' if 'user' in df.columns else '用户名'
    location_col = 'location' if 'location' in df.columns else '地理位置'

    if 'time' not in df.columns:
        return []

    df = df.copy()
    df['hour'] = df['time'].dt.hour
    night = df[(df['hour'] >= 0) & (df['hour'] <= 5)]
    night_foreign = night[~night[location_col].str.contains('China|Priv|中国', na=False)]

    events = []
    for _, row in night_foreign.head(50).iterrows():
        events.append({
            'severity': 'high',
            'type': 'off_hours_foreign',
            'user': row.get(user_col, ''),
            'detail': f'深夜({row["hour"]}点) 国外登录: {row.get(location_col, "")}',
            'attck': 'T1078',
        })
    return events


def run_triage(filepath: str, columns: dict = None, min_severity: str = 'high') -> dict:
    """执行分诊"""
    df = load_data(filepath, columns)

    all_events = []
    all_events.extend(triage_credential_stuffing(df))
    all_events.extend(triage_brute_force(df))
    all_events.extend(triage_impossible_travel(df))
    all_events.extend(triage_high_risk_countries(df))
    all_events.extend(triage_off_hours(df))

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    min_idx = severity_order.get(min_severity, 1)
    filtered = [e for e in all_events if severity_order.get(e['severity'], 3) <= min_idx]
    filtered.sort(key=lambda x: (severity_order.get(x['severity'], 3), x.get('type', '')))

    return {
        'file': filepath,
        'triage_time': datetime.now().isoformat(),
        'total_events': len(filtered),
        'critical_count': sum(1 for e in filtered if e['severity'] == 'critical'),
        'high_count': sum(1 for e in filtered if e['severity'] == 'high'),
        'events': filtered,
    }


def print_triage(result: dict):
    """打印分诊结果"""
    print("=" * 60)
    print("🚨 认证日志快速分诊报告")
    print("=" * 60)
    print(f"文件: {result['file']}")
    print(f"分诊时间: {result['triage_time']}")
    print(f"高危事件: {result['critical_count']} Critical + {result['high_count']} High = {result['total_events']} 总计")
    print()

    if result['total_events'] == 0:
        print("✅ 未发现 High/Critical 级别事件")
        print("=" * 60)
        return

    current_sev = None
    for event in result['events']:
        if event['severity'] != current_sev:
            current_sev = event['severity']
            emoji = SEVERITY_EMOJI.get(current_sev, '❓')
            print(f"\n{emoji} {current_sev.upper()}")

        detail = event.get('detail', '')
        attck = event.get('attck', '')
        ip = event.get('ip', event.get('first_ip', ''))
        user = event.get('user', '')

        parts = []
        if ip:
            parts.append(f"IP={ip}")
        if user:
            parts.append(f"用户={user}")
        parts.append(detail)
        if attck:
            parts.append(f"[{attck}]")

        print(f"  [{event['type']}] {' | '.join(parts)}")

    print("\n" + "=" * 60)
    print("建议: 对 Critical 事件立即响应，对 High 事件 4 小时内处理")


def main():
    parser = argparse.ArgumentParser(description='认证日志快速分诊工具')
    parser.add_argument('file', help='CSV 认证日志文件')
    parser.add_argument('-j', '--json', action='store_true', help='输出 JSON 格式')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'],
                        default='high', help='最低输出严重级别（默认: high）')
    parser.add_argument('--time-col', help='时间列名')
    parser.add_argument('--user-col', help='用户列名')
    parser.add_argument('--ip-col', help='IP 列名')
    parser.add_argument('--location-col', help='地理位置列名')

    args = parser.parse_args()

    columns = DEFAULT_COLUMNS.copy()
    if args.time_col:
        columns['time'] = args.time_col
    if args.user_col:
        columns['user'] = args.user_col
    if args.ip_col:
        columns['ip'] = args.ip_col
    if args.location_col:
        columns['location'] = args.location_col

    result = run_triage(args.file, columns, args.severity)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_triage(result)


if __name__ == '__main__':
    main()
