#!/usr/bin/env python3
"""
认证日志威胁分析工具
用法: python3 auth_log_analyze.py [选项] <csv_file>
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict

try:
    import pandas as pd
except ImportError:
    print("错误: 需要 pandas 库。请运行: pip install pandas")
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

# 云服务 IP 模式
CLOUD_IP_PATTERNS = [
    r'^40\.',   # Microsoft Azure
    r'^52\.',   # AWS
    r'^34\.',   # Google Cloud
    r'^13\.',   # AWS
    r'^20\.',   # Microsoft
]


def load_data(filepath: str, columns: Dict[str, str]) -> pd.DataFrame:
    """加载并预处理数据"""
    df = pd.read_csv(filepath, encoding='utf-8-sig')

    # 重命名列
    rename_map = {}
    for key, default in DEFAULT_COLUMNS.items():
        col = columns.get(key, default)
        if col in df.columns and col != key:
            rename_map[col] = key

    if rename_map:
        df = df.rename(columns=rename_map)

    # 转换时间列
    time_col = 'time' if 'time' in df.columns else columns.get('time', '时间')
    if time_col in df.columns:
        df['time'] = pd.to_datetime(df[time_col])

    return df


def get_overview(df: pd.DataFrame) -> Dict[str, Any]:
    """获取数据概览"""
    time_col = 'time' if 'time' in df.columns else df.columns[1]
    user_col = 'user' if 'user' in df.columns else df.columns[2]
    ip_col = 'ip' if 'ip' in df.columns else df.columns[5]

    return {
        'total_records': len(df),
        'time_range': {
            'start': str(df[time_col].min()) if time_col in df.columns else None,
            'end': str(df[time_col].max()) if time_col in df.columns else None,
        },
        'unique_users': df[user_col].nunique() if user_col in df.columns else 0,
        'unique_ips': df[ip_col].nunique() if ip_col in df.columns else 0,
    }


def detect_credential_stuffing(df: pd.DataFrame, threshold: int = 5) -> Dict[str, Any]:
    """检测凭据填充攻击"""
    ip_col = 'ip' if 'ip' in df.columns else '源IP地址'
    user_col = 'user' if 'user' in df.columns else '用户名'
    count_col = 'count' if 'count' in df.columns else '次数'

    # 统计每个 IP 访问的用户数
    ip_users = df.groupby(ip_col)[user_col].nunique().sort_values(ascending=False)
    suspicious = ip_users[ip_users > threshold]

    results = []
    for ip, user_count in suspicious.head(50).items():
        ip_data = df[df[ip_col] == ip]
        total_attempts = ip_data[count_col].sum() if count_col in df.columns else len(ip_data)
        users = ip_data[user_col].unique().tolist()[:20]

        results.append({
            'ip': ip,
            'user_count': int(user_count),
            'total_attempts': int(total_attempts),
            'users': users,
            'time_range': {
                'start': str(ip_data['time'].min()) if 'time' in df.columns else None,
                'end': str(ip_data['time'].max()) if 'time' in df.columns else None,
            }
        })

    return {
        'suspicious_ips': len(suspicious),
        'details': results,
    }


def detect_brute_force(df: pd.DataFrame, threshold: int = 50) -> Dict[str, Any]:
    """检测暴力破解"""
    count_col = 'count' if 'count' in df.columns else '次数'
    user_col = 'user' if 'user' in df.columns else '用户名'
    ip_col = 'ip' if 'ip' in df.columns else '源IP地址'

    if count_col not in df.columns:
        return {'error': '无次数列，无法检测暴力破解'}

    # 单次高频
    high_freq = df[df[count_col] > threshold].sort_values(count_col, ascending=False)

    results = []
    for _, row in high_freq.head(30).iterrows():
        results.append({
            'time': str(row.get('time', row.get('时间', ''))),
            'user': row.get(user_col, ''),
            'ip': row.get(ip_col, ''),
            'count': int(row[count_col]),
            'location': row.get('location', row.get('地理位置', '')),
        })

    return {
        'high_frequency_records': len(high_freq),
        'details': results,
    }


def detect_impossible_travel(df: pd.DataFrame, hours_threshold: float = 2.0) -> Dict[str, Any]:
    """检测不可能旅行"""
    user_col = 'user' if 'user' in df.columns else '用户名'
    location_col = 'location' if 'location' in df.columns else '地理位置'
    ip_col = 'ip' if 'ip' in df.columns else '源IP地址'

    if 'time' not in df.columns:
        return {'error': '无时间列，无法检测不可能旅行'}

    df_sorted = df.sort_values([user_col, 'time'])
    impossible = []

    for user, group in df_sorted.groupby(user_col):
        records = group.to_dict('records')
        for i in range(1, len(records)):
            prev, curr = records[i-1], records[i]

            prev_loc = str(prev.get(location_col, ''))
            curr_loc = str(curr.get(location_col, ''))

            # 跳过私有 IP
            if 'Priv' in prev_loc or 'Priv' in curr_loc:
                continue

            # 提取国家
            prev_country = prev_loc.split(',')[-1].strip() if ',' in prev_loc else prev_loc
            curr_country = curr_loc.split(',')[-1].strip() if ',' in curr_loc else curr_loc

            if not prev_country or not curr_country:
                continue

            # 不同国家
            if prev_country != curr_country:
                time_diff = (curr['time'] - prev['time']).total_seconds() / 3600

                if 0 < time_diff < hours_threshold:
                    impossible.append({
                        'user': user,
                        'first_time': str(prev['time']),
                        'first_location': prev_loc,
                        'first_ip': prev.get(ip_col, ''),
                        'second_time': str(curr['time']),
                        'second_location': curr_loc,
                        'second_ip': curr.get(ip_col, ''),
                        'hours_diff': round(time_diff, 2),
                    })

    # 统计受影响用户
    user_counts = defaultdict(int)
    for item in impossible:
        user_counts[item['user']] += 1

    top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:20]

    return {
        'total_records': len(impossible),
        'affected_users': len(user_counts),
        'top_affected_users': [{'user': u, 'count': c} for u, c in top_users],
        'samples': impossible[:30],
    }


def detect_high_risk_countries(df: pd.DataFrame) -> Dict[str, Any]:
    """检测高风险国家登录"""
    location_col = 'location' if 'location' in df.columns else '地理位置'
    user_col = 'user' if 'user' in df.columns else '用户名'
    ip_col = 'ip' if 'ip' in df.columns else '源IP地址'
    count_col = 'count' if 'count' in df.columns else '次数'

    df['country'] = df[location_col].apply(
        lambda x: x.split(',')[-1].strip() if ',' in str(x) else str(x)
    )

    results = {}
    for country in HIGH_RISK_COUNTRIES:
        country_data = df[df['country'] == country]
        if len(country_data) > 0:
            total_attempts = country_data[count_col].sum() if count_col in df.columns else len(country_data)
            results[country] = {
                'records': len(country_data),
                'attempts': int(total_attempts),
                'users': country_data[user_col].nunique(),
                'ips': country_data[ip_col].nunique(),
                'user_list': country_data[user_col].unique().tolist()[:15],
            }

    return results


def detect_user_anomalies(df: pd.DataFrame) -> Dict[str, Any]:
    """检测用户行为异常"""
    user_col = 'user' if 'user' in df.columns else '用户名'
    ip_col = 'ip' if 'ip' in df.columns else '源IP地址'
    count_col = 'count' if 'count' in df.columns else '次数'
    location_col = 'location' if 'location' in df.columns else '地理位置'

    # IP 使用异常
    user_ips = df.groupby(user_col)[ip_col].nunique().sort_values(ascending=False)
    ip_anomaly = user_ips[user_ips > 500].to_dict()

    # 登录次数异常
    if count_col in df.columns:
        user_attempts = df.groupby(user_col)[count_col].sum().sort_values(ascending=False)
        attempts_top = user_attempts.head(20).to_dict()
    else:
        attempts_top = {}

    # 访问国家数异常
    df['country'] = df[location_col].apply(
        lambda x: x.split(',')[-1].strip() if ',' in str(x) else str(x)
    )
    user_countries = df.groupby(user_col)['country'].nunique().sort_values(ascending=False)
    country_anomaly = user_countries[user_countries > 8].to_dict()

    return {
        'ip_anomaly': {k: int(v) for k, v in ip_anomaly.items()},
        'top_attempts': {k: int(v) for k, v in attempts_top.items()},
        'country_anomaly': {k: int(v) for k, v in country_anomaly.items()},
    }


def detect_off_hours(df: pd.DataFrame) -> Dict[str, Any]:
    """检测非工作时间登录"""
    user_col = 'user' if 'user' in df.columns else '用户名'
    location_col = 'location' if 'location' in df.columns else '地理位置'

    if 'time' not in df.columns:
        return {'error': '无时间列'}

    df['hour'] = df['time'].dt.hour

    # 深夜 (0-5点)
    night = df[df['hour'].isin([0, 1, 2, 3, 4, 5])]

    # 深夜 + 国外
    night_foreign = night[~night[location_col].str.contains('China|Priv|中国', na=False)]

    return {
        'night_logins': len(night),
        'night_foreign_logins': len(night_foreign),
        'night_top_users': night[user_col].value_counts().head(15).to_dict(),
    }


def analyze(filepath: str, columns: Dict[str, str] = None) -> Dict[str, Any]:
    """主分析函数"""
    if columns is None:
        columns = DEFAULT_COLUMNS

    df = load_data(filepath, columns)

    result = {
        'file': filepath,
        'analyze_time': datetime.now().isoformat(),
        'overview': get_overview(df),
        'credential_stuffing': detect_credential_stuffing(df),
        'brute_force': detect_brute_force(df),
        'impossible_travel': detect_impossible_travel(df),
        'high_risk_countries': detect_high_risk_countries(df),
        'user_anomalies': detect_user_anomalies(df),
        'off_hours': detect_off_hours(df),
    }

    # 计算风险摘要
    risks = []

    cs = result['credential_stuffing']
    if cs.get('suspicious_ips', 0) > 0:
        risks.append(f"凭据填充: {cs['suspicious_ips']} 个可疑 IP")

    bf = result['brute_force']
    if bf.get('high_frequency_records', 0) > 0:
        risks.append(f"暴力破解: {bf['high_frequency_records']} 条高频记录")

    it = result['impossible_travel']
    if it.get('total_records', 0) > 0:
        risks.append(f"不可能旅行: {it['total_records']} 条, {it['affected_users']} 用户")

    hrc = result['high_risk_countries']
    if hrc:
        total = sum(v['records'] for v in hrc.values())
        risks.append(f"高风险国家: {total} 条登录")

    result['risk_summary'] = risks

    return result


def print_result(result: Dict[str, Any]):
    """打印分析结果"""
    print("=" * 60)
    print("认证日志威胁分析报告")
    print("=" * 60)

    overview = result['overview']
    print(f"\n文件: {result['file']}")
    print(f"分析时间: {result['analyze_time']}")
    print(f"总记录: {overview['total_records']:,}")
    print(f"唯一用户: {overview['unique_users']}")
    print(f"唯一 IP: {overview['unique_ips']}")

    print("\n--- 风险摘要 ---")
    for risk in result.get('risk_summary', []):
        print(f"  [!] {risk}")

    # 凭据填充
    cs = result['credential_stuffing']
    if cs.get('suspicious_ips', 0) > 0:
        print(f"\n--- 凭据填充检测 ({cs['suspicious_ips']} 个可疑 IP) ---")
        for item in cs['details'][:5]:
            print(f"  {item['ip']}: {item['user_count']} 用户, {item['total_attempts']} 次")

    # 暴力破解
    bf = result['brute_force']
    if bf.get('high_frequency_records', 0) > 0:
        print(f"\n--- 暴力破解检测 ({bf['high_frequency_records']} 条) ---")
        for item in bf['details'][:5]:
            print(f"  {item['user']}: {item['count']} 次 ({item['ip']})")

    # 不可能旅行
    it = result['impossible_travel']
    if it.get('total_records', 0) > 0:
        print(f"\n--- 不可能旅行 ({it['total_records']} 条) ---")
        print("  受影响用户 Top 5:")
        for item in it.get('top_affected_users', [])[:5]:
            print(f"    {item['user']}: {item['count']} 次")

    # 高风险国家
    hrc = result['high_risk_countries']
    if hrc:
        print(f"\n--- 高风险国家登录 ---")
        for country, data in hrc.items():
            print(f"  {country}: {data['records']} 条, {data['users']} 用户")

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(description='认证日志威胁分析')
    parser.add_argument('file', help='CSV 日志文件')
    parser.add_argument('-j', '--json', action='store_true', help='输出 JSON')
    parser.add_argument('-o', '--output', help='输出文件')
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

    result = analyze(args.file, columns)

    if args.json:
        output = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output:
            Path(args.output).write_text(output, encoding='utf-8')
            print(f"已保存: {args.output}")
        else:
            print(output)
    else:
        print_result(result)
        if args.output:
            Path(args.output).write_text(
                json.dumps(result, ensure_ascii=False, indent=2),
                encoding='utf-8'
            )
            print(f"\nJSON 已保存: {args.output}")


if __name__ == '__main__':
    main()
