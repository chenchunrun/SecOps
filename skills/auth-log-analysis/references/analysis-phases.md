# 认证日志分析阶段详解

## 第一阶段：数据概览

### 数据加载与清洗

```python
import pandas as pd

df = pd.read_csv('login.csv', encoding='utf-8-sig')
df['时间'] = pd.to_datetime(df['时间'])

print(f"总记录: {len(df):,}")
print(f"时间范围: {df['时间'].min()} ~ {df['时间'].max()}")
print(f"唯一用户: {df['用户名'].nunique()}")
print(f"唯一 IP: {df['源IP地址'].nunique()}")
```

### 基础统计

```python
# 协议分布
print(df['协议'].value_counts())

# 地理分布 Top 10
print(df['地理位置'].value_counts().head(10))

# 登录次数分布
print(df['次数'].describe())
```

**关注点**:
- 异常协议（如大量 HTTP 而非 IMAP/POP3）
- 非业务国家的登录
- 登录次数的异常峰值

## 第二阶段：凭据填充检测

### 单 IP 多用户分析

```python
# 统计每个 IP 访问的用户数
ip_users = df.groupby('源IP地址')['用户名'].nunique().sort_values(ascending=False)

# 可疑阈值: 单 IP 访问 > 5 用户
suspicious = ip_users[ip_users > 5]
print(f"可疑 IP: {len(suspicious)} 个")
```

**凭据填充特征**:
| 指标 | 正常值 | 可疑值 |
|------|--------|--------|
| 单 IP 用户数 | 1-3 | > 5 |
| 每用户尝试次数 | 正常使用模式 | 1-2 次（遍历尝试） |
| 时间分布 | 分散 | 密集（按顺序遍历） |
| 协议 | 多样 | 单一（通常 HTTP） |

### 确认攻击

```python
for ip in suspicious.head(10).index:
    ip_data = df[df['源IP地址'] == ip]
    print(f"\nIP: {ip}")
    print(f"  用户数: {ip_data['用户名'].nunique()}")
    print(f"  总尝试: {ip_data['次数'].sum()}")
    print(f"  时间范围: {ip_data['时间'].min()} ~ {ip_data['时间'].max()}")
    print(f"  用户列表: {', '.join(ip_data['用户名'].unique()[:10])}")
```

## 第三阶段：暴力破解检测

### 高频登录检测

```python
# 单次记录 > 50 次
brute = df[df['次数'] > 50].sort_values('次数', ascending=False)
print(f"超高频记录: {len(brute)} 条")

# 小时级聚合
df['hour'] = df['时间'].dt.floor('h')
hourly = df.groupby(['用户名', 'hour'])['次数'].sum()
hourly_high = hourly[hourly > 100]
print(f"1小时内 >100 次: {len(hourly_high)} 条")
```

**暴力破解阈值**:
| 时间窗口 | 告警阈值 | 严重阈值 |
|---------|---------|---------|
| 1 分钟 | > 10 次 | > 50 次 |
| 1 小时 | > 100 次 | > 500 次 |
| 1 天 | > 500 次 | > 2000 次 |

### 失败登录分析

如有失败状态字段：
```python
failed = df[df['状态'] == '失败']
failed_by_user = failed.groupby('用户名').size().sort_values(ascending=False)
print("失败登录 Top 20:")
print(failed_by_user.head(20))
```

## 第四阶段：不可能旅行检测

### 地理异常检测

```python
from datetime import timedelta

df_sorted = df.sort_values(['用户名', '时间'])
impossible = []

for user, group in df_sorted.groupby('用户名'):
    records = group.to_dict('records')
    for i in range(1, len(records)):
        prev, curr = records[i-1], records[i]

        # 提取国家
        prev_country = prev['地理位置'].split(',')[-1].strip()
        curr_country = curr['地理位置'].split(',')[-1].strip()

        # 跳过私有 IP
        if 'Priv' in prev_country or 'Priv' in curr_country:
            continue

        # 不同国家且间隔 < 2 小时
        time_diff = (curr['时间'] - prev['时间']).total_seconds() / 3600
        if prev_country != curr_country and 0 < time_diff < 2:
            impossible.append({
                '用户': user,
                '第一次': prev['时间'],
                '位置1': prev['地理位置'],
                '第二次': curr['时间'],
                '位置2': curr['地理位置'],
                '间隔(小时)': round(time_diff, 2)
            })
```

**不可能旅行阈值**:
| 地理跨度 | 最短合理时间 |
|---------|-------------|
| 同城市 | 即时 |
| 同国家不同城市 | 1-3 小时 |
| 邻国 | 2-4 小时 |
| 跨洲 | 8-15 小时 |

### VPN/代理识别

已知云服务 IP 段：
```
40.x.x.x      # Microsoft Azure
52.x.x.x      # AWS
34.x.x.x      # Google Cloud
13.x.x.x      # AWS
20.x.x.x      # Microsoft
```

```python
cloud_pattern = r'^(40\.|52\.|34\.|13\.|20\.)'
cloud_logins = df[df['源IP地址'].str.match(cloud_pattern, na=False)]
print(f"云服务 IP 登录: {len(cloud_logins)} 条")
```

## 第五阶段：高风险国家分析

### 国家分布

```python
df['country'] = df['地理位置'].apply(
    lambda x: x.split(',')[-1].strip() if ',' in str(x) else str(x)
)
print(df['country'].value_counts().head(20))
```

### 非业务国家登录

```python
# 定义业务国家白名单
business_countries = {'China', 'Indonesia', 'Laos', 'Cambodia', 'Vietnam', '中国', '印度尼西亚'}

# 高风险国家
high_risk = {'Russia', 'Ukraine', 'North Korea', 'Iran'}

risk_logins = df[df['country'].isin(high_risk)]
print(f"高风险国家登录: {len(risk_logins)} 条")
for country in high_risk:
    count = len(df[df['country'] == country])
    if count > 0:
        print(f"  {country}: {count} 条")
```

## 第六阶段：用户行为分析

### IP 使用异常

```python
# 用户使用 IP 数量
user_ips = df.groupby('用户名')['源IP地址'].nunique().sort_values(ascending=False)

# 正常: 10-50 个 IP
# 异常: > 500 个 IP
print("IP 使用异常用户:")
print(user_ips[user_ips > 500])
```

### 非工作时间登录

```python
df['hour'] = df['时间'].dt.hour
df['weekday'] = df['时间'].dt.weekday

# 深夜 (0-5点)
night = df[df['hour'].isin([0, 1, 2, 3, 4, 5])]
print(f"深夜登录: {len(night)} 条")

# 深夜 + 国外
night_foreign = night[~night['地理位置'].str.contains('China|Priv', na=False)]
print(f"深夜国外登录: {len(night_foreign)} 条")
```

### 访问国家数异常

```python
user_countries = df.groupby('用户名')['country'].nunique().sort_values(ascending=False)
# 正常: 1-5 个国家
# 异常: > 8 个国家
print("访问国家异常用户:")
print(user_countries[user_countries > 8])
```
