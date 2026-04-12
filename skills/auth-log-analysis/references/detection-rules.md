# 检测规则参考

## 凭据填充检测规则

### 规则 1: 单 IP 多用户

```yaml
name: credential_stuffing_ip_spread
description: 单个 IP 访问多个用户账户
condition:
  - ip_unique_users > 5
  - per_user_attempts <= 3
severity:
  - suspicious_ips >= 5: low
  - suspicious_ips >= 20: medium
  - suspicious_ips >= 50: high
  - per_ip_users >= 10: high
  - per_ip_users >= 50: critical
```

### 规则 2: 批量探测模式

```yaml
name: credential_stuffing_pattern
description: 按顺序遍历用户名的探测行为
condition:
  - single_protocol: true  # 通常只用 HTTP
  - sequential_users: true  # 按字母顺序
  - uniform_interval: true  # 均匀间隔
severity: critical
```

---

## 暴力破解检测规则

### 规则 3: 单次高频登录

```yaml
name: brute_force_single
description: 单次记录中登录次数过高
thresholds:
  warning: 50
  high: 100
  critical: 500
```

### 规则 4: 时间窗口高频

```yaml
name: brute_force_window
description: 时间窗口内累计登录次数过高
windows:
  - period: 1m
    warning: 10
    critical: 50
  - period: 1h
    warning: 100
    critical: 500
  - period: 1d
    warning: 500
    critical: 2000
```

### 规则 5: 失败登录比例

```yaml
name: brute_force_failure_ratio
description: 失败登录比例过高
condition:
  - failure_ratio > 0.8
  - total_attempts > 10
severity:
  - failure_ratio >= 0.9: high
  - failure_ratio >= 0.95: critical
```

---

## 不可能旅行检测规则

### 规则 6: 跨国异常

```yaml
name: impossible_travel_cross_country
description: 短时间内跨国登录
thresholds:
  - same_city: 0h  # 即时
  - same_country: 2h
  - neighbor_countries: 4h
  - cross_continent: 12h
severity:
  - hours_diff < 0.5: critical  # 30分钟内
  - hours_diff < 1: high
  - hours_diff < 2: medium
```

### 规则 7: 速度异常

```yaml
name: impossible_travel_velocity
description: 移动速度超过物理可能
condition:
  - distance_km / hours_diff > 1000  # > 1000 km/h
severity: critical
```

---

## 高风险国家规则

### 规则 8: 黑名单国家

```yaml
name: high_risk_country
description: 来自高风险国家的登录
countries:
  critical:
    - North Korea
    - Iran
  high:
    - Russia
    - Ukraine
    - Belarus
  medium:
    - Uzbekistan
    - Azerbaijan
    - Kazakhstan
```

### 规则 9: 非业务国家

```yaml
name: non_business_country
description: 来自非业务国家的登录
whitelist:
  - China
  - Indonesia
  - Laos
  - Cambodia
  - Vietnam
  - Thailand
  - Myanmar
action: alert_if_not_in_whitelist
```

---

## 用户行为规则

### 规则 10: IP 使用异常

```yaml
name: user_ip_anomaly
description: 用户使用过多不同 IP
thresholds:
  normal: 50  # 正常用户通常 < 50 IP
  warning: 200
  high: 500
  critical: 1000
```

### 规则 11: 访问国家异常

```yaml
name: user_country_anomaly
description: 用户从过多国家登录
thresholds:
  normal: 5
  warning: 8
  high: 12
  critical: 20
```

### 规则 12: 非工作时间登录

```yaml
name: off_hours_login
description: 非工作时间登录
time_ranges:
  night: "00:00-06:00"
  weekend: "Saturday, Sunday"
condition:
  - night AND foreign_ip: high
  - night AND high_risk_country: critical
```

---

## 云服务/VPN 规则

### 规则 13: 云服务 IP

```yaml
name: cloud_service_ip
description: 来自云服务 IP 的登录
ip_patterns:
  microsoft_azure: "40.x.x.x, 52.x.x.x, 20.x.x.x"
  aws: "52.x.x.x, 13.x.x.x, 34.x.x.x"
  google_cloud: "34.x.x.x, 35.x.x.x"
  alibaba_cloud: "47.x.x.x, 120.x.x.x"
  hetzner: "138.201.x.x, 159.69.x.x"
severity: medium
note: 可能是正常邮件客户端，也可能是代理
```

### 规则 14: 已知 VPN 出口

```yaml
name: known_vpn_exit
description: 来自已知 VPN 服务的登录
sources:
  - nordvpn
  - expressvpn
  - protonvpn
severity: medium
action: correlate_with_other_indicators
```

---

## 组合规则

### 规则 15: 账户接管指标

```yaml
name: account_takeover_indicators
description: 账户接管综合判断
conditions:
  - impossible_travel: +30
  - new_country: +20
  - new_device: +15
  - password_change: +25
  - forwarding_rule_created: +40
  - off_hours: +10
thresholds:
  warning: 30
  high: 50
  critical: 70
```

### 规则 16: 凭据泄露后使用

```yaml
name: credential_leak_usage
description: 疑似使用泄露凭据
conditions:
  - multiple_ips_same_time: +40
  - geographic_spread: +30
  - protocol_unusual: +20
  - after_breach_disclosure: +50
```

---

## 告警响应

| 严重程度 | 响应时间 | 处置措施 |
|---------|---------|---------|
| Critical | 1小时 | 立即封禁 IP，强制密码重置，通知用户 |
| High | 4小时 | 封禁 IP，联系用户确认 |
| Medium | 24小时 | 监控，收集更多信息 |
| Low | 72小时 | 记录，纳入趋势分析 |

---

## 误报排除

### 白名单条件

```yaml
exclusions:
  # 公司代理出口
  - ip_in: "220.197.30.0/24"

  # 移动办公用户（需确认）
  - user_in: ["sales_team", "executives"]
    country_in: ["China", "Indonesia", "Laos"]

  # Microsoft 365 同步
  - ip_pattern: "40.99.x.x"
    protocol: "IMAP"
    user_agent_contains: "Outlook"
```
