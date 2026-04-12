# 威胁狩猎查询模板

## 动态DNS服务滥用检测

攻击者常用动态DNS服务托管C2，绕过域名封锁。

### 高风险动态DNS服务

| 服务 | 历史关联数 | 常见滥用类型 | 搜索语法 |
|------|-----------|-------------|---------|
| duckdns.org | 862+ | AsyncRAT, RemCos, NjRAT | `domain="duckdns.org"` |
| ydns.eu | 495+ | Xworm, AgentTesla | `domain="ydns.eu"` |
| linkpc.net | 98+ | NjRAT, RemCos | `domain="linkpc.net"` |
| ddns.net | 高 | 多种RAT | `domain="ddns.net"` |
| no-ip.org | 高 | 僵尸网络 | `domain="no-ip.org"` |
| didns.ru | 隐蔽 | RemCos | `domain="didns.ru"` |
| xxbot.co | 隐蔽 | MooBot | `domain="xxbot.co"` |
| cantdown.space | 隐蔽 | Mirai | `domain="cantdown.space"` |

### 查询示例

```bash
# 扫描动态DNS服务基础设施
domain="duckdns.org"
domain="ydns.eu"
domain="linkpc.net"

# 结合端口过滤可疑RAT
domain="duckdns.org" && (port="4444" || port="5555" || port="7777" || port="8888")

# 结合地理位置
domain="duckdns.org" && country="US"
```

## 恶意软件家族C2特征

### Cobalt Strike

```bash
# 默认证书
ssl="6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C"

# 默认端口
port="50050"

# Team Server banner特征
body="HTTP/1.1 404 Not Found" && header="Content-Length: 0"

# Beacon特征
port="443" && ssl.jarm="07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
```

### AsyncRAT

```bash
# 常见端口
port="6606" || port="7707" || port="8808"

# 配合动态DNS
domain="duckdns.org" && port="6606"
```

### Xworm

```bash
# 常见端口
port="7000" || port="7777" || port="8888"

# 配合动态DNS
domain="ydns.eu" && port="7000"
```

### NjRAT

```bash
# 常见端口
port="5552" || port="1177" || port="5555"

# 配合动态DNS
domain="linkpc.net" && port="5552"

# body特征
body="njrat" || body="NjRAT"
```

### RemCos

```bash
# 常见端口
port="2404" || port="2405" || port="4782"

# 配合动态DNS
domain="didns.ru" && port="4782"
```

### Metasploit

```bash
# Meterpreter 常见端口
port="4444" && service="shell"

# Reverse Shell
port="4444" || port="4445" || port="5555"
```

## 僵尸网络基础设施

### Mirai 变种

```bash
# 常见Telnet端口
port="23" || port="2323"

# IRC C2
port="6667" || port="6668" || port="6669"

# 特定banner
banner="Mirai" || body="mirai"
```

### MooBot

```bash
# 扫描特征
port="23" || port="37215" || port="52869"
```

### Gafgyt

```bash
# IRC端口
port="6667" && body="gafgyt"
```

### XorDDoS

```bash
# 常见域名模式
domain="ddos" || domain="botnet"
```

## IOC 关联分析连招

### 连招 1: 单IP展开

```
已知: 恶意IP 1.2.3.4

步骤:
1. ip="1.2.3.4"                    → 获取所有绑定域名、开放端口、证书
2. 提取证书特征 → ssl="证书CN"      → 关联其他IP
3. 提取域名 → domain="xxx.com"     → 获取历史IP、同域名资产
4. 同C段 → 手动构建同网段查询        → 关联基础设施
5. risk_insight 查威胁情报           → 获取家族/标签信息
```

### 连招 2: 域名追踪

```
已知: 恶意域名 evil.duckdns.org

步骤:
1. domain="evil.duckdns.org"       → 当前IP
2. 获取IP后 → ip="x.x.x.x"         → 同IP其他域名
3. 统计同IP域名数量                  → 判断是否防弹托管
4. 扩展动态DNS服务 → domain="duckdns.org" → 同服务其他可疑域名
5. risk_insight 查域名情报
```

### 连招 3: 基础设施变更追踪

```
发现: 域名 evil.com 的IP从 A 变成 B

步骤:
1. ip="A"                          → 旧IP当前状态
2. ip="B"                          → 新IP当前状态
3. 对比两个IP的域名列表              → 找迁移模式
4. 检查是否使用相同证书              → 确认关联
5. 记录变更时间线                    → 追踪基础设施演化
```

### 连招 4: 恶意软件家族扩展

```
发现: IP 1.2.3.4 被标记为 AsyncRAT

步骤:
1. 获取该IP特征（端口、证书、banner）
2. 搜索同特征的其他IP
   - port="6606"
   - ssl="相同证书"
3. 扩展到同家族其他C2
4. 构建家族基础设施图谱
```

## 防弹托管识别

### 高托管密度IP特征

当单个IP托管大量域名时（>100），可能是:
- 防弹托管服务
- 恶意基础设施
- 快速变换域名(Fast-Flux)

```bash
# 搜索IP后检查域名数量
ip="x.x.x.x"

# 如果返回域名数量 > 100，标记为可疑
```

### 常见防弹托管提供商特征

```bash
# 俄罗斯防弹托管
country="RU" && (asn="AS48666" || asn="AS44094")

# 荷兰防弹托管
country="NL" && asn="AS202425"

# 特定组织
org="bulletproof" || org="offshore"
```

## CVE漏洞利用关联

### 按CVE搜索受影响资产

```bash
# Ivanti Connect Secure (CVE-2024-21887)
app="ivanti" && port="443"

# MOVEit Transfer (CVE-2023-34362)
app="moveit" && port="443"

# Exchange ProxyLogon
app="exchange" && port="443"
```

### 漏洞扫描器IP识别

```bash
# 短时间内扫描多个端口的IP
# 需要结合威胁情报判断

# 已知扫描器特征
banner="masscan" || banner="zgrab"
```

## 输出格式

### 威胁狩猎报告模板

```markdown
## 威胁狩猎报告

### 狩猎目标
- 初始IOC: [IP/域名/Hash]
- 威胁类型: [恶意软件家族/僵尸网络/APT]

### 关联发现

#### 新增IP
| IP | 关联方式 | 威胁标签 | 托管域名数 |
|----|---------|---------|-----------|
| x.x.x.x | 证书关联 | AsyncRAT | 150 |

#### 新增域名
| 域名 | 关联IP | DNS服务 | 检测率 |
|------|--------|---------|--------|
| evil.duckdns.org | x.x.x.x | DuckDNS | 10/95 |

### 基础设施画像
- 托管商: [名称]
- 地理分布: [国家列表]
- 活跃时间: [时间范围]

### 处置建议
1. 紧急封禁: [IP列表]
2. 监控域名: [域名列表]
3. 检测规则: [Sigma/Snort规则]
```

## 注意事项

1. **CIDR语法**: 使用 `cidr="x.x.x.x/24"` 进行网段搜索（注意是等号+引号，不是冒号）
2. **结果时效性**: 搜索结果基于历史扫描，可能有延迟
3. **关联验证**: 关联发现需用 `risk_insight` 交叉验证
4. **基础设施变化**: 攻击者会频繁更换IP，需定期复查

## C段关联分析

使用 CIDR 语法进行同网段关联：

```bash
# 发现恶意IP后，搜索同C段
cidr="45.74.17.165/24"     # 返回478条，可发现同网段其他恶意资产
cidr="178.16.55.0/24"      # 返回797条，AsyncRAT C2所在网段
cidr="185.225.74.0/24"     # MooBot僵尸网络所在网段

# 结合端口过滤
cidr="178.16.55.0/24" && port="6606"   # 同网段的AsyncRAT
cidr="45.74.17.0/24" && port="7000"    # 同网段的Xworm
```
