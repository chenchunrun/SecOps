---
name: auth-log-analysis
description: 当用户要求"分析登录日志"、"检测异常登录"、"分析认证日志"、"检测暴力破解"、"检测凭据填充"、"分析邮件登录"、"不可能旅行检测"、"检测账户接管"、"认证安全审计"时使用此技能。
metadata:
  version: 1.1.0
  builtin: true
  attck_version: v16.1
  owasp_version: "2025"
---

# 认证日志威胁分析

分析认证日志（邮件、VPN、SSO、RDP、SSH 等）中的异常行为和安全威胁，覆盖凭据攻击、账户接管、内部威胁等场景。

## 依赖要求

**Python 版本**: 3.8+

**必需库**:
```bash
pip install pandas
```

## 快速使用

```bash
# 完整分析
python3 scripts/auth_log_analyze.py login.csv

# JSON 输出（适合管道处理）
python3 scripts/auth_log_analyze.py -j login.csv

# 指定列名映射（适配不同日志格式）
python3 scripts/auth_log_analyze.py login.csv \
  --time-col "登录时间" --user-col "账号" --ip-col "IP地址" --location-col "地理位置"

# 快速分诊（只输出高风险事件）
python3 scripts/triage.py login.csv

# 生成 Sigma 检测规则
python3 scripts/sigma_gen.py --type credential-stuffing --threshold 10
```

## MITRE ATT&CK 技术映射

| ATT&CK ID | 战术 | 技术 | 本技能检测方式 |
|-----------|------|------|--------------|
| **T1110.001** | Credential Access | Brute Force: Password Guessing | 暴力破解检测 — 单用户高频尝试 |
| **T1110.002** | Credential Access | Brute Force: Password Cracking | 离线破解不适用于日志分析，但可检测撞库结果 |
| **T1110.003** | Credential Access | Brute Force: Password Spraying | 凭据填充检测 — 单 IP 多用户低频尝试 |
| **T1110.004** | Credential Access | Brute Force: Credential Stuffing | 凭据填充检测 — 使用泄露凭据批量测试 |
| **T1110.005** | Credential Access | Brute Force: Password Spraying (Same URL) | 协议维度单 IP 多用户分析 |
| **T1078** | Defense Evasion, Persistence, Privilege Escalation | Valid Accounts | 不可能旅行 + 异常地理位置 + 非工作时间 |
| **T1078.002** | Defense Evasion | Valid Accounts: Domain Accounts | 域账户异常登录模式 |
| **T1078.003** | Defense Evasion | Valid Accounts: Local Accounts | 本地账户异常使用 |
| **T1078.004** | Defense Evasion | Valid Accounts: Cloud Accounts | 云服务 IP 登录检测 |
| **T1021** | Lateral Movement | Remote Services | RDP/SSH 跨段登录关联 |
| **T1556** | Credential Access, Defense Evasion, Persistence | Modify Authentication Process | 异常认证协议或 MFA 绕过模式 |
| **T1621** | Credential Access | Multi-Factor Authentication Request Generation | MFA 疲劳攻击模式（短时间大量 MFA 请求） |
| **T1133** | Initial Access | External Remote Services | 外部 VPN/RDP 暴露检测 |
| **T1098** | Persistence | Account Manipulation | 邮件转发规则创建、权限变更关联 |
| **T1530** | Collection | Data from Cloud Storage Object | 云存储异常访问模式 |

## OWASP 2025 相关映射

| OWASP 类别 | 关联性 | 检测点 |
|-----------|--------|--------|
| **A07:2021 – Identification and Authentication Failures** | 核心 | 暴力破解、凭据填充、弱密码利用 |
| **A01:2021 – Broken Access Control** | 次要 | 越权登录、权限提升后异常访问 |
| **A09:2021 – Security Logging and Monitoring Failures** | 方法论 | 认证日志完整性验证、审计追踪 |
| **A05:2021 – Security Misconfiguration** | 关联 | MFA 配置缺陷、默认凭据利用 |

## 威胁类型与检测方法

| 类型 | 特征 | 检测方法 | ATT&CK 映射 |
|------|------|---------|------------|
| **凭据填充** | 单 IP 访问多用户，每用户 1-2 次 | IP-用户关联分析 | T1110.004 |
| **密码喷洒** | 单密码尝试多账户，低频分散 | 用户-时间矩阵分析 | T1110.003 |
| **暴力破解** | 单用户短时间大量尝试 | 频率阈值检测 | T1110.001 |
| **账户盗用** | 不可能旅行、异常地理位置 | 地理异常检测 | T1078 |
| **内部威胁** | 非工作时间、异常访问模式 | 行为基线偏离 | T1078.002 |
| **代理滥用** | 云服务 IP、VPN 出口、Tor 节点 | IP 类型识别 | T1078.004 |
| **MFA 疲劳** | 短时间大量 MFA 推送请求 | MFA 请求频率分析 | T1621 |
| **横向移动** | 内网跨段 RDP/SSH 登录 | 登录链路分析 | T1021 |
| **邮件转发滥用** | 异常转发规则创建 | 关联邮件日志审计 | T1098 |

## 分析工作流

### Phase 1: 数据加载与预处理

```bash
python3 scripts/auth_log_analyze.py login.csv
```

**数据质量检查：**
- 字段完整性（时间、用户、IP、位置）
- 时间格式标准化
- IP 格式校验（IPv4/IPv6）
- 缺失值处理

**输出：** 日志概览、字段识别、数据质量报告

### Phase 2: 威胁检测（自动化）

| 检测项 | 脚本模块 | 默认阈值 | ATT&CK |
|--------|---------|---------|--------|
| 凭据填充 | `detect_credential_stuffing()` | 单 IP > 5 用户 | T1110.004 |
| 密码喷洒 | `detect_credential_stuffing()` | 单 IP 多用户每用户 ≤ 2 次 | T1110.003 |
| 暴力破解 | `detect_brute_force()` | 单记录 > 50 次 | T1110.001 |
| 不可能旅行 | `detect_impossible_travel()` | 跨国 < 2 小时 | T1078 |
| 高风险国家 | `detect_high_risk_countries()` | 黑名单国家列表 | T1078.004 |
| 用户行为异常 | `detect_user_anomalies()` | IP 数 > 500 / 国家数 > 8 | T1078 |
| 非工作时间 | `detect_off_hours()` | 0-6 点 + 国外 IP | T1078 |

### Phase 3: 深度分析与关联

**IOC 提取：**
- 提取所有可疑源 IP → 调用 `ip-analysis` 进行威胁情报关联
- 提取可疑用户名 → 关联 AD/LDAP 账户状态
- 提取地理位置异常 → 关联 VPN/代理检测

**跨技能协同：**
| 发现 | 调用技能 | 用途 |
|------|---------|------|
| 攻击源 IP | `ip-analysis` | IP 威胁情报、信誉评分 |
| VPN/代理 IP | `ip-analysis` | 匿名化服务识别 |
| 可疑用户行为 | `linux-ir` / `windows-ir` | 主机级证据收集 |
| 邮件登录异常 | `phishing-analysis` | 关联钓鱼攻击 |
| 攻击技术提取 | `ttp-extractor` | ATT&CK 技术归纳 |
| 完整报告输出 | `pdf-report` | 生成 PDF 分析报告 |

### Phase 4: 分诊与报告

```bash
# 快速分诊 — 只输出 Critical/High 事件
python3 scripts/triage.py login.csv

# 完整分析报告
python3 scripts/auth_log_analyze.py login.csv -o report.json
```

按 `references/report-format.md` 输出结构化报告。

## 工具命令速查

| 任务 | 命令 |
|------|------|
| 完整分析 | `python3 scripts/auth_log_analyze.py log.csv` |
| JSON 输出 | `python3 scripts/auth_log_analyze.py -j log.csv` |
| 凭据填充检测 | `python3 scripts/auth_log_analyze.py --detect credential-stuffing log.csv` |
| 暴力破解检测 | `python3 scripts/auth_log_analyze.py --detect brute-force log.csv` |
| 不可能旅行检测 | `python3 scripts/auth_log_analyze.py --detect impossible-travel log.csv` |
| 指定时间列 | `--time-col "登录时间"` |
| 指定用户列 | `--user-col "账号"` |
| 指定 IP 列 | `--ip-col "IP地址"` |
| 快速分诊 | `python3 scripts/triage.py log.csv` |
| Sigma 规则生成 | `python3 scripts/sigma_gen.py --type credential-stuffing` |

## 关键阈值速查

### 凭据填充 / 密码喷洒
| 指标 | 正常值 | 可疑值 | 严重值 |
|------|--------|--------|--------|
| 单 IP 用户数 | 1-3 | > 5 | > 20 |
| 每用户尝试次数 | 正常使用 | 1-2 次 | > 5 次 |
| 单 IP 协议种类 | 1-2 | 2-3 | > 3 |

### 暴力破解
| 时间窗口 | 告警阈值 | 严重阈值 | 关键阈值 |
|---------|---------|---------|---------|
| 1 分钟 | > 10 次 | > 50 次 | > 100 次 |
| 1 小时 | > 100 次 | > 500 次 | > 1000 次 |
| 1 天 | > 500 次 | > 2000 次 | > 5000 次 |

### 不可能旅行
| 地理跨度 | 最短合理时间 | 说明 |
|---------|-------------|------|
| 同城市 | 即时 | 正常 |
| 同国家不同城市 | 1-3 小时 | 视距离 |
| 跨洲 | 8-15 小时 | 需要飞行 |
| 对跖点 | > 24 小时 | 理论极限 |

### MFA 疲劳攻击
| 指标 | 正常值 | 可疑值 | 严重值 |
|------|--------|--------|--------|
| 1 小时 MFA 请求 | 1-3 | > 10 | > 50 |
| 连续 MFA 间隔 | > 30 分钟 | < 5 分钟 | < 1 分钟 |

## 使用示例

### 示例 1: 邮件系统暴力破解事件响应

```bash
# 1. 从邮件网关导出登录日志
# 2. 运行完整分析
python3 scripts/auth_log_analyze.py mail_login.csv -o result.json

# 3. 快速分诊查看高危事件
python3 scripts/triage.py mail_login.csv

# 4. 提取可疑 IP 进行情报查询
# （从 result.json 中提取 IP 列表）
cat result.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for ip_info in data.get('credential_stuffing', {}).get('details', []):
    print(ip_info['ip'])
" | while read ip; do
    echo "Analyzing $ip..."
    # 调用 ip-analysis 技能
done

# 5. 为检测到的攻击生成 Sigma 规则
python3 scripts/sigma_gen.py --type credential-stuffing --threshold 10
```

### 示例 2: VPN 不可能旅行检测

```bash
# 分析 VPN 登录日志
python3 scripts/auth_log_analyze.py --detect impossible-travel vpn_logs.csv

# 输出示例：
# --- 不可能旅行 (15 条) ---
# 受影响用户 Top 5:
#   userA: 4 次
#   userB: 3 次
```

### 示例 3: 批量日志分诊

```bash
# 对多个日志文件快速扫描
for f in /var/log/auth/*.csv; do
    echo "=== $f ==="
    python3 scripts/triage.py "$f" --severity high
done
```

## 误报排除指南

### 常见误报场景

| 场景 | 特征 | 排除方法 |
|------|------|---------|
| 公司代理出口 | 多用户共享 1 个公网 IP | IP 白名单 `220.197.30.0/24` |
| 移动办公 | 频繁切换基站 IP | 用户白名单 + 地理围栏 |
| Microsoft 365 同步 | 固定 IP + IMAP + Outlook UA | IP 模式 `40.99.x.x` + UA 匹配 |
| CDN 回源 | 云服务 IP 段 | 区分正向代理 vs 反向代理 |
| 时区错误 | 所有"非工作时间" | 验证日志时区配置 |

### 白名单配置示例

```yaml
# whitelist.yaml
exclusions:
  # 公司代理出口 IP
  - ip_cidr: "220.197.30.0/24"
    reason: "公司代理出口"

  # 管理员批量操作
  - user_in: ["admin", "system"]
    time_window: "maintenance_window"
    reason: "计划维护"

  # M365 同步连接
  - ip_pattern: "40.99.*.*"
    protocol: "IMAP"
    user_agent_contains: "Outlook"
    reason: "Exchange Online 同步"
```

## 关联技能调用

| 发现的 IOC | 调用技能 | 说明 |
|-----------|---------|------|
| 攻击来源 IP | `ip-analysis` | 分析 IP 威胁情报、信誉 |
| VPN/代理 IP | `ip-analysis` | 识别匿名化服务 |
| 主机异常 | `linux-ir` / `windows-ir` | 主机级取证 |
| 邮件钓鱼 | `phishing-analysis` | 关联钓鱼邮件 |
| 攻击技术归纳 | `ttp-extractor` | 提取 ATT&CK TTP |
| 报告生成 | `pdf-report` | 生成 PDF 报告 |
| 恶意邮件附件 | `mail-attachment-downloader` | 下载并分析 |

## 参考文件

- **[references/report-format.md](references/report-format.md)** — 📋 报告格式规范（必读）
- [references/analysis-phases.md](references/analysis-phases.md) — 分析阶段详解
- [references/detection-rules.md](references/detection-rules.md) — 详细阈值配置与组合规则

## CVE 与威胁情报参考

| CVE / 威胁 | 关联性 | 影响 |
|-----------|--------|------|
| **CVE-2024-XXXX** (Exchange ProxyLogon 类) | 认证绕过导致异常登录 | 检测未授权会话创建 |
| **CVE-2023-XXXX** (Citrix Bleed) | 会话令牌泄露导致账户接管 | 检测异常会话 + 不可能旅行 |
| **APT41 凭据攻击活动** | 利用泄露凭据进行邮件登录 | 凭据填充检测 + 高风险国家 |
| **MFA 疲劳攻击趋势** | 2024-2025 年显著增加 | MFA 请求频率分析 |

## Sigma 规则生成

本技能可生成 Sigma 规则用于 SIEM 集成：

```bash
# 生成凭据填充检测规则
python3 scripts/sigma_gen.py --type credential-stuffing --threshold 10

# 生成暴力破解检测规则
python3 scripts/sigma_gen.py --type brute-force --window 1h --threshold 100

# 生成不可能旅行检测规则
python3 scripts/sigma_gen.py --type impossible-travel --hours 2
```

生成的 Sigma 规则可直接导入 Splunk、Elastic Security、Microsoft Sentinel 等 SIEM 平台。

---

## AI 建议

- 发现邮箱地址时，建议使用 `email-osint` 技能进行深入调查
- 检测到横向移动迹象时，立即启动 `linux-ir` 或 `windows-ir` 进行主机取证
- 大规模攻击事件建议调用 `ttp-extractor` 归纳攻击技术，更新检测规则
- 发现泄露凭据使用时，关联 `phishing-analysis` 追溯攻击入口