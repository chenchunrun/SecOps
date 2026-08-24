---
name: redteam-recon-person
description: 个人目标情报收集。针对特定个人的OSINT收集和社工画像分析。当用户要求"人物画像"、"个人情报"、"OSINT调查"、"社工预研"、"VIP安全评估"、"高管风险评估"时使用此技能。
metadata:
  version: 2.1.0
  builtin: true
  category: redteam-recon
---

# 个人目标情报

针对特定个人进行开源情报收集和社工画像分析。

## 依赖要求

**Python 环境**: Python 3.8+

**安装依赖**:
```bash
pip3 install -r requirements.txt
```

**环境检测**:
```bash
python3 scripts/check_env.py
```

**关联技能**: 本技能依赖 `email-osint` 技能的 holehe 和 blackbird 工具。

## 适用场景

**仅限授权测试**:
- 红队演练社工预研
- 高管安全风险评估
- VIP人员保护评估
- 钓鱼演练目标分析
- 安全意识培训素材

## 执行超时说明

> ⚠️ **重要**: 个人情报收集需要查询多个平台，请耐心等待。

| 工具/阶段 | 默认超时 | 说明 |
|----------|---------|------|
| `person_recon.py` (完整) | **~5分钟** | 完整侦察流程 |
| holehe | **120s** (2分钟) | 邮箱社交账号验证 |
| blackbird | **120s** (2分钟) | 跨平台用户名搜索 |

**超时原因**：
- holehe 需要检测 100+ 社交平台
- blackbird 需要搜索多个网站验证用户名

## 核心能力

| 能力 | 实现方式 | 说明 |
|------|----------|------|
| OSINT收集 | 本地脚本 + MCP | 多维度情报收集 |
| 邮箱关联 | holehe (email-osint) | 检测邮箱注册的平台 |
| 用户名搜索 | blackbird (email-osint) | 跨平台用户名搜索 |
| 社交画像 | 本地脚本 | 行为分析和画像生成 |
| 数字足迹 | Google Dorks | 在线活动追踪 |

## 工具矩阵

### 本地自动化脚本

```bash
# 基础扫描 (仅姓名)
python3 scripts/person_recon.py -n "John Doe"

# 完整扫描 (姓名+邮箱+用户名)
python3 scripts/person_recon.py -n "John Doe" -e john@example.com -u johndoe

# 输出 JSON
python3 scripts/person_recon.py -n "John Doe" -e john@example.com --json -o result.json

# 输出 Markdown 报告
python3 scripts/person_recon.py -n "John Doe" --markdown -o report.md

# 详细模式
python3 scripts/person_recon.py -n "John Doe" -e john@example.com -v
```

### 关联技能工具 (email-osint)

```bash
# holehe - 邮箱注册检测
python3 ../email-osint/scripts/holehe_run.py target@example.com

# blackbird - 用户名搜索
python3 ../email-osint/scripts/blackbird_run.py -u johndoe
```

### 可选本地工具

| 工具 | 用途 | 安装命令 |
|------|------|----------|
| sherlock | 用户名搜索 | `pip3 install sherlock-project` |
| maigret | 高级用户名搜索 | `pip3 install maigret` |
| theHarvester | 信息收集 | `pip3 install theHarvester` |

---

## 工作流程

```
输入: 目标姓名/邮箱/用户名
     │
     ├─► Phase 1: 用户名推断
     │     └─► 本地: person_recon.py (姓名变体生成)
     │
     ├─► Phase 2: 邮箱关联检测
     │     └─► 关联: email-osint/holehe
     │
     ├─► Phase 3: 用户名搜索
     │     └─► 关联: email-osint/blackbird
     │
     ├─► Phase 4: 数据泄露检查
     │     └─► 手动: haveibeenpwned.com
     │
     ├─► Phase 5: 社交媒体搜索
     │     └─► 本地: Google Dorks 生成
     │
     ├─► Phase 6: 画像分析
     │     └─► 本地: person_recon.py
     │
     └─► 输出: 人物档案报告
```

---

## 工作流程详解

### Phase 1: 基础信息

收集目标基本信息：
- 姓名（全名、昵称、网名）
- 职位和组织
- 公开联系方式
- 照片（用于验证）

### Phase 2: 社交媒体

**平台搜索**:

| 平台 | 搜索方法 | 信息价值 |
|------|---------|---------|
| LinkedIn | 姓名+公司 | 职业经历、技能 |
| Twitter/X | 用户名搜索 | 观点、兴趣 |
| Facebook | 姓名+地区 | 个人生活、社交 |
| Instagram | 用户名 | 生活方式 |
| GitHub | 用户名/邮箱 | 技术能力 |
| 微博 | 姓名/昵称 | 中文内容 |
| 知乎 | 姓名 | 专业观点 |

**搜索技巧**:
```
# Google Dorks
"John Doe" site:linkedin.com
"john.doe" site:github.com
"target@company.com" site:twitter.com
```

### Phase 3: 用户名枚举

**跨平台搜索**:
```bash
# Sherlock
sherlock username

# WhatsMyName
whatsmyname -u username

# Maigret
maigret username
```

**常见用户名模式**:
- 真名变体: johndoe, john_doe, john.doe
- 昵称: jd1990, johnny123
- 邮箱前缀: jdoe

### Phase 4: 数据泄露

**检查历史泄露**:
```bash
# Have I Been Pwned API
curl "https://haveibeenpwned.com/api/v3/breachedaccount/email@example.com"
```

**泄露数据库搜索**:
- DeHashed
- LeakCheck
- IntelX

**发现的凭证类型**:
| 类型 | 价值 | 使用方式 |
|------|------|---------|
| 明文密码 | 极高 | 直接尝试 |
| 哈希密码 | 高 | 离线破解 |
| 密码模式 | 中 | 推断新密码 |

### Phase 5: 行为画像

**兴趣分析**:
- 关注的账号和话题
- 发布内容的主题
- 互动活跃的社区
- 使用的工具和平台

**性格特征**:
- 公开程度（隐私意识）
- 技术水平
- 社交活跃度
- 决策风格

**时间模式**:
- 活跃时间段
- 发布频率
- 响应速度

### Phase 6: 社工评估

**攻击面分析**:

| 攻击向量 | 可行性 | 成功率预估 |
|---------|-------|-----------|
| 邮件钓鱼 | 高 | 中 |
| 电话社工 | 中 | 中 |
| 社交钓鱼 | 高 | 高 |
| 物理接近 | 低 | 低 |

**社工话术建议**:
基于目标的兴趣和职责设计场景：
- 利用的心理因素（权威、紧迫、好奇等）
- 推荐的钓鱼主题
- 话术脚本建议

## 输出规范

### 人物档案

```markdown
# 目标档案

## 基本信息
| 字段 | 信息 |
|------|------|
| 姓名 | John Doe |
| 职位 | IT Manager |
| 公司 | Target Corp |
| 邮箱 | john.doe@target.com |

## 社交媒体
| 平台 | 用户名 | 活跃度 | 隐私设置 |
|------|--------|-------|---------|
| LinkedIn | john-doe-123 | 高 | 公开 |
| Twitter | @johndoe | 中 | 公开 |
| GitHub | jdoe | 低 | 公开 |

## 兴趣标签
- 技术: Python, DevOps, Cloud
- 爱好: 高尔夫, 红酒, 旅行
- 关注: 科技新闻, 创业

## 安全评估
| 维度 | 评估 | 说明 |
|------|------|------|
| 隐私意识 | 低 | 大量公开信息 |
| 安全习惯 | 中 | 有2FA迹象 |
| 社工脆弱性 | 高 | 易被话术诱导 |

## 社工建议
- 推荐场景: 技术会议邀请
- 钓鱼主题: DevOps工具试用
- 话术要点: 强调技术前沿性
```

## OSINT工具

### 用户名搜索

| 工具 | 用途 | 命令 |
|------|------|------|
| Sherlock | 跨平台搜索 | `sherlock username` |
| Maigret | 高级搜索 | `maigret username` |
| WhatsMyName | 用户名枚举 | `whatsmyname -u user` |

### 邮箱情报

| 工具 | 用途 | 命令 |
|------|------|------|
| theHarvester | 邮箱收集 | `theHarvester -d domain.com` |
| h8mail | 泄露检查 | `h8mail -t email@domain.com` |

### 人脸搜索

| 工具 | 用途 |
|------|------|
| PimEyes | 人脸识别搜索 |
| TinEye | 反向图片搜索 |
| Google Images | 反向搜索 |

## MITRE ATT&CK 技术映射

个人情报收集涉及红队侦察全周期的多个 ATT&CK 技术：

| 战术 | 技术 | 名称 | 场景 |
|------|------|------|------|
| **Reconnaissance (TA0095)** | T1592 | Gather Victim Host Information | 收集目标使用的主机/设备信息 |
| | T1592.004 | Client Configurations | 收集目标客户端配置信息 |
| | T1593 | Search Closed Sources | 使用付费数据库(DeHashed/IntelX)搜索 |
| | T1593.002 | Code Repositories | 搜索目标 GitHub/GitLab 活动 |
| | T1594 | Search Victim-Owned Websites | 搜索目标个人博客/作品集网站 |
| | T1589 | Gather Victim Identity Information | 收集目标身份信息 |
| | T1589.001 | Credentials | 从泄露数据库收集凭证 |
| | T1589.002 | Email Addresses | 收集目标邮箱地址 |
| | T1590 | Gather Victim Host Information | 收集目标网络存在信息 |
| | T1591 | Gather Victim Org Information | 收集目标组织信息 |
| | T1595.003 | Wordlist Scrolling | 基于已知信息生成密码字典 |
| **Initial Access (TA0001)** | T1566.001 | Spearphishing Attachment | 基于画像发送定向钓鱼邮件 |
| | T1566.002 | Spearphishing Link | 基于兴趣发送钓鱼链接 |
| | T1078 | Valid Accounts | 使用泄露凭证尝试登录 |
| **Social Engineering (TA0001)** | T1566 | Phishing | 基于社交画像设计话术 |
| | T1650 | Acquire Infrastructure | 注册仿冒域名用于钓鱼 |
| **Credential Access (TA0006)** | T1110 | Brute Force | 基于画像生成密码进行爆破 |
| | T1110.002 | Password Cracking | 离线破解泄露的哈希密码 |
| | T1552 | Unsecured Credentials | 从泄露数据库获取明文凭证 |

## OWASP Top 10 映射

个人情报收集直接支持 OWASP 安全评估：

| OWASP 类别 | CWE | 关联场景 |
|-----------|-----|---------|
| **A01** Broken Access Control | CWE-284 | 泄露凭证导致越权访问 |
| **A02** Cryptographic Failures | CWE-311 | 泄露数据库中的明文/弱哈希密码 |
| **A04** Insecure Design | CWE-209 | 社交媒体泄露系统设计信息 |
| **A05** Security Misconfiguration | CWE-16 | 公开云存储桶/错误配置暴露数据 |
| **A07** Identification & Auth Failures | CWE-287 | 凭证填充攻击基于泄露数据 |
| **A08** Software & Data Integrity Failures | CWE-345 | 供应链攻击通过社工触达 |
| **A09** Security Logging Failures | CWE-778 | OSINT收集过程无法被检测 |
| **A10** SSRF | CWE-918 | 内部人员信息辅助SSRF攻击 |

## Sigma 检测规则

### 规则 1: 异常登录行为检测（基于凭证泄露）

```yaml
title: Suspicious Login After Credential Leak
description: >
  检测用户在已知数据泄露事件后，从异常位置/设备登录的行为。
  结合 OSINT 泄露情报和认证日志进行关联分析。
status: experimental
author: sec-skills
references:
  - https://attack.mitre.org/techniques/T1078/
  - https://attack.mitre.org/techniques/T1110/
tags:
  - attack.initial_access
  - attack.credential_access
  - attack.t1078
  - attack.t1110
logsource:
  product: windows
  service: security
detection:
  selection_successful_logon:
    EventID: 4624
    LogonType: 10
  filter_normal_location:
    IpAddress:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  timeframe: 24h
  condition: selection_successful_logon and not filter_normal_location
falsepositives:
  - 用户出差/远程办公
  - VPN 连接
level: medium
```

### 规则 2: 用户名枚举检测（跨平台搜索行为）

```yaml
title: Cross-Platform Username Enumeration Pattern
description: >
  检测从单一源IP对多个社交媒体/平台进行用户名搜索的行为模式。
  这种行为通常指示自动化 OSINT 工具（如 Sherlock/Maigret）的使用。
status: experimental
author: sec-skills
references:
  - https://attack.mitre.org/techniques/T1589/
  - https://attack.mitre.org/techniques/T1593/
tags:
  - attack.reconnaissance
  - attack.t1589
  - attack.t1593
logsource:
  product: proxy
detection:
  selection:
    c-uri-query:
      - "*linkedin*"
      - "*twitter*"
      - "*github*"
      - "*facebook*"
      - "*instagram*"
  timeframe: 10m
  condition: selection | count(c-uri-query) by src_ip > 5
falsepositives:
  - 合法用户同时访问多个社交媒体
level: low
```

## CVE 参考表

个人情报收集相关的高危 CVE（社交工程/凭证利用向量）：

| CVE | 产品 | 影响 | OSINT 关联 |
|-----|------|------|-----------|
| CVE-2021-44228 | Apache Log4j | RCE | 通过LinkedIn定位使用Java的目标人员 |
| CVE-2023-23397 | Microsoft Outlook | 凭证泄露 | 收集目标Outlook版本后定向钓鱼 |
| CVE-2024-21413 | Microsoft Outlook | 远程代码执行 | 针对高管Outlook客户端 |
| CVE-2021-26855 | Microsoft Exchange | SSRF | 识别使用Exchange的目标组织 |
| CVE-2023-46805 | Ivanti Connect Secure | 身份验证绕过 | 识别使用Ivanti VPN的目标人员 |

## IOC 采集指引

| 数据类型 | 采集方法 | 存储格式 | 用途 |
|---------|---------|---------|------|
| 邮箱地址 | holehe/Google Dorks | email_addr | 关联分析/凭证填充 |
| 用户名变体 | person_recon.py | username | 跨平台搜索 |
| 社交媒体链接 | blackbird/sherlock | url | 行为分析 |
| 泄露凭证 | HIBP/DeHashed | credential | 风险评估 |
| 电话号码 | Google Dorks | phone | 社工攻击 |
| 物理地址 | 公开记录 | address | 物理安全评估 |
| 技术技能 | LinkedIn/GitHub | skill_list | 攻击面评估 |
| 密码模式 | 泄露分析 | password_pattern | 密码字典生成 |

## 合规标准关联

| 标准 | 条款 | 关联 |
|------|------|------|
| **GDPR** | Art. 5/32 | 个人数据保护—OSINT收集需合规 |
| **PIPL** | 第13条 | 个人信息处理—需取得同意 |
| **ISO 27001** | A.8.7 | 恶意软件防范—社工攻击防范 |
| **ISO 27001** | A.5.7 | 情报威胁—OSINT用于威胁情报 |
| **NIST SP 800-53** | IA-2 | 身份验证—多因素认证防范凭证泄露 |
| **NIST SP 800-53** | AT-2 | 意识培训—基于OSINT画像的钓鱼演练 |
| **NIST SP 800-60** | 附件J | 信息类型—PII分类和OSINT暴露面 |
| **PCI DSS** | 12.6.2 | 安全意识—针对持卡数据的社工防范 |

## 跨技能工作流

### 工作流 1: 红队社工攻击链

```
redteam-recon-enterprise (识别关键人员)
  └─→ redteam-recon-person (深度画像)
       └─→ redteam-intrusion-social (设计社工话术)
            └─→ phishing-analysis (钓鱼执行)
                 └─→ ttp-extractor (TTP提取)
```

### 工作流 2: 凭证泄露响应链

```
redteam-recon-person (发现泄露凭证)
  └─→ auth-log-analysis (检测异常登录)
       └─→ windows-ir/linux-ir (事件响应)
            └─→ pdf-report (事件报告)
```

### 工作流 3: 高管保护评估链

```
redteam-recon-person (高管数字足迹)
  └─→ brand-impersonation (检测仿冒账号)
       └─→ url-analysis (分析钓鱼链接)
            └─→ pdf-report (安全评估报告)
```

## 法律和道德边界

**允许的行为**:
- 公开信息收集
- 授权范围内的测试
- 安全评估报告

**禁止的行为**:
- 未授权访问账号
- 购买非法数据
- 骚扰或跟踪
- 超出授权范围

## 与其他技能的关联

### 输入来源

| 来源技能 | 产出 | 用途 |
|----------|------|------|
| `redteam-recon-enterprise` | 关键人员列表 | 高管/IT人员侦察 |
| `phishing-analysis` | 发件人信息 | 攻击者画像 |

### 输出调用

| 发现内容 | 调用技能 | 说明 |
|---------|---------|------|
| 邮箱地址 | `/email-osint` | 邮箱深度分析 |
| 钓鱼策划 | `/redteam-socialeng` | 社工攻击设计 |
| 组织信息 | `/redteam-recon-enterprise` | 企业情报 |
| 泄露凭证 | `/redteam-exploit` | 凭证利用 |

---

## 参考文件

- [references/report-format.md](references/report-format.md) - 报告格式规范
