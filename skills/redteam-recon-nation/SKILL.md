---
name: redteam-recon-nation
description: 国家级目标情报收集。针对APT组织和国家级威胁行为者的情报分析。当用户要求"APT分析"、"国家级威胁"、"APT情报"、"国家黑客组织"、"地缘政治网络威胁"、"APT归因"、"APT TTP提取"时使用此技能。
metadata:
  version: 1.1.0
  builtin: true
  category: redteam-recon
  attck_version: v16.1
  owasp_version: "2025"
---

# 国家级目标情报

追踪和分析国家级APT组织的活动特征，关联地缘政治事件与网络威胁。

## 核心能力

| 能力 | 说明 |
|------|------|
| APT追踪 | 识别和追踪国家支持的APT组织 |
| 战术分析 | 分析攻击战术、技术和程序(TTP) |
| 地缘关联 | 关联政治事件与网络攻击行动 |
| IOC提取 | 提取可操作的威胁指标 |

## 工作流程

### Phase 1: 目标确认

确定分析目标：
- APT组织名称或别名
- 受害者行业/地区
- 特定攻击行动
- 时间范围

### Phase 2: 情报收集

**公开情报来源**:
- 安全厂商APT报告（Mandiant、CrowdStrike、Kaspersky等）
- 国家CERT公告
- 学术安全研究
- 威胁情报共享平台（MISP、OTX等）

**暗网情报**:
- 地下论坛监控
- Telegram群组
- 泄露数据库

### Phase 3: 攻击者画像

构建APT组织档案：

```
组织名称: APT28 (Fancy Bear)
归属评估: 俄罗斯 GRU (高置信度)
活跃时间: 2004年至今
目标行业: 政府、军事、媒体、能源
技术特征:
  - 鱼叉式钓鱼
  - 零日漏洞利用
  - 定制化恶意软件
已知工具: X-Agent, Zebrocy, LoJax
```

### Phase 4: TTP分析

映射到MITRE ATT&CK框架：

| 战术 | 技术 | 子技术 |
|------|------|--------|
| Initial Access | Phishing | Spearphishing Attachment |
| Execution | User Execution | Malicious File |
| Persistence | Boot or Logon Autostart | Registry Run Keys |
| C2 | Application Layer Protocol | Web Protocols |

### Phase 5: IOC提取

提取可操作指标：
- 域名/IP地址
- 文件哈希(MD5/SHA256)
- YARA规则
- Sigma规则
- 网络特征

## 主要APT组织

### 俄罗斯关联

| 组织 | 别名 | 归属 | 主要目标 |
|------|------|------|---------|
| APT28 | Fancy Bear | GRU | 政府、军事 |
| APT29 | Cozy Bear | SVR | 政府、智库 |
| Sandworm | Voodoo Bear | GRU | 关键基础设施 |
| Turla | Venomous Bear | FSB | 政府、外交 |

### 中国关联

| 组织 | 别名 | 主要目标 |
|------|------|---------|
| APT41 | Winnti | 科技、电信、游戏 |
| APT40 | Leviathan | 海事、国防 |
| APT10 | Stone Panda | MSP、云服务 |

### 朝鲜关联

| 组织 | 别名 | 主要目标 |
|------|------|---------|
| Lazarus | Hidden Cobra | 金融、加密货币 |
| Kimsuky | - | 韩国政府、智库 |
| APT38 | - | 银行、SWIFT |

### 伊朗关联

| 组织 | 别名 | 主要目标 |
|------|------|---------|
| APT33 | Elfin | 航空、能源 |
| APT34 | OilRig | 中东政府、金融 |
| APT35 | Charming Kitten | 学术、人权 |

## 情报来源

### 优先级高

| 来源 | 类型 | 获取方式 |
|------|------|---------|
| MITRE ATT&CK | TTP数据库 | 公开 |
| VirusTotal | 样本分析 | API |
| AlienVault OTX | IOC共享 | 公开 |
| CISA Alerts | 政府公告 | 公开 |

### 优先级中

| 来源 | 类型 | 获取方式 |
|------|------|---------|
| Mandiant | 威胁报告 | 付费/公开 |
| CrowdStrike | 威胁报告 | 付费/公开 |
| Recorded Future | 威胁情报 | 付费 |

## 输出规范

### 威胁情报报告

1. **执行摘要** - 威胁等级、关键发现、紧急建议
2. **APT档案** - 组织画像、历史活动、能力评估
3. **TTP分析** - ATT&CK映射、攻击链分析
4. **IOC列表** - 可导入的指标清单
5. **检测规则** - YARA/Sigma规则
6. **防御建议** - 针对性缓解措施

### IOC格式

```json
{
  "type": "domain",
  "value": "malicious.example.com",
  "threat_actor": "APT28",
  "first_seen": "2024-01-15",
  "confidence": "high",
  "tags": ["c2", "phishing"]
}
```

## MITRE ATT&CK 全面映射 — 主要APT组织

### APT28 (Fancy Bear / GRU)
| 战术 | 技术 ID | 技术 | 说明 |
|------|--------|------|------|
| Initial Access | T1566.001 | Spearphishing Attachment | 鱼叉钓鱼附件 |
| Initial Access | T1566.002 | Spearphishing Link | 鱼叉钓鱼链接 |
| Execution | T1059.001 | PowerShell | PowerShell 执行 |
| Persistence | T1547.001 | Registry Run Keys | 注册表持久化 |
| Credential Access | T1552.001 | Credentials In Files | 文件中的凭据 |
| C2 | T1071.001 | Web Protocols | HTTP/HTTPS C2 |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | 通过 C2 通道外传 |

### APT29 (Cozy Bear / SVR) — Nobelium/SolarWinds
| 战术 | 技术 ID | 技术 | 说明 |
|------|--------|------|------|
| Initial Access | T1195.002 | Compromise Software Supply Chain | 供应链攻击 |
| Persistence | T1547.001 | Registry Run Keys | 持久化 |
| Defense Evasion | T1572 | Protocol Tunneling | 协议隧道 |
| Credential Access | T1606 | Forge Web Credentials | 伪造Web凭据 |
| C2 | T1071.001 | Web Protocols | 混入正常流量 |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | RDP 横向移动 |

### APT41 (Double Dragon)
| 战术 | 技术 ID | 技术 | 说明 |
|------|--------|------|------|
| Initial Access | T1190 | Exploit Public-Facing Application | 应用漏洞利用 |
| Execution | T1059.004 | Unix Shell | Linux 命令执行 |
| Persistence | T1543.002 | Systemd Service | systemd 服务 |
| Credential Access | T1110.002 | Password Cracking | 密码破解 |
| Defense Evasion | T1574.002 | DLL Side-Loading | DLL 侧加载 |
| Collection | T1560 | Archive Collected Data | 数据打包 |

### Volt Typhoon (关键基础设施潜伏)
| 战术 | 技术 ID | 技术 | 说明 |
|------|--------|------|------|
| Initial Access | T1078 | Valid Accounts | 有效账户利用 |
| Defense Evasion | T1036 | Masquerading | 伪装合法流量 |
| Credential Access | T1003.001 | LSASS Memory | 凭据转储 |
| C2 | T1090 | Proxy | 代理链隐藏 |
| Lateral Movement | T1021 | Remote Services | 内网横向移动 |

### Lazarus Group (朝鲜)
| 战术 | 技术 ID | 技术 | 说明 |
|------|--------|------|------|
| Initial Access | T1566.002 | Spearphishing Link | 鱼叉钓鱼链接 |
| Execution | T1059.001 | PowerShell | PowerShell |
| Execution | T1204.002 | User Execution: File | 恶意文件执行 |
| Defense Evasion | T1497.003 | Time Based Evasion | 延时执行 |
| C2 | T1105 | Ingress Tool Transfer | 工具传输 |
| Impact | T1486 | Data Encrypted for Impact | 勒索加密 |

## OWASP 2025 关联

虽然 APT 攻击超越应用层，但以下 OWASP 类别与国家级威胁相关：

| OWASP 类别 | APT 利用场景 | 检测建议 |
|-----------|------------|--------|
| A01: Broken Access Control | 有效账户被利用 (T1078) | 异常权限监控 |
| A05: Security Misconfiguration | 默认凭据、暴露服务 | 配置基线审计 |
| A06: Vulnerable Components | 供应链攻击 (T1195) | SCA + 补丁管理 |
| A07: Auth Failures | 凭据窃取后的账户滥用 | MFA + 异常检测 |
| A08: Software/Data Integrity | 恶意更新植入 | 代码签名验证 |
| A10: SSRF | 内网探测跳板 | 请求源验证 |

## CVE 与近期 APT 活动参考

| 威胁事件 | CVE / 关联 | APT 组织 | 说明 |
|---------|-----------|---------|------|
| SolarWinds 供应链攻击 | CVE-2020-28000 系列 | APT29 | IT 管理软件后门 |
| 3CX 供应链攻击 | CVE-2023-... | APT41 | 双重供应链攻击 |
| Microsoft Exchange | ProxyLogon/ProxyShell | HAFNIUM | 邮件服务器漏洞利用 |
| Log4Shell | CVE-2021-44228 | 多个 APT | 广泛利用 |
| Volt Typhoon | SOHO 路由器劫持 | Volt Typhoon | 关键基础设施潜伏 |
| MOVEit Transfer | CVE-2023-34362 | CL0P | 数据窃取 |

## Sigma 规则集成

APT 检测的 Sigma 规则示例：

```yaml
# APT28 PowerShell 执行检测
title: APT28 PowerShell Execution Pattern
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlock:
      - '*DownloadString*'
      - '*IEX*'
      - '*Invoke-*'
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
  - attack.g0007  # APT28
level: high
```

## 使用示例

### 示例 1: APT 组织查询
```bash
# 查询特定APT组织
python3 scripts/apt_recon.py --group APT28

# 模糊搜索
python3 scripts/apt_recon.py --group "fancy"
```

### 示例 2: 攻击数据归因分析
```bash
# 从文件分析
python3 scripts/apt_recon.py -f attack_report.txt

# 从文本分析
python3 scripts/apt_recon.py -t "使用 T1566.001 和 T1059.001 技术，目标为政府机构"

# JSON 输出
python3 scripts/apt_recon.py -f report.txt --json
```

### 示例 3: 威胁画像生成
```bash
# 从IOC列表生成完整威胁画像
python3 scripts/threat_profile.py --iocs ioc_list.txt --format pdf
```

## 分析方法论

### Diamond Model 分析

```
         对手 (Adversary)
              |
     能力 ────┼──── 基础设施
              |
         受害者 (Victim)
```

| 维度 | 分析要点 |
|------|---------|
| 对手 | 归属国家、动机（间谍/破坏/经济）、能力等级 |
| 基础设施 | C2 服务器、域名注册、CDN/VPN、证书 |
| 能力 | 恶意软件、零日漏洞、TTP 复杂度 |
| 受害者 | 行业、地理、技术栈、安全成熟度 |

### Cyber Kill Chain 映射

| 阶段 | APT 行为 | 检测机会 |
|------|---------|--------|
| Reconnaissance | 目标侦察、OSINT | DNS 异常查询 |
| Weaponization | 漏洞利用+后门打包 | （难以检测） |
| Delivery | 钓鱼邮件/水坑/供应链 | 邮件网关、WAF |
| Exploitation | 触发漏洞/执行 | EDR/HIDS |
| Installation | 植入后门/Rootkit | 文件完整性监控 |
| C2 | 建立命令控制通道 | 网络流量分析 |
| Actions on Objectives | 数据窃取/破坏 | DLP/异常行为检测 |

## 与其他技能的关联

| 发现内容 | 调用技能 | 说明 |
|---------|---------|------|
| 可疑域名 | `domain-analysis` | 深入分析域名 |
| 可疑IP | `ip-analysis` | 分析IP归属 |
| 恶意样本 | `binary-reverse-engineering` | 逆向分析 |
| 钓鱼邮件 | `phishing-analysis` | 邮件分析 |
| 攻击技术归纳 | `ttp-extractor` | ATT&CK TTP 提取 |
| IR 取证 | `linux-ir` / `windows-ir` | 主机取证 |
| 生成报告 | `pdf-report` | PDF 威胁情报报告 |
| 认证日志分析 | `auth-log-analysis` | APT 登录行为检测 |
| 红队入侵模拟 | `redteam-intrusion-social` | 社工模拟 |
| 红队入侵模拟 | `redteam-intrusion-0day` | 0day 利用模拟 |

## 参考文件

- [references/apt_database.md](references/apt_database.md) — APT 组织数据库

## AI 建议

- 检测到 APT 活动后，立即将 IOC 同步到 `ip-analysis` 和 `domain-analysis` 进行实时查询
- 对归因结果保持谨慎 — APT 归因需要多源交叉验证，单一指标不足以确认
- 建议将分析结果通过 `pdf-report` 生成正式威胁情报报告，分发给安全团队
- 高置信度归因结果建议同步到 MISP 或其他威胁情报共享平台
