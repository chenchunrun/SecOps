---
name: redteam-recon-nation
description: 国家级目标情报收集。针对APT组织和国家级威胁行为者的情报分析。当用户要求"APT分析"、"国家级威胁"、"APT情报"、"国家黑客组织"、"地缘政治网络威胁"时使用此技能。
metadata:
  version: 1.0.0
  builtin: true
  category: redteam-recon
---

> ⚠️ **RED TEAM AUTHORIZATION REQUIRED**
>
> This skill falls under the `redteam:execute` capability gate.
>
> **Before executing ANY step in this skill, you MUST:**
> 1. State the skill name and a one-line summary of what you are about to do.
> 2. Ask the user to explicitly confirm authorization by typing **"已授权 / AUTHORIZED"**.
> 3. Ask the user to confirm the authorized scope (target, timeframe, rules of engagement).
> 4. Record the confirmation in your response before proceeding.
>
> **Do NOT proceed if:**
> - The user has not typed the authorization confirmation.
> - The target is outside the stated scope.
> - Any step would cause irreversible changes without a rollback plan.
>
> Violation of this gate is logged as a `security_alert` audit event.

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

## 与其他技能的关联

| 发现内容 | 调用技能 | 说明 |
|---------|---------|------|
| 可疑域名 | `/domain-analysis` | 深入分析域名 |
| 可疑IP | `/ip-analysis` | 分析IP归属 |
| 恶意样本 | `/binary-reverse-engineering` | 逆向分析 |
| 钓鱼邮件 | `/phishing-analysis` | 邮件分析 |