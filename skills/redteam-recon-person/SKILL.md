---
name: redteam-recon-person
description: 个人目标情报收集。针对特定个人的OSINT收集和社工画像分析。当用户要求"人物画像"、"个人情报"、"OSINT调查"、"社工预研"、"VIP安全评估"、"高管风险评估"时使用此技能。
metadata:
  version: 2.0.0
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