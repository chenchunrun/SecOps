---
name: redteam-recon-ngo
description: NGO组织攻击面侦察。针对非政府组织的攻击面测绘和社工预研。当用户要求"NGO渗透测试"、"非营利组织侦察"、"人权组织攻击面"、"媒体组织渗透"、"公民社会目标分析"时使用此技能。
metadata:
  version: 2.1.0
  builtin: true
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



# NGO 组织攻击面侦察

针对非政府组织进行攻击面测绘、邮箱收集、高价值目标识别和社工场景设计。

## 依赖要求

**Python 环境**: Python 3.8+

**核心依赖**:
```bash
pip3 install requests rich
```

**邮箱收集工具 (可选，增强功能)**:
```bash
pip3 install theHarvester crosslinked holehe
```

**环境检测**:
```bash
python3 scripts/check_env.py
```

## 执行超时说明

> ⚠️ **重要**: NGO 侦察涉及多个外部服务查询，需要较长执行时间，请耐心等待。

| 工具/阶段 | 默认超时 | 说明 |
|----------|---------|------|
| `ngo_recon.py` (完整) | **~10分钟** | 完整侦察流程 |
| theHarvester | **300s** (5分钟) | 邮箱收集，多数据源 |
| CrossLinked | **180s** (3分钟) | LinkedIn 员工枚举 |
| holehe | **60s** | 邮箱社交账号验证 |
| crt.sh 查询 | 30s | 证书透明度 |

**超时原因**：
- theHarvester 需要查询 40+ 数据源
- CrossLinked 需要搜索引擎爬取
- holehe 需要检测多个社交平台

## 核心能力

| 能力 | 工具 | 说明 |
|------|------|------|
| 子域名发现 | crt.sh | 证书透明度日志查询 |
| 邮箱收集 | theHarvester | 40+ 数据源邮箱/子域名收集 |
| 员工枚举 | CrossLinked | LinkedIn 员工信息收集 |
| 邮箱验证 | holehe | 社交账号关联验证 |
| 攻击面分析 | 本地脚本 | NGO 特有系统识别 |
| 目标画像 | 本地脚本 | 高价值人员识别 |
| 社工预研 | 本地脚本 | 钓鱼场景生成 |

## 工具矩阵

### 数据源 (无需 API Key)

| 工具 | 数据源 | 用途 |
|------|--------|------|
| crt.sh | 证书透明度 | 子域名发现 |
| theHarvester | crtsh, dnsdumpster, bing, baidu, anubis, hackertarget, rapiddns, urlscan | 邮箱/子域名 |
| CrossLinked | Google, Bing | LinkedIn 员工枚举 |
| holehe | 社交平台 API | 邮箱账号验证 |

### 使用示例

```bash
# 基础扫描
python3 scripts/ngo_recon.py -n "Target NGO" -d target-ngo.org

# 指定组织类型
python3 scripts/ngo_recon.py -n "Human Rights Org" -d hrorg.org --type human_rights

# 媒体组织
python3 scripts/ngo_recon.py -n "News Media" -d newsmedia.com --type media

# 输出 JSON
python3 scripts/ngo_recon.py -n "Target" -d target.org --json -o result.json

# 跳过特定工具
python3 scripts/ngo_recon.py -n "Target" -d target.org --skip-harvester
python3 scripts/ngo_recon.py -n "Target" -d target.org --skip-crosslinked
python3 scripts/ngo_recon.py -n "Target" -d target.org --skip-holehe

# 详细模式
python3 scripts/ngo_recon.py -n "Target" -d target.org -v
```

### 组织类型

| 类型 | 参数 | 攻击特点 |
|------|------|---------
| 人权组织 | `human_rights` | 国家级APT、商业间谍软件 |
| 新闻媒体 | `media` | 信源钓鱼、水坑攻击 |
| 环保组织 | `environmental` | 企业间谍、法律施压 |
| 人道援助 | `humanitarian` | 供应链攻击、财务欺诈 |
| 政治异见 | `political` | 零日漏洞、物理监控 |

---

## 工作流程

```
输入: 组织名称 + 域名 + 类型
     │
     ├─► Phase 1: 子域名发现
     │     └─► crt.sh 证书透明度
     │
     ├─► Phase 2: 邮箱收集 (theHarvester)
     │     └─► 免费数据源: crtsh, dnsdumpster, bing, baidu...
     │
     ├─► Phase 3: 员工枚举 (CrossLinked)
     │     └─► LinkedIn 员工信息 → 邮箱格式生成
     │
     ├─► Phase 4: 邮箱验证 (holehe)
     │     └─► 社交账号关联检测
     │
     ├─► Phase 5: 攻击入口识别
     │     ├─► 捐赠系统 (donate.*, give.*)
     │     ├─► 志愿者门户 (volunteer.*, join.*)
     │     ├─► 成员系统 (member.*, portal.*)
     │     └─► 邮件系统 (mail.*, webmail.*)
     │
     ├─► Phase 6: 高价值目标推断
     │     └─► 基于组织类型的关键角色
     │
     ├─► Phase 7: 钓鱼场景生成
     │     └─► 基于组织类型的定制话术
     │
     └─► Phase 8: 攻击计划生成
           └─► 输出: 完整侦察报告
```

---

## NGO 特有攻击面

### 高风险入口

| 攻击面 | 风险 | 攻击方法 |
|--------|------|---------
| 捐赠系统 | 🔴高 | 支付劫持、钓鱼页面、XSS |
| 志愿者门户 | 🔴高 | 账号枚举、弱口令、信息泄露 |
| 成员数据库 | 🔴极高 | SQL注入、未授权访问、备份泄露 |
| 邮件系统 | 🔴高 | 凭证钓鱼、BEC攻击、邮件劫持 |
| 协作平台 | 🟡中 | OAuth钓鱼、文档钓鱼、共享链接 |

### 高价值目标

| 组织类型 | 高价值目标 |
|---------|-----------|
| 人权组织 | 调查人员、律师、发言人 |
| 新闻媒体 | 调查记者、编辑、信源管理员 |
| 环保组织 | 活动组织者、科研人员、法务 |
| 人道援助 | 财务人员、物流协调、现场负责人 |
| 政治异见 | 领导层、联络员、技术支持 |

---

## 钓鱼场景库

### 通用场景

| 场景 | 话术要点 | 目标 | 载荷 |
|------|---------|------|------|
| 媒体采访 | 知名媒体记者请求专访 | 发言人 | 访谈提纲.docx |
| 国际会议 | 邀请参加高端论坛 | 领导层 | 会议议程.pdf |
| 大额捐赠 | 基金会捐赠意向 | 筹款人员 | 意向书.xlsx |
| 权限更新 | 共享文档需要重新授权 | 全员 | OAuth 钓鱼 |
| 安全警告 | 账号异常需验证 | 全员 | 凭证钓鱼 |

### 类型特定场景

| 组织类型 | 场景 | 话术 |
|---------|------|------|
| 人权组织 | 受害者求助 | "我是受害者，附上证词文档" |
| 新闻媒体 | 独家爆料 | "我有独家资料，通过安全渠道发送" |
| 环保组织 | 企业泄露 | "我是内部人员，有重要证据" |
| 人道援助 | 紧急物资 | "灾区急需物资，请确认采购清单" |
| 政治异见 | 安全警告 | "发现针对贵组织的监控活动" |

---

## 输出规范

### 侦察报告模板

```markdown
# NGO 攻击面侦察报告

**目标组织**: [名称]
**目标域名**: [域名]
**组织类型**: [类型]
**扫描时间**: [时间]

## 执行摘要

- 发现子域名: X 个
- 收集邮箱: X 个
- LinkedIn 员工: X 个
- 验证邮箱: X 个
- 攻击入口: X 个
- 高价值目标: X 个

## 邮箱收集结果

### theHarvester 收集
| 邮箱 | 数据源 |
|------|--------|
| user@target.org | crtsh |

### CrossLinked 员工
| 姓名 | 职位 | 生成邮箱 |
|------|------|----------|
| John Doe | Director | john.doe@target.org |

### holehe 验证结果
| 邮箱 | 关联平台 |
|------|----------|
| user@target.org | Twitter, LinkedIn |

## 攻击入口

| 子域名 | 类型 | 风险 | 攻击方法 |
|--------|------|------|----------|
| donate.target.org | 捐赠系统 | 高 | 支付劫持 |

## 高价值目标

| 角色 | 邮箱 | 优先级 |
|------|------|--------|
| 总监 | director@target.org | 高 |

## 推荐钓鱼场景

### 1. [场景名称]
- 话术: ...
- 目标: ...
- 载荷: ...

## 下一步行动

1. 深度资产扫描
2. 人员画像
3. 漏洞扫描
4. 钓鱼攻击
```

---

## 与其他技能的关联

### 输入来源

| 来源技能 | 产出 | 用途 |
|----------|------|------|
| `phishing-analysis` | 钓鱼基础设施 | 分析现有攻击 |
| `domain-analysis` | 可疑域名 | 关联分析 |

### 输出调用

| 发现内容 | 调用技能 | 说明 |
|---------|---------|------|
| 组织资产 | `/redteam-recon-enterprise` | 深度资产扫描 |
| 高价值人员 | `/redteam-recon-person` | 人员画像 |
| 邮箱地址 | `/email-osint` | 邮箱关联分析 |
| 攻击入口 | `/redteam-vulnscan` | 漏洞扫描 |
| 钓鱼场景 | `/redteam-socialeng` | 社工攻击执行 |

---

## 参考文件

- [references/report-format.md](references/report-format.md) - 报告格式规范