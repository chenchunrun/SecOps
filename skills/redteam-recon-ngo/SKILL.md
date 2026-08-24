---
name: redteam-recon-ngo
description: NGO组织攻击面侦察。针对非政府组织的攻击面测绘和社工预研。当用户要求"NGO渗透测试"、"非营利组织侦察"、"人权组织攻击面"、"媒体组织渗透"、"公民社会目标分析"时使用此技能。
metadata:
  version: 2.2.0
  builtin: true
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

## ATT&CK 技术映射表

NGO 侦察活动覆盖 ATT&CK 矩阵的 Reconnaissance 和其他战术。以下映射指导侦察活动的技术覆盖范围：

### Reconnaissance 战术 (TA0043)

| ATT&CK ID | 技术名称 | 子技术 | NGO侦察应用场景 |
|-----------|---------|--------|----------------|
| T1592 | 收集受害者主机信息 | - | 识别NGO使用的CMS、框架、服务器技术栈 |
| T1592.002 | 收集受害者OS信息 | OS指纹 | 识别组织使用的操作系统和版本 |
| T1592.004 | 收集受害者客户端配置 | 浏览器/插件 | 识别组织内部使用的浏览器配置 |
| T1589 | 收集受害者身份信息 | - | 收集NGO员工姓名、职位、邮箱 |
| T1589.001 | 凭据 | 邮箱地址收集 | theHarvester/crt.sh 邮箱枚举 |
| T1589.002 | 邮箱地址 | 邮箱格式推测 | CrossLinked LinkedIn→邮箱格式 |
| T1589.003 | 员工姓名 | 人员枚举 | LinkedIn 员工列表收集 |
| T1590 | 收集受害者组织信息 | - | NGO组织结构、部门、合作伙伴 |
| T1590.002 | 组织关系 | 合作关系 | 识别NGO的捐赠方、合作机构 |
| T1590.003 | 商业限制 | 注册信息 | 查询组织注册数据 |
| T1590.004 | 确定能力 | 技术能力 | 评估NGO的安全防护水平 |
| T1590.005 | 组织部门 | 部门架构 | 识别关键部门和职能团队 |
| T1591 | 收集受害者公开信息 | - | 社交媒体、新闻稿、年报 |
| T1591.001 | 社交媒体 | 社交画像 | Facebook/Twitter/LinkedIn 公开信息 |
| T1591.002 | 搜索可攻击的公开资料 | 诱饵设计 | 收集钓鱼话术素材 |
| T1593 | 搜索开放技术数据库 | - | crt.sh 证书透明度、DNS记录 |
| T1593.002 | WHOIS | 域名注册 | WHOIS 查询组织域名信息 |
| T1595 | 主动扫描 | - | NGO外部资产端口扫描 |
| T1595.001 | 扫描IP段 | IP发现 | 扫描组织拥有的IP段 |
| T1595.002 | 漏洞扫描 | 漏洞识别 | 对NGO外部服务进行漏洞扫描 |
| T1595.003 | Wordlist扫描 | 目录爆破 | 对Web服务进行目录和文件枚举 |
| T1596 | 搜索开放域数据库 | - | Shodan/Censys 搜索暴露服务 |
| T1596.001 | DNS被动DNS | 域名历史 | 被动DNS查询历史解析记录 |
| T1596.002 | DNS子域名 | 子域名 | 通过DNS枚举发现子域名 |

### Initial Access 战术 (TA0001)

| ATT&CK ID | 技术名称 | 子技术 | NGO侦察应用场景 |
|-----------|---------|--------|----------------|
| T1566 | 钓鱼 | - | 基于侦察结果设计定向钓鱼 |
| T1566.001 | 鱼叉式钓鱼附件 | 恶意文档 | 媒体采访邀请.docx 等社工载荷 |
| T1566.002 | 鱼叉式钓鱼链接 | 恶意链接 | 伪造OAuth登录页面 |
| T1566.003 | 鱼叉式钓鱼服务 | 社交平台 | 通过LinkedIn/WhatsApp建立信任 |

### Command and Control 战术 (TA0011)

| ATT&CK ID | 技术名称 | 子技术 | NGO侦察应用场景 |
|-----------|---------|--------|----------------|
| T1071 | 应用层协议 | - | 识别NGO网络出站协议（用于C2规划） |
| T1071.001 | Web协议 | HTTP/HTTPS | 捐赠平台/门户网站的Web协议分析 |
| T1105 | 入口工具传输 | - | 识别可利用的文件传输通道 |

### Collection 战术 (TA0009)

| ATT&CK ID | 技术名称 | 子技术 | NGO侦察应用场景 |
|-----------|---------|--------|----------------|
| T1583 | 建立基础设施 | - | 准备钓鱼域名和C2基础设施 |
| T1583.001 | 域名 | 仿冒域名 | 注册与NGO相似的钓鱼域名 |
| T1583.002 | DNS服务器 | DNS基础设施 | 建设C2 DNS解析 |
| T1584 | 入口基础设施 | - | 评估NGO现有基础设施可利用性 |

### ATT&CK 缓解措施参考

| Mitigation ID | 名称 | 侦察阶段应用 |
|---------------|------|-------------|
| M1056 | 预认证防御 | 防御邮箱枚举，启用MFA |
| M1018 | 账户管理 | 监控异常账户查询行为 |
| M1041 | 加密敏感信息 | 保护成员数据库和通信 |
| M1031 | 网络入侵防护 | 检测和阻断主动扫描 |
| M1021 | 限制Web基于主机的元数据 | 防止服务器指纹泄露 |

---

## OWASP Top 10 映射

NGO 侦察关注的外部资产 OWASP 风险类别：

| OWASP 类别 | 相关风险 | NGO侦察应用 |
|-----------|---------|------------|
| A01:2021 - Broken Access Control | 成员系统未授权访问 | 捐赠/成员系统权限测试 |
| A02:2021 - Cryptographic Failures | 传输加密不足 | 识别HTTP明文服务 |
| A03:2021 - Injection | SQL注入/XSS | 捐赠系统支付参数注入 |
| A04:2021 - Insecure Design | 业务逻辑缺陷 | 捐赠流程逻辑绕过 |
| A05:2021 - Security Misconfiguration | 默认配置/信息泄露 | 子域名服务配置审计 |
| A07:2021 - Identification and Authentication Failures | 弱口令/账号枚举 | 志愿者门户凭证测试 |
| A08:2021 - Software and Data Integrity Failures | 供应链风险 | 第三方捐赠插件分析 |
| A09:2021 - Security Logging and Monitoring Failures | 日志缺失 | 评估NGO安全监控能力 |

### CWE 关联映射

| CWE ID | 名称 | ATT&CK 关联 |
|--------|------|-------------|
| CWE-200 | 信息暴露 | T1592/T1590 信息收集 |
| CWE-204 | 可观察行为差异 | T1589 用户枚举 |
| CWE-302 | 数据认证完整性缺失 | T1566 钓鱼防御 |
| CWE-532 | 日志文件信息泄露 | T1593 开放数据库搜索 |
| CWE-538 | 敏感信息插入外部可访问文件 | T1591 公开信息收集 |
| CWE-601 | 开放重定向 | T1566.002 钓鱼链接 |

---

## Sigma 检测规则

### 规则 1: 异常子域名枚举行为检测

```yaml
title: 异常DNS子域名枚举行为 - 可能的NGO侦察活动
id: 7a3c1f2e-8b9d-4e6f-a012-3456789abcde
status: experimental
description: 检测同一源IP短时间内对特定NGO域名进行大量子域名查询，可能指示侦察阶段的DNS枚举
references:
    - https://attack.mitre.org/techniques/T1593/002/
    - https://attack.mitre.org/techniques/T1596/001/
tags:
    - attack.reconnaissance
    - attack.t1593.002
    - attack.t1596.001
logsource:
    product: dns
    category: dns_query
detection:
    selection:
        query|contains:
            - donate
            - member
            - volunteer
            - portal
            - admin
            - mail
            - webmail
    timeframe: 10m
    condition: selection | count(src_ip) > 50
falsepositives:
    - 合法DNS监控服务
    - 安全扫描器（需白名单）
    - CDN健康检查
level: medium
```

### 规则 2: LinkedIn自动化枚举行为检测

```yaml
title: LinkedIn自动化员工枚举 - 可能的NGO目标侦察
id: 8b4d2e3f-9c0e-4f7a-b123-456789abcdef
status: experimental
description: 检测可能的LinkedIn自动化爬取行为，通常用于NGO员工枚举和邮箱格式推测
references:
    - https://attack.mitre.org/techniques/T1589/003/
    - https://attack.mitre.org/techniques/T1591/001/
tags:
    - attack.reconnaissance
    - attack.t1589.003
    - attack.t1591.001
logsource:
    product: proxy
    category: web_activity
detection:
    selection_domain:
        url|contains:
            - linkedin.com
            -linkedin.com/in/
            -linkedin.com/company/
    selection_pattern:
        - "|uri|re|/in/[a-z]+-[a-z]+-$|"
    timeframe: 30m
    condition: selection_domain and selection_pattern | count(src_ip) > 20
falsepositives:
    - HR招聘活动
    - 销售团队客户搜索
level: low
```

---

## CVE 参考表

NGO 常用平台的高危 CVE 参考：

| CVE ID | 受影响系统 | CVSS | NGO影响场景 |
|--------|-----------|------|------------|
| CVE-2024-23692 | Rocket.Chat (NGO常用Slack替代) | 9.8 | 成员系统RCE，捐赠平台渗透 |
| CVE-2023-3460 | Ultimate Member插件 (WordPress) | 9.8 | 成员系统权限提升 |
| CVE-2024-27956 | WordPress Automatic插件 | 9.9 | NGO新闻站点RCE |
| CVE-2023-20198 | Cisco IOS XE | 10.0 | NGO网络设备入侵 |
| CVE-2024-3094 | XZ Utils 后门 | 10.0 | NGO服务器供应链攻击 |

---

## IOC 采集指引

侦察过程中应收集以下 IOC 指标，供后续防御和分析使用：

### 高优先级 IOC

| IOC 类型 | 采集目标 | 格式 | 用途 |
|---------|---------|------|------|
| 邮箱地址 | theHarvester/CrossLinked 收集 | user@ngo.org | 钓鱼目标列表、凭据检测 |
| 子域名 | crt.sh/DNS枚举 | sub.ngo.org | 攻击面映射、证书监控 |
| 员工姓名 | LinkedIn 公开信息 | First Last | 邮箱推测、社工剧本 |
| 社交账号 | holehe 验证结果 | platform:user | 社交工程、身份伪造 |
| 技术栈指纹 | HTTP响应头/页面源码 | CMS:X.X | 漏洞匹配、利用规划 |
| 开放端口 | Nmap 扫描结果 | port:service:banner | 服务漏洞利用 |

### 中优先级 IOC

| IOC 类型 | 采集目标 | 格式 | 用途 |
|---------|---------|------|------|
| SSL证书信息 | crt.sh 查询 | issuer:subject:dates | 基础设施关联分析 |
| DNS记录 | A/MX/TXT/SPF/DMARC | record_type:value | 邮件安全评估、子域名发现 |
| WHOIS信息 | 域名注册查询 | registrar:dates:contact | 组织规模和时间线分析 |
| Web应用指纹 | Wappalyzer/WhatWeb | app:version | 漏洞数据库匹配 |
| 目录结构 | DirBuster/Gobuster | /path:status_code | 隐藏管理面板发现 |
| 外部链接 | 页面爬虫分析 | url:anchor_text | 合作伙伴关系映射 |

---

## 合规标准参考表

NGO 侦察活动涉及以下合规框架：

| 标准 | 相关条款 | 适用场景 |
|------|---------|---------|
| GDPR Art. 4(1) | 个人数据定义 | 邮箱/姓名属于个人数据，侦察活动需合法授权 |
| GDPR Art. 6 | 合法处理依据 | 渗透测试需获得明确书面授权 |
| PIPL 第十三条 | 个人信息处理规则 | 中国NGO个人信息处理的合法性基础 |
| PIPL 第二十六条 | 敏感个人信息 | 调查人员/异见人士信息属于敏感数据 |
| ISO 27001 A.12.6 | 技术漏洞管理 | 漏洞扫描需在授权范围内 |
| ISO 27001 A.5.13 | 信息 labeling | NGO报告需标密控制分发 |
| NIST SP 800-115 | 技术安全测试指南 | 渗透测试方法论参考 |
| NIST SP 800-53 RA-3 | 风险评估 | 授权侦察的范围界定 |
| 等保2.0 第八章 | 网络通信安全 | NGO系统安全评估标准 |
| EU NIS2 Directive | 关键基础设施安全 | 部分大型NGO属于必要/重要实体 |
| Council of Europe Convention 185 | 布达佩斯公约 | 跨境网络犯罪调查合作 |
| Universal Declaration HR Art. 12 | 隐私权 | NGO成员隐私保护的人权基础 |

---

## 跨技能工作流

### 工作流 1: NGO完整攻击面评估

```
cyberspace-search (初始搜索)
    ↓
redteam-recon-ngo (组织侦察)
    ↓
redteam-recon-enterprise (深度资产扫描)
    ↓
redteam-recon-person (关键人员画像)
    ↓
phishing-analysis (钓鱼载荷设计)
    ↓
ttp-extractor (TTP提取与检测规则生成)
```

### 工作流 2: NGO钓鱼演练

```
redteam-recon-ngo (目标侦察+场景生成)
    ↓
email-osint (邮箱验证与关联)
    ↓
domain-analysis (钓鱼域名评估)
    ↓
phishing-analysis (钓鱼执行与分析)
```

### 工作流 3: APT追踪-NGO定向攻击分析

```
redteam-recon-ngo (NGO攻击面基线)
    ↓
windows-ir / macos-ir (终端IR检测)
    ↓
traffic-analysis (网络流量分析)
    ↓
ttp-extractor (APT TTP映射)
    ↓
pdf-report (综合报告生成)
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

### 国家级 APT 对 NGO 的典型攻击模式

| APT 组织 | 目标NGO类型 | 常用技术 | 参考 CVE |
|---------|------------|---------|----------|
| APT28 (Fancy Bear) | 人权/政治组织 | T1566.001 鱼叉钓鱼 + 0day | CVE-2024-3094 |
| NSO Group (Pegasus) | 人权/媒体组织 | T1566.003 零点击IM漏洞 | CVE-2021-30860 |
| APT41 | 多种NGO | T1190 应用漏洞利用 | CVE-2023-20198 |
| Bahamut | 媒体/异见组织 | T1583.001 仿冒域名钓鱼 | - |
| DarkHydrus | 中东NGO | T1566.001 恶意文档 | CVE-2024-27956 |

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
| `cyberspace-search` | 初始情报 | 搜索NGO公开信息 |

### 输出调用

| 发现内容 | 调用技能 | 说明 |
|---------|---------|------|
| 组织资产 | `/redteam-recon-enterprise` | 深度资产扫描 |
| 高价值人员 | `/redteam-recon-person` | 人员画像 |
| 邮箱地址 | `/email-osint` | 邮箱关联分析 |
| 攻击入口 | `/researching-vulnerabilities` | 漏洞研究 |
| 钓鱼场景 | `/phishing-analysis` | 钓鱼分析 |
| 安全事件 | `/ttp-extractor` | TTP提取 |
| 综合报告 | `/pdf-report` | 报告生成 |

---

## 参考文件

- [references/report-format.md](references/report-format.md) - 报告格式规范
