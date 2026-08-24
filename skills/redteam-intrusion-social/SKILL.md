---
name: redteam-intrusion-social
description: 社工钓鱼作战。社会工程学攻击策划和钓鱼内容构造。当用户要求"钓鱼攻击"、"社工攻击"、"钓鱼邮件"、"BEC攻击"、"钓鱼页面"、"社会工程"时使用此技能。仅限授权红队测试使用。
metadata:
  version: 1.2.0
  builtin: true
  category: redteam-intrusion
---

# 社工钓鱼作战

社会工程学攻击策划和钓鱼内容构造，用于授权红队演练。

> ⚠️ **法律警告**: 本技能仅适用于书面授权的安全测试。未经授权的社会工程学攻击是违法行为。

## 适用场景

**仅限授权测试**:
- 企业钓鱼演练
- 安全意识测试
- 红队社工攻击
- 安全培训素材

## MITRE ATT&CK 社会工程技术映射

社会工程学在 ATT&CK 框架中主要映射到 **TA0001 (Initial Access)** 战术，部分技术涉及 **TA0043 (Reconnaissance)**：

| ATT&CK ID | 技术名称 | 战术 | 社工场景 | 检测信号 |
|-----------|---------|------|---------|---------|
| **T1566** | Phishing | Initial Access | 鱼叉式钓鱼邮件投递 | 邮件网关异常附件/链接 |
| T1566.001 | Spearphishing Attachment | Initial Access | 携带恶意附件的定向邮件 | Office 宏启用、LNK 文件 |
| T1566.002 | Spearphishing Link | Initial Access | 包含恶意链接的邮件 | URL 重写检测、新注册域名 |
| T1566.003 | Spearphishing via Service | Initial Access | 通过 LinkedIn/微信等社交平台投递 | 第三方平台异常消息报告 |
| T1566.004 | Spearphishing Voice | Initial Access | 语音钓鱼 (Vishing) | 异常来电记录、转接模式 |
| T1566.005 | Spearphishing SMS | Initial Access | 短信钓鱼 (Smishing) | 短链接 + 伪基站检测 |
| T1566.006 | Spearphishing via Search | Initial Access | SEO 投毒引导用户 | 搜索引擎异常排名 |
| **T1656** | Impersonation | Initial Access | 冒充身份（供应商/IT/高管） | 身份验证异常、权限越界 |
| **T1564.008** | Hidden Domains | Defense Evasion | 注册相似域名进行欺骗 | DNS 混淆检测、typosquatting |
| **T1583.001** | Domains | Resource Development | 注册钓鱼域名 | 新注册域名监控、证书透明度 |
| **T1584.001** | Domains | Resource Development | 获取基础设施 | Whois 隐私保护 + 短TTL |
| **T1588.004** | Digital Signatures | Resource Development | 伪造代码签名证书 | 证书异常、撤销检查 |
| **T1204.002** | User Execution: File | Execution | 用户点击恶意附件 | 文件执行审计日志 |
| **T1204.001** | User Execution: Link | Execution | 用户点击恶意链接 | 浏览器导航日志 |

### ATT&CK 检测与 mitigations

**M1041** - Encrypt Sensitive Information
**M1047** - Audit Account Permissions
**M1054** - Software Configuration (邮件网关规则)
**M1017** - User Training (安全意识培训 — 最核心的社工防御)
**M1031** - Network Intrusion Prevention (URL 过滤)
**M1021** - Restrict Web-Based Content

## OWASP 社会工程关联

| OWASP 类别 | 社工关联 | 防御要点 |
|-----------|---------|---------|
| A01 Broken Access Control | 凭证钓鱼 → 越权访问 | 强制 MFA + 最小权限 |
| A04 Insecure Design | 缺乏反钓鱼机制 | 安全设计：邮件认证(SPF/DKIM/DMARC) |
| A07 Auth Failures | 钓鱼导致凭证泄露 | 无密码认证 + FIDO2 |
| A08 Software/Data Integrity | 供应链社工攻击 | 代码签名 + 供应商验证 |

## 攻击类型

### 1. 钓鱼邮件

| 类型 | 目标 | 成功率 | ATT&CK |
|------|------|-------|--------|
| 鱼叉式钓鱼 | 特定个人 | 高 | T1566.001/002 |
| BEC攻击 | 财务人员 | 高 | T1656 |
| 凭证收割 | 全员 | 中 | T1566.002 |
| 恶意附件 | 技术人员 | 中 | T1566.001 |

### 2. 语音钓鱼 (Vishing)

| 场景 | 话术要点 | ATT&CK |
|------|---------|--------|
| IT支持 | "您的账号需要验证" | T1566.004 |
| 供应商 | "发票需要确认" | T1656 |
| 高管助理 | "紧急会议变更" | T1656 |

### 3. 短信钓鱼 (Smishing)

| 场景 | 诱导方式 | ATT&CK |
|------|---------|--------|
| 快递通知 | "包裹无法投递" | T1566.005 |
| 银行警告 | "异常交易提醒" | T1566.005 |
| 验证码 | "您的验证码是..." | T1566.005 |

### 4. 社交媒体钓鱼

| 平台 | 手法 | ATT&CK |
|------|------|--------|
| LinkedIn | 伪装招聘/客户 | T1566.003 |
| 微信/钉钉 | 伪装同事/供应商 | T1566.003 |
| 邮件+电话 | 多渠道组合攻击 | T1566.004 + T1656 |

## 心理学原则

### 西奥迪尼六原则

| 原则 | 应用 | 示例 | 检测信号 |
|------|------|------|---------|
| 互惠 | 先给予再请求 | "免费资源分享" | 不期望的优惠/礼物 |
| 承诺一致 | 小请求升级 | "先看一下这个" | 逐步升级的请求链 |
| 社会认同 | 他人也在做 | "其他同事已完成" | 引用不存在的群体行为 |
| 喜好 | 建立好感 | 共同兴趣话题 | 过度友好的陌生人 |
| 权威 | 冒充权威 | "IT部门通知" | 紧急+权威组合 |
| 稀缺 | 制造紧迫 | "限时24小时" | 不合理的时间压力 |

### 心理学操纵模式（APTs 常用）

| 模式 | 描述 | 典型 APT 组织 |
|------|------|-------------|
| 情感操纵 | 利用恐惧/好奇/贪婪 | APT28 (Fancy Bear) |
| 紧急+权威 | 高管伪装+限时压力 | FIN7, TA505 |
| 上下文利用 | 热点事件/组织变更 | APT29 (Cozy Bear) |
| 信任建立 | 长期社交工程潜伏 | APT41 |

## 钓鱼邮件构造

### 邮件模板框架

```
发件人: [可信发件人]
主题: [引起注意的主题]

[称呼]

[背景说明 - 建立合理性]

[行动要求 - 明确指令]

[紧迫性 - 时间压力]

[签名 - 增强可信度]
```

### 高效主题示例

| 场景 | 主题 | 心理学触发器 |
|------|------|------------|
| IT安全 | "【紧急】您的账号将在24小时后停用" | 权威+稀缺 |
| 人事 | "年度绩效评估结果已发布" | 好奇 |
| 财务 | "报销审批：您提交的费用需要补充材料" | 承诺一致 |
| 合规 | "合规培训未完成提醒" | 权威 |
| 高管 | "CEO分享：Q4战略调整" | 权威+好奇 |

### 恶意附件策略

| 文件类型 | 伪装 | 触发方式 | ATT&CK |
|---------|------|---------|--------|
| Office宏 | 发票.xlsm | 启用宏 | T1204.002 |
| PDF | 合同.pdf | 打开即执行 | T1204.002 |
| LNK | 资料.lnk | 双击打开 | T1204.002 |
| ISO/IMG | 工具包.iso | 挂载打开 | T1204.002 + T1564.008 |

## 钓鱼页面设计

### 设计原则

1. **高度仿真** - 与真实页面一致
2. **SSL证书** - 必须有HTTPS（利用 Let's Encrypt）
3. **相似域名** - typosquatting / homoglyph
4. **移动适配** - 响应式设计（60%+ 从移动端访问）

### 域名策略

| 技术 | 示例 | 说明 | ATT&CK |
|------|------|------|--------|
| 同形字 | examp1e.com | 数字替代 | T1564.008 |
| 拼写变体 | exampel.com | 常见拼写错误 | T1583.001 |
| 子域名 | login.example.fake.com | 利用子域名 | T1564.008 |
| 顶级域 | example.co | 不同TLD | T1583.001 |
| Punycode | xn--e1awd.com | Unicode 同形字 | T1564.008 |

### 页面类型

| 类型 | 目标 | 收集信息 | IOC 类型 |
|------|------|---------|---------|
| 登录页面 | 凭证 | 用户名+密码 | URL 模式 |
| OAuth | Token | 授权码 | 重定向 URL |
| 表单 | 信息 | 个人/公司信息 | 表单字段 |
| 下载页 | 载荷 | 诱导下载 | 文件 Hash |

## Sigma 检测规则

### 钓鱼邮件检测 Sigma 规则示例

```yaml
title: Suspicious Phishing Email with Urgency Keywords
id: 7e3b4450-8d5a-4b1f-9c3a-6a2e8f1d4b5c
status: experimental
description: Detects phishing emails containing urgency and authority keywords
logsource:
    product: gateway
    service: email
detection:
    selection_keywords:
        subject|contains:
            - "urgent"
            - "account suspended"
            - "verify now"
            - "紧急"
            - "账户异常"
    selection_attachment:
        attachment|endswith:
            - ".xlsm"
            - ".docm"
            - ".lnk"
            - ".iso"
    condition: selection_keywords and selection_attachment
falsepositives:
    - Legitimate urgent communications
level: high
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.t1566.002
```

### BEC 检测 Sigma 规则示例

```yaml
title: Business Email Compromise Pattern
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects potential BEC attacks via impersonation patterns
logsource:
    product: gateway
    service: email
detection:
    external_domain:
        sender_domain|endswith:
            - ".co"
            - ".xyz"
            - ".top"
    financial_keywords:
        body|contains:
            - "wire transfer"
            - "payment urgent"
            - "invoice attached"
            - "银行转账"
            - "紧急付款"
    condition: external_domain and financial_keywords
falsepositives:
    - Legitimate financial communications
level: medium
tags:
    - attack.initial_access
    - attack.t1656
```

## 技术实现

### 发信基础设施

```bash
# 域名配置
# 1. 注册相似域名 (ATT&CK T1583.001)
# 2. 配置SPF记录
v=spf1 include:_spf.domain.com ~all

# 3. 配置DKIM
# 4. 配置DMARC
v=DMARC1; p=none; rua=mailto:dmarc@domain.com
```

### 钓鱼平台

| 工具 | 用途 | 特点 |
|------|------|------|
| Gophish | 邮件钓鱼 | 开源、全功能 |
| Evilginx2 | 中间人钓鱼 | 绕过2FA (T1556) |
| SocialFish | 社交钓鱼 | 简单易用 |
| King Phisher | 企业级 | 完整报告 |
| Modlishka | 反向代理钓鱼 | 动态页面 |

### GoPhish 配置示例

```bash
# 启动GoPhish
./gophish

# 访问管理界面
https://localhost:3333

# 配置步骤:
# 1. 创建发送配置 (Sending Profile)
# 2. 创建邮件模板 (Email Template)
# 3. 创建钓鱼页面 (Landing Page)
# 4. 创建目标组 (Users & Groups)
# 5. 启动活动 (Campaign)
```

## 规避技术

### 邮件网关绕过

| 检测机制 | 绕过方法 | 防御建议 |
|---------|---------|---------|
| SPF检查 | 配置正确的SPF | DMARC p=reject |
| 链接扫描 | 使用重定向/短链 | URL 重写 + 沙箱 |
| 附件扫描 | 密码保护ZIP | 文件类型白名单 |
| 内容检测 | 图片替代文字 | OCR 内容分析 |

### 安全软件规避

| 检测 | 绕过方法 | 防御建议 |
|------|---------|---------|
| 沙箱分析 | 延迟执行 | 行为分析 + 交互检测 |
| 行为检测 | 用户交互触发 | 监控宏执行链 |
| 签名检测 | 混淆处理 | 启发式 + YARA 规则 |

## IOC 采集要点

社工攻击产生的 IOC 类型：

| IOC 类型 | 采集来源 | 示例 | ATT&CK |
|---------|---------|------|--------|
| 域名 | DNS 日志、邮件头 | typosquatting 域名 | T1583.001 |
| IP | 发信IP、C2 IP | 新注册域名解析IP | T1584.006 |
| URL | 邮件正文、浏览器日志 | 钓鱼页面 URL | T1566.002 |
| 文件 Hash | 附件分析 | 宏文档 SHA256 | T1566.001 |
| 发件人地址 | 邮件头 | 仿冒邮箱地址 | T1656 |
| 社交账号 | 平台报告 | 伪装招聘账号 | T1566.003 |

## 输出规范

### 社工作战计划

```markdown
# 社工作战计划

## 目标概况
- 目标组织: [组织名]
- 目标人员: [人数/角色]
- 演练目标: 凭证收割 / 载荷投递
- ATT&CK 技术映射: T1566.002, T1204.001

## 场景设计
- 伪装身份: [IT支持/供应商等]
- 钓鱼主题: [主题]
- 紧迫因素: [时间限制]
- 心理学原理: [权威+稀缺]

## 技术方案
- 发信域名: [域名] (T1583.001)
- 钓鱼页面: [URL] (T1566.002)
- 载荷类型: [如有] (T1566.001)

## 邮件模板
[完整邮件内容]

## 时间计划
- 发送时间: [选择高响应时段]
- 持续时间: [活动周期]

## 成功指标
- 打开率目标: X%
- 点击率目标: X%
- 凭证收割目标: X%

## 防御建议（报告交付时附）
- M1017: 安全意识培训
- M1054: 邮件网关强化规则
- M1031: URL 过滤
```

## 合规与法律参考

| 标准 | 相关条款 | 要求 |
|------|---------|------|
| GDPR | Art. 32 | 安全措施有效性测试 |
| PIPL | 第55条 | 个人信息处理安全评估 |
| ISO 27001 | A.6.3 | 安全意识培训和教育 |
| ISO 27001 | A.12.6 | 技术漏洞管理 |
| PCI DSS | 12.6 | 安全意识计划 |
| NIST CSF | PR.AT | 安全意识培训 |

## YARA 规则

### YARA 规则 1: 钓鱼载荷检测 (Office Macro + Shell Execution)

```yara
rule Social_Engineering_Malicious_Payload {
    meta:
        description = "Detects payloads commonly delivered via social engineering attacks"
        author = "SecSkill Evolution"
        date = "2026-06-24"
        reference = "ATT&CK T1566.001, T1204.002"
    strings:
        $ole_header = { D0 CF 11 E0 A1 B1 1A E1 }
        $vba_autoopen = "AutoOpen" ascii nocase
        $vba_docopen = "Document_Open" ascii nocase
        $powershell = "powershell" ascii nocase
        $cmd = "cmd.exe" ascii nocase
        $wscript = "WScript.Shell" ascii nocase
        $download = "MSXML2.XMLHTTP" ascii nocase
        $shell_cmd = "/c " ascii
        $enc_ps = "-enc " ascii nocase
    condition:
        $ole_header at 0 and any of ($vba_*) and 1 of ($powershell, $cmd, $wscript)
}
```

### YARA 规则 2: BEC 钓鱼模板特征

```yara
rule Social_Engineering_BEC_Template {
    meta:
        description = "Detects BEC phishing email templates with financial fraud patterns"
        author = "SecSkill Evolution"
        date = "2026-06-24"
        reference = "ATT&CK T1656, T1566.002"
    strings:
        $wire_transfer = "wire transfer" ascii nocase
        $urgent_payment = "urgent payment" ascii nocase
        $invoice_attached = "invoice attached" ascii nocase
        $ceo_request = "CEO request" ascii nocase
        $bank_change = "bank account change" ascii nocase
        $wire_zh = "银行转账" ascii
        $urgent_zh = "紧急付款" ascii
        $invoice_zh = "发票" ascii
        $redirect_url = "https://" ascii
        $attachment_flag = "attachment" ascii nocase
    condition:
        2 of ($wire_*, $urgent_*, $invoice_*, $ceo_*, $bank_*, $wire_zh, $urgent_zh, $invoice_zh)
}
```

---

## CVE 参考表

社工攻击中高频利用的 CVE 及其在钓鱼场景中的应用：

| CVE ID | 漏洞名称 | CVSS | ATT&CK | 社工场景 |
|--------|---------|------|--------|----------|
| CVE-2023-23397 | Outlook EoP (零点击) | 9.8 | T1566.001 | BEC 攻击中零点击触发、目标无感知 |
| CVE-2022-30190 | Follina (MSDT RCE) | 7.8 | T1566.001 | 鱼叉邮件附件触发 ms-msdt 协议执行 |
| CVE-2021-40444 | MSHTML RCE | 8.8 | T1566.001 | 伪装合同/发票文档加载恶意 ActiveX |
| CVE-2023-36884 | Office HTML RCE | 8.3 | T1566.001 | 邮件附件远程加载 HTML 内容执行 |
| CVE-2017-11882 | Equation Editor RCE | 8.8 | T1566.001 | 经典社工载荷、伪装财务报表 |

---

## 跨技能生态工作流（扩展）

| 场景 | 上游技能 → 本技能 → 下游技能 | 数据流 |
|------|-------------------------------|--------|
| 红队社工演练 | email-osint → **redteam-intrusion-social** → ttp-extractor | 目标画像 → 钓鱼设计 → TTP 提取 |
| BEC 检测 | brand-impersonation → **redteam-intrusion-social** → auth-log-analysis | 品牌仿冒检测 → BEC 识别 → 凭证异常监控 |
| 钓鱼演练报告 | redteam-recon-person → **redteam-intrusion-social** → pdf-report | 个人侦察 → 钓鱼执行 → 演练报告 |
| 跨渠道社工 | redteam-recon-enterprise → **redteam-intrusion-social** → phishing-analysis | 企业侦察 → 多渠道钓鱼 → 钓鱼检测验证 |
| 意识培训评估 | redteam-recon-ngo → **redteam-intrusion-social** → data-desensitize | NGO 侦察 → 钓鱼演练 → 数据脱敏处理 |

---

## 法律边界

**必须遵守**:
- 书面授权（范围、时间、目标明确）
- 范围限定（不超出授权边界）
- 数据保护（不保留敏感凭证）
- 及时报告（发现真实威胁立即通报）

**禁止行为**:
- 超出授权范围
- 保留敏感凭证
- 对外部目标攻击
- 造成实际损害

## 跨技能生态工作流

| 场景 | 上游技能 | 本技能 | 下游技能 |
|------|---------|-------|---------|
| 红队社工 | email-osint (目标画像) | 钓鱼设计 | ttp-extractor (TTP 提取) |
| 演练报告 | brand-impersonation (域名检测) | 钓鱼执行 | pdf-report (演练报告) |
| 防御验证 | redteam-recon-person (个人信息) | 社交工程 | auth-log-analysis (凭据异常检测) |

## 命令速查

```bash
# 钓鱼邮件分析
python scripts/social_attack_analyzer.py -f email.eml
python scripts/social_attack_analyzer.py -t "邮件文本内容" --json

# BEC 模式检测
python scripts/bec_detector.py -f email.eml
python scripts/bec_detector.py --sender "ceo@fake-domain.co" --body "urgent wire transfer"

# 演练报告生成
python scripts/social_attack_analyzer.py -f email.eml --json | \
  python scripts/campaign_report.py --template redteam --output report.md
```
