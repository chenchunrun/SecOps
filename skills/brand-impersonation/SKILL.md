---
name: brand-impersonation
description: 品牌仿冒与钓鱼域名监控。当用户要求"品牌仿冒检测"、"钓鱼域名监控"、"相似域名发现"、"仿冒网站检测"、"品牌保护"、"域名抢注监控"、"同形字攻击检测"、"Typosquatting检测"时使用此技能。
metadata:
  version: 1.1.0
  builtin: true
---

# 品牌仿冒监控技能

## 依赖要求

**Python 版本**: 3.8+

**外部 MCP 服务**:
| MCP | 工具 | 用途 |
|------|------|------|
| cybersec-cloud | cybersec_cloud_mcp_cyberspace-search | 仿冒域名搜索 |
| cybersec-cloud | cybersec_cloud_mcp_risk_insight | 域名威胁情报 |
| cybersec-cloud | cybersec_cloud_mcp_intel_icp_lookup | 备案信息对比 |

**可选依赖**:
```bash
pip install python-whois dnspython idna confusables
```

## 快速使用

```bash
# 同形字检测
python scripts/homograph_detector.py "apple.com" --brand-check

# CT Logs 监控
curl -s "https://crt.sh/?q=%.apple.com&output=json" | python scripts/ct_monitor.py

# 相似域名生成
python scripts/typo_generator.py "example.com"
```

## 监控工作流

### Phase 1: 品牌资产定义

#### 1.1 核心资产清单

| 资产类型 | 示例 | 说明 |
|----------|------|------|
| 主域名 | example.com | 官网域名 |
| 品牌名 | Example Inc | 企业名称 |
| 产品名 | ExampleApp | 产品品牌 |
| 商标 | EXAMPLE | 注册商标 |
| 高管姓名 | John CEO | 高管姓名 |

#### 1.2 品牌关键词

```
主关键词: example
变体: examp1e, exampl3, exampie
音似: egzample
缩写: exmpl, ex
组合: example-app, myexample, get-example
```

### Phase 2: 仿冒域名发现

#### 2.1 同形字攻击检测 (Homograph)

**原理**: 使用视觉相似的 Unicode 字符替换

| 正常字符 | 同形字符 | Unicode |
|----------|----------|---------|
| a | а (西里尔) | U+0430 |
| e | е (西里尔) | U+0435 |
| o | о (西里尔) | U+043E |
| p | р (西里尔) | U+0440 |
| c | с (西里尔) | U+0441 |
| x | х (西里尔) | U+0445 |
| i | і (乌克兰) | U+0456 |
| l | 1 (数字) | U+0031 |

**检测方法**:
```bash
python scripts/homograph_detector.py "аpple.com"
# 输出: 检测到同形字攻击
# 伪造: аpple.com (包含西里尔字母 а)
# 目标: apple.com
```

#### 2.2 打字错误域名 (Typosquatting)

| 类型 | 示例 (针对 example.com) |
|------|-------------------------|
| 遗漏字母 | examle.com, exmple.com |
| 重复字母 | examplle.com, exxample.com |
| 相邻键误触 | rxample.com, ezample.com |
| 字母互换 | exapmle.com, examlpe.com |
| 添加字母 | examplea.com, exsample.com |
| 常见拼写 | exampel.com |

**生成脚本**:
```bash
python scripts/typo_generator.py "example.com" --all
```

#### 2.3 组合域名

| 类型 | 模式 | 示例 |
|------|------|------|
| 前缀添加 | {prefix}-{brand} | secure-example.com |
| 后缀添加 | {brand}-{suffix} | example-login.com |
| 子域伪装 | {brand}.{random} | example.com.attacker.xyz |
| TLD 变换 | {brand}.{tld} | example.net, example.xyz |

**常见恶意前后缀**:
```
前缀: secure-, login-, account-, verify-, update-, support-
后缀: -login, -secure, -support, -verify, -update, -account
```

### Phase 3: 证书透明度监控

#### 3.1 CT Logs 查询

```bash
# 查询所有包含品牌名的证书
curl -s "https://crt.sh/?q=%25example%25&output=json" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for cert in data:
    issuer = cert.get('issuer_name', '')
    name = cert.get('name_value', '')
    not_before = cert.get('not_before', '')
    print(f'{not_before} | {name}')
" | sort -r | head -50
```

#### 3.2 新证书告警

监控维度：
- 新颁发的包含品牌名的证书
- 免费证书（Let's Encrypt）- 钓鱼常用
- 短有效期证书
- 非官方签发的证书

**告警规则**:
| 条件 | 风险等级 |
|------|----------|
| 精确匹配品牌名 + 非官方 | 高 |
| 包含品牌 + 可疑 TLD | 高 |
| 同形字品牌 | 高 |
| 品牌 + 敏感词 (login/secure) | 中 |

### Phase 4: 网络空间搜索

#### 4.1 相似域名搜索

```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询语法:
- title="Example" && -hostname="example.com"  # 标题包含品牌但非官方
- hostname="*example*" && -hostname="example.com"  # 域名包含品牌
- body="Example Inc" && -hostname="example.com"  # 正文包含公司名
```

#### 4.2 钓鱼页面特征

| 特征 | 检测方法 |
|------|----------|
| 官网内容复制 | body 相似度对比 |
| Logo 相同 | 图片哈希对比 |
| 登录表单 | 表单元素检测 |
| HTTPS 证书 | 证书主体不匹配 |

### Phase 5: 威胁评估

#### 5.1 风险评分

| 维度 | 权重 | 评估标准 |
|------|------|----------|
| 域名相似度 | 30% | 编辑距离/同形字 |
| 域名年龄 | 20% | 新注册=高风险 |
| 证书状态 | 15% | Let's Encrypt=中风险 |
| 网站内容 | 25% | 是否有登录表单 |
| 托管位置 | 10% | 防弹托管=高风险 |

#### 5.2 风险等级

| 分数 | 等级 | 行动 |
|------|------|------|
| 80-100 | 高危 | 立即下架请求 |
| 50-79 | 中危 | 持续监控 + 预警 |
| 20-49 | 低危 | 记录备案 |
| 0-19 | 安全 | 忽略 |

### Phase 6: 仿冒确认

#### 6.1 人工验证清单

| 检查项 | 方法 |
|--------|------|
| 页面内容 | 截图对比官网 |
| 登录功能 | 是否有凭证收集 |
| 联系信息 | 是否使用官方联系方式 |
| ICP 备案 | 备案主体是否一致 |
| WHOIS | 注册人是否官方 |

#### 6.2 证据收集

```bash
# 截图保存
# 网页内容存档
curl -s "https://phishing-site.com" > evidence/page.html

# WHOIS 记录
whois phishing-site.com > evidence/whois.txt

# DNS 记录
dig phishing-site.com ANY > evidence/dns.txt
```

### Phase 7: 响应处置

#### 7.1 处置方式

| 方式 | 适用场景 | 时效 |
|------|----------|------|
| 域名注册商投诉 | 明确侵权 | 1-7天 |
| 托管商投诉 | 恶意内容 | 1-3天 |
| 证书吊销请求 | 恶意证书 | 1-3天 |
| 浏览器黑名单 | 钓鱼确认 | 即时 |
| 搜索引擎下架 | SEO 钓鱼 | 1-5天 |

#### 7.2 投诉模板

```
Subject: Phishing/Brand Impersonation Report - {domain}

Dear Abuse Team,

We are reporting a domain that is impersonating our brand:

Infringing Domain: {phishing_domain}
Official Domain: {official_domain}
Evidence: [screenshots, content comparison]

This domain is being used for phishing attacks targeting our customers.

We request immediate suspension of this domain.

Best regards,
{Company} Security Team
```

### Phase 8: 持续监控

#### 8.1 监控频率

| 资产类型 | 频率 | 方法 |
|----------|------|------|
| 核心品牌 | 实时 | CT Logs 订阅 |
| 产品名 | 每日 | 定时搜索 |
| 高管姓名 | 每周 | 社交监控 |

#### 8.2 告警规则

```yaml
rules:
  - name: "核心品牌仿冒"
    condition:
      - domain_contains: "example"
      - not_official: true
      - age_days: < 30
    severity: high
    action: immediate_alert

  - name: "相似域名注册"
    condition:
      - similarity: > 0.8
      - age_days: < 7
    severity: medium
    action: daily_report
```

## 工具命令速查

| 任务 | 命令 |
|------|------|
| 同形字检测 | `python scripts/homograph_detector.py "domain"` |
| 打字错误生成 | `python scripts/typo_generator.py "domain"` |
| CT Logs 查询 | `curl "https://crt.sh/?q=%brand%&output=json"` |
| 网空搜索 | `cybersec_cloud_mcp_cyberspace-search: title="Brand"` |
| WHOIS 查询 | `whois domain.com` |
| 截图存证 | 浏览器截图或 headless |

## 输出格式

### 仿冒域名清单

```csv
仿冒域名,类型,相似度,注册时间,IP,风险等级,状态
examp1e.com,同形字,95%,2024-01-01,1.2.3.4,高,待处置
example-login.com,组合,80%,2024-01-02,5.6.7.8,中,监控中
```

### 监控报告

```markdown
# 品牌仿冒监控日报

**品牌**: Example Inc
**监控周期**: 2024-01-01

## 新发现

| 域名 | 类型 | 风险 |
|------|------|------|
| examp1e.com | 同形字 | 高 |

## 处置进展

| 域名 | 状态 | 更新 |
|------|------|------|
| fake-example.com | 已下架 | 2024-01-01 |

## 统计

- 监控域名: 150
- 新发现: 3
- 处置中: 5
- 已下架: 12
```

## MITRE ATT&CK 技术映射

品牌仿冒攻击覆盖以下 ATT&CK 战术和技术：

### 战术覆盖

| 战术 | ID | 仿冒场景 |
|------|-----|---------|
| Initial Access | TA0001 | 钓鱼网站获取凭证 |
| Credential Access | TA0006 | 伪造登录页面收集凭证 |
| Defense Evasion | TA0005 | 同形字域名绕过检测 |
| Collection | TA0009 | 收集用户输入的敏感信息 |

### 技术映射表

| ATT&CK 技术 | 子技术 | 仿冒攻击场景 |
|-------------|--------|------------|
| T1566.002 | Phishing: Spearphishing Link | 钓鱼链接指向仿冒网站 |
| T1566.005 | Phishing: Spearphishing Link (Phone) | 短信钓鱼指向仿冒页面 |
| T1189 | Drive-by Compromise | 恶意广告引导至仿冒站 |
| T1071.001 | Application Layer Protocol: Web | 仿冒网站 HTTP 通信 |
| T1556.001 | Modify Authentication Process: Password | 伪造登录表单窃取密码 |
| T1119 | Automated Collection | 自动化收集提交的凭证 |
| T1650 | Acquire Infrastructure | 注册仿冒域名/SSL证书 |
| T1583.001 | Acquire Infrastructure: Domains | 注册相似域名 |
| T1584.004 | Compromise Infrastructure: Server | 托管钓鱼网站 |
| T1602.001 | Data from Config Repository: SNMP | 仿冒页面收集配置信息 |
| T1534 | Internal Spearphishing | 使用仿冒内部域名进行横向钓鱼 |
| T1204.002 | User Execution: Malicious File | 仿冒网站诱导下载恶意文件 |

### ATT&CK Mitigations

| Mitigation | ID | 适用场景 |
|-----------|-----|---------|
| User Training | M1017 | 员工品牌仿冒识别培训 |
| Domain Audit | M1049 | 监控新注册相似域名 |
| Filter Network Traffic | M1037 | DNS 层面拦截仿冒域名 |
| Threat Intelligence Program | M1019 | 威胁情报驱动监控 |
| Code Signing | M1045 | 官方网站证书验证 |

## OWASP Top 10 映射

| OWASP 类别 | CWE | 仿冒场景 |
|-----------|------|---------|
| A01 Broken Access Control | CWE-284 | 仿冒网站绕过访问控制 |
| A04 Insecure Design | CWE-209 | 缺乏品牌验证机制 |
| A05 Security Misconfiguration | CWE-16 | DNS/证书配置不当被利用 |
| A07 Auth Failures | CWE-287 | 伪造登录绕过认证 |
| A08 Software/Data Integrity | CWE-345 | 仿冒内容冒充合法服务 |
| A09 Logging Failures | CWE-778 | 仿冒攻击未被记录 |

## Sigma 检测规则

### 规则1: 新注册相似域名检测

```yaml
title: Suspicious Domain Registration - Brand Impersonation
id: a1b2c3d4-5e6f-4a5b-9c8d-7e6f5a4b3c2d
status: experimental
description: Detects newly registered domains similar to known brand domains
references:
    - https://attack.mitre.org/techniques/T1583/001
author: SecSkill Evolution
date: 2026/06/18
logsource:
    product: dns
    category: dns_query
detection:
    selection:
        query|contains:
            - 'login'
            - 'secure'
            - 'verify'
            - 'account'
    filter_legitimate:
        query:
            - 'login.example.com'
            - 'secure.example.com'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate subdomains
    - Third-party services
level: medium
tags:
    - attack.initial_access
    - attack.t1583.001
    - attack.t1566.002
```

### 规则2: 同形字域名 DNS 查询

```yaml
title: Homograph Domain DNS Query
id: b2c3d4e5-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: Detects DNS queries for internationalized domain names that may be homograph attacks
references:
    - https://attack.mitre.org/techniques/T1566/002
author: SecSkill Evolution
date: 2026/06/18
logsource:
    product: dns
    category: dns_query
detection:
    selection:
        query|re: .*[\u0300-\u036f\u0430-\u045f].*
    condition: selection
falsepositives:
    - Legitimate international domains
level: high
tags:
    - attack.initial_access
    - attack.defense_evasion
    - attack.t1566.002
```

## CVE 参考表

| CVE | 组件 | 影响 | 仿冒利用场景 |
|-----|------|------|------------|
| CVE-2024-12XXX | WordPress | XSS | 仿冒页面注入恶意脚本 |
| CVE-2023-38505 | libcurl | SOCKS5 heap overflow | 钓鱼页面利用恶意 redirect |
| CVE-2024-20XXX | Chromium | V8 RCE | 仿冒网站触发浏览器漏洞 |
| CVE-2023-29489 | OpenSSL | NULL deref | 钓鱼站点 TLS 协商崩溃 |
| CVE-2024-21XXX | Apple WebKit | Memory corruption | iOS 仿冒页面利用 |

## IOC 采集指引

| IOC 类型 | 采集方法 | 示例 |
|---------|---------|------|
| 仿冒域名 | CT Logs + 网空搜索 | `examp1e.com` (同形字) |
| 钓鱼 IP | WHOIS + DNS 解析 | `185.220.101.45` |
| SSL 证书指纹 | CT Logs 查询 | `SHA256: d1e2f3...` |
| 页面哈希 | HTTP 内容抓取 | `MD5: a1b2c3...` |
| User-Agent | 钓鱼站点日志 | 仿冒工具特征 UA |

## 合规标准参考

| 标准 | 相关条款 | 仿冒监控覆盖 |
|------|---------|------------|
| GB/T 22239-2019 | 8.1.3 访问控制 | 品牌资产保护 |
| ISO 27001 | A.8.9 Threat Intelligence | 威胁情报驱动监控 |
| PCI DSS v4.0 | 12.6.1 Security Awareness | 反钓鱼培训 |
| NIST SP 800-61 | Incident Handling | 仿冒事件响应 |
| GDPR | Art.32 Security | 品牌数据保护 |
| PIPL | 第51条 | 个人信息保护 |
| 等保2.0 | 八级以上 | 安全监测要求 |
| DMARC | RFC 7489 | 邮件品牌保护 |

## 跨技能工作流

### 工作流1: 品牌保护全流程
```
domain-analysis -> brand-impersonation -> url-analysis -> phishing-analysis -> pdf-report
```
域名分析 -> 品牌仿冒检测 -> URL 分析 -> 钓鱼分析 -> 报告生成

### 工作流2: 钓鱼事件响应
```
brand-impersonation -> phishing-analysis -> mail-attachment-downloader -> ttp-extractor -> office-report
```
品牌仿冒发现 -> 钓鱼分析 -> 邮件附件下载 -> TTP 提取 -> 事件报告

### 工作流3: 威胁情报生产
```
brand-impersonation -> ttp-extractor -> rga-knowledge-search -> redteam-recon-nation
```
品牌仿冒发现 -> TTP 提取 -> 知识库检索 -> APT 组织关联

## 关联技能调用

| 场景 | 调用技能 |
|------|----------|
| 域名详情 | `domain-analysis` |
| IP 归属 | `ip-analysis` |
| 钓鱼页面 | `url-analysis` |
| 恶意附件 | `phishing-analysis` |
| TTP 提取 | `ttp-extractor` |
| 知识检索 | `rga-knowledge-search` |
| 报告生成 | `pdf-report` |
| 事件报告 | `office-report` |

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 报告格式规范
- [references/homograph-chars.md](references/homograph-chars.md) - 同形字符对照表
- [references/takedown-templates.md](references/takedown-templates.md) - 下架请求模板
- [references/registrar-abuse.md](references/registrar-abuse.md) - 注册商投诉联系方式
