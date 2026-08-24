---
name: url-analysis
description: 对可疑 URL 进行双模式安全分析，包括快速研判、钓鱼检测、重定向追踪、同形字攻击识别、规避技术检测、黑产组织归因、威胁情报补充和威胁扩线。当用户提供可疑链接、要求检查 URL 安全性、分析钓鱼页面或追溯攻击来源时使用此技能。
metadata:
  version: 2.18.0
  builtin: true
---

# URL 威胁分析技能

对 URL 进行双模式安全分析，支持**快速分析**和**深度分析**两种模式。

## 模式选择

```text
用户输入 URL
    │
    ├─ 默认执行快速分析
    │
    └─ 深度分析（仅在以下情况进入）：
         - 用户明确要求“深度分析”“完整分析”“全面分析”
         - 用户明确要求“截图”“归因增强”“扩线”
         - 快速分析命中高风险，且需要进一步确认视觉证据或关联基础设施
```

## 分析边界

- `url-analysis` 负责：URL 解析、跳转分析、页面内容分析、规避技术检测、URL 级威胁情报、归因建议、扩线建议。
- `domain-analysis` 是域名注册信息、WHOIS、域名年龄风险、DNS 记录的**权威来源**。
- `ip-analysis` 用于 URL 中关联 IP 的独立威胁分析，不在本技能内替代执行。

## 依赖要求

**Python 版本**: 3.8+

**本地脚本**:
| 脚本 | 用途 |
|------|------|
| url_analyze.py | URL 综合分析主入口 |
| url_parser.py | URL 解析与验证 |
| url_expand.py | 短链接展开 |
| url_defang.py | URL 脱敏 |
| url_fetcher.py | HTTP 获取、重定向追踪、JS 跳转检测 |
| phishing_detector.py | 页面钓鱼内容检测 |
| url_evasion_patterns.py | 规避技术检测 |
| threat_actor_attribution.py | 黑产组织归因与 WebSearch 建议 |

**关联技能**:
| 技能 | 用途 |
|------|------|
| domain-analysis | WHOIS、域名年龄、DNS 记录、DGA、同形字 |
| ip-analysis | 关联 IP 独立威胁分析 |

**MCP 服务**:
| MCP | 工具 | 用途 |
|------|------|------|
| cybersec-cloud | cybersec_cloud_mcp_risk_insight | URL 威胁情报 |
| cybersec-cloud | cybersec_cloud_mcp_dns_history | DNS 历史 |
| cybersec-cloud | cybersec_cloud_mcp_cyberspace-search | 威胁扩线 |
| webtools | webcap_tool | 页面截图 |
| webtools | websearch_tool | 归因增强 |

## 环境变量配置

| 环境变量 | 说明 | 默认值 |
|------|------|------|
| `URL_ANALYSIS_TIMEOUT` | 获取超时时间（秒） | 30 |
| `URL_ANALYSIS_MAX_REDIRECTS` | 最大重定向次数 | 10 |
| `URL_ANALYSIS_USER_AGENT` | User-Agent 类型 | chrome |
| `URL_ANALYSIS_VERIFY_SSL` | 是否验证 SSL 证书 | false |

**优先级**: 命令行参数 > 环境变量 > 默认值

详细说明见 [references/env-config.md](references/env-config.md)

## 快速开始

```bash
# 快速分析（静态）
python <SKILL_DIR>/scripts/url_analyze.py "https://example.com/login"

# 快速分析（含内容获取，推荐）
python <SKILL_DIR>/scripts/url_analyze.py "https://example.com/login" --fetch

# 使用本地 HTML 进行内容分析
python <SKILL_DIR>/scripts/url_analyze.py "https://example.com/login" --html page.html

# JSON 输出
python <SKILL_DIR>/scripts/url_analyze.py "https://example.com/login" -o json
```

## 快速分析

> **适用场景**: 日常排查、初次研判、需要快速给出处置建议时

### 快速分析阶段

1. URL 解析与基础特征提取
2. 条件式内容获取与跳转分析（`--fetch` 或 `--html`）
3. 页面内容检测与规避技术检测（仅在拿到 HTML 时）
4. 调用 `domain-analysis` 获取域名权威信息
5. URL 威胁情报查询
6. 快速风险评估与快速报告输出

### 快速分析强约束

快速分析仅允许执行以下 5 类动作：
1. URL 解析与静态特征分析
2. 条件式内容获取与跳转分析
3. 页面内容检测与规避技术检测
4. `domain-analysis` 域名分析
5. URL 威胁情报查询

完成上述步骤后，必须立即输出快速分析报告并结束。

禁止在快速分析中继续调用以下能力：
- 页面截图
- WebSearch 归因增强
- DNS 历史查询
- 威胁扩线
- 同 IP 资产扩展侦察
- 同证书资产扩展侦察
- 相似标题 / 相似域名扩线
- 任何额外的 cyberspace-search 扩展分析

除非用户明确要求深度分析，或快速分析已明确提示需要升级，否则不得进入深度分析阶段。

### 快速分析输出要求

- 默认输出快速分析结论，而不是完整深度报告。
- 必须明确 `domain-analysis` 为域名年龄与 WHOIS 的权威来源。
- 如果联用了 `domain-analysis`、`ip-analysis` 等下游技能，必须区分“URL 主分析结果”和“联用补充结果”，避免把多 skill 结果混写为 `url-analysis` 默认产出。
- 联用场景下，至少明确以下信息：主分析技能、联用技能、关键结论来源（例如 WHOIS / 域名年龄来自 `domain-analysis`，IP 地理位置 / ASN / IP 威胁情报来自 `ip-analysis`）。
- 如果脚本输出了 `deep_analysis_recommended` / 深度建议信号，应在快速报告中给出升级原因。
- 报告格式必须遵循 [references/report-format.md](references/report-format.md) 中的快速分析模板。

## 深度分析

> **适用场景**: 明确要求全面评估、需要视觉证据、需要归因增强、需要威胁扩线时

### 深度分析追加阶段

在快速分析基础上，按需追加：
1. 页面截图
2. DNS 历史查询
3. WebSearch 归因增强
4. 威胁扩线
5. 深度风险评估与深度报告输出

### 深度分析触发条件

进入深度分析的典型条件：
- 用户明确要求“深度分析”“全面分析”“完整分析”
- 用户明确要求“截图”或“页面证据”
- 用户明确要求“归因增强”或“搜索安全报告”
- 用户明确要求“扩线”“同 IP 资产”“同证书站点”
- 快速分析已命中高风险，且需要进一步确认当前页面、基础设施或归因结论

### 深度分析注意事项

- 页面截图仅属于深度分析，不是默认必做步骤。
- `websearch_suggestions` 是深度分析建议信号，不代表默认必须执行 WebSearch。
- `expansion_suggestions` 是深度分析建议信号，不代表默认必须执行扩线。
- 深度分析报告格式必须遵循 [references/report-format.md](references/report-format.md) 中的深度分析模板。

## domain-analysis 调用规则

对于非 IP 直连 URL，必须调用 `domain-analysis` 获取域名权威信息。

```bash
python <DOMAIN_ANALYSIS_SKILL_DIR>/scripts/domain_analyze.py "<域名>"
```

重点整合以下结果：
- 注册商
- 注册日期
- 域名年龄
- WHOIS 隐私保护情况
- DNS 记录
- 域名侧风险评分

如果目标是 IP 直连 URL，可跳过该步骤，并在报告中明确写明“IP 地址无需 WHOIS 查询”。

## 执行建议

### 快速模式推荐命令

```bash
python <SKILL_DIR>/scripts/url_analyze.py "<URL>" --fetch
```

### 深度模式常见追加动作

- 根据快速分析结果调用 `webcap_tool` 获取截图
- 根据需要调用 `cybersec_cloud_mcp_dns_history` 查询 DNS 历史
- 当 `websearch_suggestions.enabled = true` 时，再执行 `websearch_tool`
- 当 `expansion_suggestions.enabled = true` 时，再执行 `cybersec_cloud_mcp_cyberspace-search`

## 报告与状态写法

- 检查已执行且正常时，写“已检测（未发现风险）”，不要写“未检测”。
- 快速分析报告只保留最小必要章节。
- 深度分析报告才包含截图、归因增强、扩线等附加章节。
- 截图如已执行，必须按 Markdown 图片语法写入报告。

## 参考文件

- [references/phases.md](references/phases.md) - 双模式阶段说明
- [references/report-format.md](references/report-format.md) - 快速分析 / 深度分析报告模板
- [references/cli-reference.md](references/cli-reference.md) - CLI 命令、输出字段与双模式对应关系
- [references/env-config.md](references/env-config.md) - 环境变量配置
- [references/threat-actors.md](references/threat-actors.md) - 归因参考资料

## MITRE ATT&CK 技术映射

URL 分析覆盖攻击生命周期多个阶段，以下为 ATT&CK v16 技术映射：

| 战术 | 技术 | 子技术 | URL 分析中的表现 |
|------|------|--------|------------------|
| Initial Access | T1566 | Phishing | 钓鱼 URL 是初始访问的最常见载体 |
| Initial Access | T1566.002 | Spearphishing Link | 定向钓鱼链接（区别于附件钓鱼） |
| Initial Access | T1190 | Exploit Public-Facing Application | URL 指向已知漏洞利用页面 |
| Execution | T1059 | Command and Scripting Interpreter | URL 参数中嵌入命令注入载荷 |
| Execution | T1059.007 | JavaScript | 恶意 JS 通过 URL 触发执行 |
| Defense Evasion | T1027 | Obfuscated Files or Information | URL 编码/混淆规避检测 |
| Defense Evasion | T1036 | Masquerading | 仿冒合法域名（typosquatting/homoglyph） |
| Defense Evasion | T1036.005 | Match Legitimate Name or Location | 路径伪装合法站点（如 `/login.php`） |
| Command and Control | T1071 | Application Layer Protocol | URL 作为 C2 通信通道（HTTP/HTTPS） |
| Command and Control | T1071.001 | Web Protocols | C2 通过 Web 协议回传数据 |
| Command and Control | T1105 | Ingress Tool Transfer | URL 用于下载恶意工具/载荷 |
| Defense Evasion | T1090 | Proxy | URL 通过代理链隐藏真实 C2 |
| Defense Evasion | T1090.004 | Domain Fronting | CDN 域前置隐藏真实目的地 |
| Credential Access | T1552 | Unsecured Credentials | URL 指向伪造登录页窃取凭证 |
| Credential Access | T1552.001 | Credentials In Files | 钓鱼页面表单收割用户密码 |
| Exfiltration | T1567 | Exfiltration Over Web Service | 数据通过 URL 参数外传到外部服务 |
| Exfiltration | T1567.002 | Exfiltration to Cloud Storage | 数据上传到云存储 URL |
| Reconnaissance | T1595 | Active Scanning | URL 扫描探测 Web 应用弱点 |
| Reconnaissance | T1595.002 | Vulnerability Scanning | URL 指纹识别和漏洞扫描 |

### ATT&CK 缓解措施

| Mitigation | 相关技术 | URL 分析中的作用 |
|------------|----------|------------------|
| M1041 — Encrypt Sensitive Information | T1552 | 检测页面是否使用 HTTPS 保护凭证传输 |
| M1053 — Software Update | T1190 | 识别 URL 是否指向已知漏洞利用目标 |
| M1031 — Network Intrusion Prevention | T1071, T1105 | URL 情报集成到 IPS/IPS 规则 |
| M1021 — Restrict Web-Based Content | T1566 | URL 过滤和分类阻断恶意链接 |

## OWASP Top 10 + CWE 映射

| OWASP 2025 | CWE | 与 URL 分析的关系 |
|-----------|------|------------------|
| A01 Broken Access Control | CWE-639 | URL 路径遍历/IDOR 检测 |
| A03 Injection | CWE-89 | URL 参数 SQL 注入特征检测 |
| A03 Injection | CWE-79 | URL 参数 XSS 注入检测 |
| A04 Insecure Design | CWE-209 | URL 暴露错误信息/堆栈跟踪 |
| A05 Security Misconfiguration | CWE-16 | URL 暴露管理面板/默认页面 |
| A07 Identification & Authentication Failures | CWE-287 | 钓鱼 URL 仿冒登录页面 |
| A08 Software & Data Integrity Failures | CWE-829 | URL 指向未签名/篡改的下载资源 |
| A10 SSRF | CWE-918 | URL 参数中嵌入内网地址（SSRF 探测） |

## Sigma 检测规则

### 规则 1: 恶意 URL 访问检测（Proxy 日志）

```yaml
title: 检测用户访问已知恶意 URL
type: detect
status: stable
logsource:
  product: proxy
  category: webserver
detection:
  selection:
    c-uri|contains:
      - "/wp-admin/"
      - "/.env"
      - "/phpmyadmin/"
      - "/admin/login"
    c-useragent:
      - "curl/*"
      - "python-requests/*"
      - "Go-http-client/*"
  filter_legitimate:
    c-uri-status:
      - 200
    src_ip:
      - 10.0.0.0/8
      - 172.16.0.0/12
  condition: selection and not filter_legitimate
fields:
  - src_ip
  - dst_host
  - c-uri
  - c-useragent
  - c-uri-status
falsepositives:
  - 内部管理员访问自有管理面板
  - 自动化健康检查工具
level: medium
tags:
  - attack.initial_access
  - attack.t1566
  - attack.reconnaissance
  - attack.t1595
```

### 规则 2: URL 重定向链异常检测（Web Proxy）

```yaml
title: 检测可疑多重重定向链（可能钓鱼/C2）
type: detect
status: experimental
logsource:
  product: proxy
  category: webserver
detection:
  selection_redirect_chain:
    c-uri|contains:
      - "redirect="
      - "url="
      - "next="
      - "return_to="
      - "goto="
  suspicious_destination:
    dst_host:
      - "*.tk"
      - "*.ml"
      - "*.ga"
      - "*.cf"
      - "*.gq"
  new_domain_age:
    dst_ip: "*"
  condition: selection_redirect_chain and suspicious_destination
fields:
  - src_ip
  - dst_host
  - c-uri
  - c-uri-status
  - c-referer
falsepositives:
  - 合法的短链接服务
  - 营销邮件中的跟踪链接
level: high
tags:
  - attack.initial_access
  - attack.t1566.002
  - attack.defense_evasion
  - attack.t1036
  - attack.credential_access
  - attack.t1552
```

## YARA 规则

### 规则 1: URL 钓鱼页面特征检测

```yara
rule Phishing_Page_URL_Patterns {
  meta:
    description = "检测钓鱼页面中常见的 URL 提取和凭证收割模式"
    author = "sec-skills url-analysis"
    date = "2026-06-21"
    reference = "ATT&CK T1566.002"
  strings:
    $form_action1 = /action=["']https?:\/\/[^"']+\.(tk|ml|ga|cf|gq)/ nocase
    $form_action2 = /action=["']https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase
    $cred_harvest1 = /name=["']?(password|passwd|pwd|pass)["']?/ nocase
    $cred_harvest2 = /name=["']?(username|user|email|account)["']?/ nocase
    $obfuscation = /document\.write\(atob\(/ nocase
    $iframe_inject = /<iframe[^>]+src=["']https?:\/\// nocase
  condition:
    ($form_action1 or $form_action2) and ($cred_harvest1 and $cred_harvest2)
    or ($obfuscation and $iframe_inject)
}
```

### 规则 2: URL 缩短服务滥用检测

```yara
rule URL_Shortener_Suspicious_Patterns {
  meta:
    description = "检测可疑的 URL 缩短服务使用模式"
    author = "sec-skills url-analysis"
    date = "2026-06-21"
    reference = "ATT&CK T1027 Obfuscated Files or Information"
  strings:
    $shortener1 = /https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly)\/[A-Za-z0-9]{6,}/ nocase
    $shortener2 = /https?:\/\/(t\.me|telegram\.me)\/[a-zA-Z0-9_]+\?start=/ nocase
    $redirect_param = /[?&](redirect|url|next|goto|return_to|continue)=https?%3A%2F%2F/ nocase
    $tracking = /[?&](utm_source|utm_medium|campaign)=/ nocase
  condition:
    ($shortener1 or $shortener2) and $redirect_param
    or ($shortener1 and not $tracking)
}
```

## CVE 参考

| CVE | 描述 | URL 分析关联 |
|-----|------|-------------|
| CVE-2021-44228 | Log4Shell JNDI 注入 | URL 参数 `${jndi:ldap://}` 模式检测 |
| CVE-2023-50164 | Apache Struts 路径遍历 | URL 路径操纵上传 Web Shell |
| CVE-2024-3400 | Palo Alto PAN-OS 命令注入 | URL 中嵌入 shell 命令特征 |
| CVE-2023-23397 | Outlook NTLM 品尝 | 恶意 URL 触发 NTLM 认证泄露 |
| CVE-2024-21893 | Ivanti Connect Secure SSRF | URL 参数利用 SSRF 链 |
| CVE-2023-46604 | Apache ActiveMQ RCE | URL 指向恶意 XML 配置 |
| CVE-2025-31101 | Apple WebKit URL Scheme 漏洞 | 恶意 URL Scheme 触发 Safari 漏洞 |

## IOC 采集指引

URL 分析过程中应提取以下 IOC 并格式化输出：

| IOC 类型 | 提取方法 | 格式 |
|----------|----------|------|
| 完整 URL | url_parser.py 输出 | `hxxps://example[.]com/path` (Defang) |
| 目标域名 | 从 URL 解析 | `example[.]com` (Defang) |
| 目标 IP | DNS 解析或 URL 提取 | `1.2.3[.]4` (Defang) |
| 重定向链 | url_fetcher.py 追踪 | JSON 数组，每跳含 URL + 状态码 |
| 页面标题 | url_fetcher.py 提取 | 纯文本 |
| SSL 证书指纹 | url_fetcher.py 获取 | SHA-256 |
| User-Agent 特征 | 僵尸网络/扫描器 UA | 字符串模式 |
| 路径关键词 | URL 路径段分析 | `/admin` `/login` `/.env` `/api/` |
| 查询参数 | URL 参数分析 | JSON key-value（注意脱敏） |
| 页面 Hash | 页面内容 SHA-256 | SHA-256 哈希值 |
| JS 框架指纹 | 页面内容分析 | React/Vue/jQuery 版本 |
| 同形字域名 | url_evasion_patterns.py | Unicode + ASCII 对照 |

## 合规标准参考

| 标准 | 章节/控制项 | 与 URL 分析的关系 |
|------|------------|------------------|
| ISO/IEC 27001 | A.13 通信安全 | URL 过滤和恶意链接防护 |
| ISO/IEC 27001 | A.14 系统获取、开发及维护 | Web 应用 URL 安全测试 |
| NIST SP 800-53 | SC-7 Boundary Protection | URL 过滤和网关检测 |
| NIST SP 800-53 | SI-3 Malicious Code Protection | URL 信誉检测集成 |
| NIST SP 800-137 | Information Security Continuous Monitoring | URL 持续监控 |
| PCI DSS v4.0 | 6.5 Web Application Security | URL 输入验证和注入防护 |
| GDPR | Article 32 | URL 泄露中的 PII 检测（URL 参数中的个人信息） |
| 等保2.0 | 第八章 通信网络 | URL 访问控制和安全检测 |

## 跨技能工作流

### 工作流 1: 钓鱼 URL 完整分析链

```
邮件附件/钓鱼报告 → url-analysis（URL 分析）→ domain-analysis（域名信息）→ ip-analysis（IP 威胁）
  → phishing-analysis（钓鱼判定）→ ttp-extractor（TTP 提取）→ pdf-report（报告生成）
```

### 工作流 2: C2 URL 威胁狩猎

```
日志分析/SIEM 告警 → url-analysis（C2 URL 确认）→ ip-analysis（基础设施追溯）
  → domain-analysis（域名注册历史）→ ttp-extractor（攻击行为映射）→ 报告
```

### 工作流 3: Web 应用漏洞 URL 检测

```
代码审计/资产发现 → url-analysis（漏洞 URL 验证）→ researching-vulnerabilities（漏洞关联）
  → code-audit（代码验证）→ ttp-extractor（漏洞利用 TTP）→ 报告
```

## 技能关联

**上游技能**: phishing-analysis, office-malware-analyzer, pdf-analysis, traffic-analysis, code-audit, brand-impersonation, mail-attachment-downloader

**下游技能**: domain-analysis, ip-analysis, binary-reverse-engineering, office-malware-analyzer, pdf-analysis, mail-attachment-downloader, prompt-injection-detect, ttp-extractor, pdf-report
