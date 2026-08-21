---
name: domain-analysis
description: |
  对域名进行综合威胁分析，包括 WHOIS 查询、域名年龄风险评估、DNS 记录检查、DGA 检测、同形字攻击识别、CDN 检测和 ICP 备案查询。作为 WHOIS/域名年龄的权威来源，url-analysis 等技能应调用本技能获取域名注册信息。当用户要求分析域名安全性、查询域名注册信息、检测可疑域名或评估钓鱼风险时使用此技能。
metadata:
  version: 2.2.0
  builtin: true
---

# 域名威胁分析技能

对域名进行威胁情报分析，支持**快速分析**和**深度分析**两种模式。

## 模式选择

```
用户输入域名
    │
    ├─ 默认执行快速分析
    │
    └─ 深度分析（用户主动要求时执行）：
         - 用户明确要求（"深度分析"、"全面分析"）
         - 发现高风险域名，需进一步确认
```

## 依赖要求

**MCP 服务**:
| MCP | 工具 | 用途 |
|------|------|------|
| cybersec-cloud | cybersec_cloud_mcp_risk_insight | 多源威胁情报聚合 |

**本地脚本**:
| 脚本 | 用途 |
|------|------|
| domain_validate.py | 域名格式验证和分类 |
| domain_whois.py | WHOIS 查询、域名年龄分析 |

---

# 快速分析

> **适用场景**: 日常排查、初次研判
> **目标耗时**: <5s

## Phase 1: 格式验证

```
bash: python <SKILL_DIR>/scripts/domain_validate.py <domain>
```

输出：域名格式、IDN 解码、分类

## Phase 2: WHOIS 查询

```
bash: python <SKILL_DIR>/scripts/domain_whois.py <domain>
```

返回：注册商、注册日期、过期日期、域名年龄、注册人信息

**域名年龄风险评分**：
| 域名年龄 | 分值 | 说明 |
|---------|------|------|
| < 7 天 | +30 | 极高风险，很可能是恶意域名 |
| 7-30 天 | +20 | 高风险 |
| 30-90 天 | +10 | 中风险 |
| 90-180 天 | +5 | 较低风险 |
| > 180 天 | 0 | 相对可信 |

## Phase 3: 威胁情报

```
工具: cybersec_cloud_mcp_risk_insight
参数: indicator="<domain>", kind="domain"
```

返回：多源威胁标签、检测率、关联样本

## Phase 3.5: 风险评分

> ⚠️ **必须执行**。快速分析虽然只做 3 个阶段，但必须基于以下规则给出明确分数，不能只给主观高/中/低判断。

**评分规则**：
| 指标 | 分值 | 说明 |
|------|------|------|
| 域名年龄 < 7 天 | +30 | 极高风险，新注册恶意域名常见 |
| 域名年龄 7-30 天 | +20 | 高风险 |
| 域名年龄 30-90 天 | +10 | 中风险 |
| 域名年龄 90-180 天 | +5 | 较低风险 |
| WHOIS 最终查询失败/缺失 | +10 | 仅在 WHOIS 最终无结果时计分，瞬时超时但重试成功不计分 |
| WHOIS 隐私保护 | +5 | 单独出现时仅弱信号，需结合其他指标 |
| 高风险 TLD | +15 | 参考 references/high-risk-tlds.md |
| 多源标记恶意（≥3 源） | +40 | 多个情报源确认恶意 |
| 多源标记恶意（2 源） | +30 | 2 个情报源确认恶意 |
| 单源标记恶意 | +20 | 仅 1 个情报源标记 |
| 命中 C2 标签 | +30 | 命令控制基础设施 |
| 命中 phishing 标签 | +25 | 钓鱼域名 |
| 命中 malware 标签 | +25 | 恶意软件相关域名 |
| 命中 spam 标签 | +15 | 垃圾邮件或投递相关 |
| 恶意样本关联 > 10 | +25 | 大量样本通信/投递 |
| 恶意样本关联 1-10 | +15 | 少量样本关联 |

**快速分析风险等级**：
| 分数 | 等级 | 建议 |
|------|------|------|
| 0-20 | Low | 持续监控 |
| 21-40 | Medium | 建议补充深度分析 |
| 41-60 | High | 建议尽快深度分析确认 |
| 61-100 | Critical | 优先处置/阻断 |

**输出要求**：
- 必须在最终报告中给出总分
- 必须明确列出主要加分项（如域名年龄、情报源命中、标签命中）
- 如果某项未获取到数据，写明“未计分”，不要臆造分数

## Phase 4: 输出报告

> ⚠️ **必须执行**，按以下模板输出（5 章节）：

```markdown
# [!] 域名威胁分析报告

**威胁等级**: [HIGH] (评分: 45)
**分析时间**: YYYY-MM-DD HH:MM
**分析模式**: 快速分析
---
## 1. 域名基本信息
- **域名**: <domain>
- **TLD**: .<tld>
- **注册商**: <registrar>
- **注册日期**: YYYY-MM-DD
- **域名年龄**: X 天
- **注册人信息**: <info> 或 隐私保护
---
## 2. 威胁情报
| 来源 | 判定 | 标签 |
|------|------|------|
| <来源名> | malicious | c2, phishing |

**检测率**: X/X 引擎标记恶意
**情报时效**: 最新活动 YYYY-MM-DD (<状态>)
---
## 3. 结论与处置建议
**威胁类型**: 钓鱼域名 / C2 域名 / 恶意域名
**风险等级**: 高

**评分明细**:
- **域名年龄**: +20
- **情报源命中**: +20
- **标签命中（phishing/c2/malware 等）**: +5
- **总分**: 45

**处置建议**:
1. [+] 持续监控
2. [*] 建议深度分析进一步确认
3. [!] 如确认恶意，阻断该域名解析
---
## 4. IOC 汇总
**域名**: <domain>
**解析 IP**: <ip> 或 未获取
**关联 URL**: <list> 或 未发现
---
## 5. 分析局限性
未进行深度扫描，缺少如下信息：
- 未进行 DGA 检测
- 未进行同形字检测
- 未进行 CDN 检测
- 未查询子域名历史
```

## 快速分析强约束

快速分析仅允许执行以下 3 类操作：
1. 域名格式验证
2. WHOIS 查询
3. 威胁情报查询

完成上述 3 步后，必须立即输出快速分析报告并结束。

禁止在快速分析中继续调用以下能力：
- ICP 查询
- DNS 历史查询
- 子域名发现
- 同 IP 域名分析
- CDN 检测
- DGA 检测
- 同形字检测
- 解析 IP 的地理归属扩展分析
- 任何额外的 cyberspace-search 扩展侦察

除非用户明确要求“深度分析”，否则不得进入深度分析阶段。

### 快速分析输出要求

- 默认输出域名主分析结论，而不是完整深度报告。
- 快速分析报告仅基于域名格式验证、WHOIS 查询、威胁情报查询 3 类结果生成，不引入其他 skill 的补充结论。
- 报告格式必须遵循 [references/report-format.md](references/report-format.md) 中的快速分析模板。

---

# 深度分析

> **适用场景**: 全面评估、入侵分析、确认为威胁时

## Phase 5: ICP 备案查询

> ⚠️ ICP 备案是针对**注册域名（主域名）**进行的，子域名无需单独备案。

```
工具: cybersec_cloud_mcp_intel_icp_lookup
参数: domain="<注册域名>"
```

## Phase 6: DGA 检测

```
bash: python <SKILL_DIR>/scripts/domain_dga.py <domain>
```

**术语**：命中用"疑似 DGA 域名"，未命中用"未发现 DGA 特征"

## Phase 7: 同形字攻击检测

```
bash: python <SKILL_DIR>/scripts/homograph_detector.py <domain>
```

## Phase 7.5: 动态 DNS 服务检测

> ⚠️ 仅在深度分析中补充执行，用于识别常见 DDNS/C2 托管特征，不纳入快速分析。

**检测目标**：识别域名是否命中高风险或中风险动态 DNS 服务商。

**高风险动态 DNS 服务**：
- `duckdns.org` - 常见于 AsyncRAT、RemCos、NjRAT
- `ydns.eu` - 常见于 Xworm、AgentTesla
- `linkpc.net` - 常见于 NjRAT、RemCos
- `ddns.net` - 常见于多种 RAT
- `no-ip.org` - 常见于僵尸网络
- `didns.ru` - 常见于 RemCos

**中风险动态 DNS 服务**：
- `hopto.org` - 常见于 RAT
- `zapto.org` - 常见于 RAT

**结果写法**：
- 命中时：`命中高风险动态 DNS 服务 (<服务商>)` / `命中中风险动态 DNS 服务 (<服务商>)`
- 未命中时：`未发现动态 DNS 托管特征`

## Phase 8: CDN 检测

> ⚠️ **必须在分析 DNS 历史之前执行**，避免将 CDN 正常行为误判为威胁。

```
bash: python <SKILL_DIR>/scripts/cdn_detector.py <ip>
```

**结果解读**：
| 结果 | 风险变化 |
|------|---------|
| CDN 域名 | 风险 -15（GeoDNS 负载均衡，正常） |
| 非 CDN 域名 | 风险 +15（可能是 Fast-Flux） |

## Phase 9: 子域名发现

```
工具: cybersec_cloud_mcp_cyberspace-search
参数: query="hostname=\"*.<domain>\"", limit=20
```

## Phase 10: 同 IP 域名分析

```
工具: cybersec_cloud_mcp_cyberspace-search
参数: query="ip=\"<解析IP>\"", limit=10
```

| 同 IP 域名数 | 判断 |
|-------------|------|
| < 10 | 正常 |
| 10-100 | 可疑 |
| > 100 | 高度可疑（可能防弹托管） |

## Phase 11: DNS 安全配置检测

```bash
# SPF 记录
dig TXT <domain> | grep "v=spf1"

# DMARC 记录
dig TXT _dmarc.<domain>
```

## Phase 11.5: 深度风险评估

> ⚠️ **必须执行**。深度分析在快速分析总分基础上，继续叠加以下增量评分，不能只复述检测结果。

**深度分析增量评分**：
| 指标 | 分值 | 说明 |
|------|------|------|
| 检测到 DGA 特征 | +35 | 疑似算法生成域名 |
| 检测到同形字攻击 | +30 | 疑似品牌仿冒或混淆字符 |
| 命中高风险动态 DNS 服务 | +20 | 常见于 RAT/C2 托管基础设施 |
| 命中中风险动态 DNS 服务 | +10 | 需结合其他信号进一步确认 |
| 非 CDN 且存在 Fast-Flux 特征 | +15 | 解析行为异常 |
| CDN 命中 | -15 | GeoDNS/负载均衡等正常行为降分 |
| 同 IP 域名 10-100 个（仅非 CDN） | +10 | 仅在解析 IP 未命中 CDN 时，作为可疑共享托管信号 |
| 同 IP 域名 > 100 个（仅非 CDN） | +20 | 仅在解析 IP 未命中 CDN 时，作为高度可疑托管信号 |
| 发现大量高风险子域名（≥10） | +10 | 可疑资产扩散 |
| 未配置 SPF | +5 | 邮件滥用风险上升 |
| 未配置 DMARC | +5 | 邮件仿冒风险上升 |
| SPF 过于宽松（+all） | +10 | 几乎无防护作用 |

**深度分析风险等级**：
| 分数 | 等级 | 建议 |
|------|------|------|
| 0-20 | Low | 持续监控 |
| 21-40 | Medium | 观察并保留情报 |
| 41-60 | High | 建议重点核查 |
| 61-100 | Critical | 优先阻断并开展排查 |

**深度分析输出要求**：
- 先给出快速分析基础分，再给出深度分析增量分
- 必须明确总分 = 基础分 + 增量分
- 如果某个深度检查未执行或执行失败，写明“未计分”或“未执行”，不要默认按 0 分伪装为已检测

## Phase 12: 输出报告

**报告输出约束**：
- “解析 IP”仅填写本次实际拿到的解析结果；未获取到时明确写“未获取”
- “关联域名”仅填写同 IP 域名、子域名发现或情报源明确返回的关联域名；不要把当前分析域名重复写入“关联域名”
- “关联 URL”仅在情报源或关联分析返回具体 URL 时填写；未返回具体 URL 时写“未发现”
- “ICP 备案”仅针对注册域名（主域名）填写，不对子域名单独臆造备案信息
- 如果某项检查未执行、执行失败或结果缺失，必须明确写“未执行”“查询失败”或“未返回”，不要默认写成阴性结论

> ⚠️ **必须执行**，按以下模板输出（8 章节）：

```markdown
# [!] 域名威胁分析报告

**威胁等级**: [HIGH] (评分: 45)
**分析时间**: YYYY-MM-DD HH:MM
**分析模式**: 深度分析
---
## 1. 域名基本信息
- **域名**: <domain>
- **TLD**: .<tld>
- **注册商**: <registrar>
- **注册日期**: YYYY-MM-DD
- **域名年龄**: X 天
- **注册人信息**: <info> 或 隐私保护
- **ICP 备案**: 有/无
---
## 2. 威胁情报
| 来源 | 判定 | 标签 | 首次发现 | 最后活跃 |
|------|------|------|----------|----------|
| <来源名> | malicious | c2, phishing | YYYY-MM-DD | YYYY-MM-DD |

**检测率**: X/X 引擎标记恶意
**情报时效**: 最新活动 YYYY-MM-DD (<状态>)
---
## 3. 特殊检测
**DGA 检测**: 未发现 DGA 特征 / 疑似 DGA 域名
**同形字检测**: 未发现同形字攻击 / 疑似仿冒 "<品牌>"
**动态 DNS 检测**: 未发现动态 DNS 托管特征 / 命中高风险动态 DNS 服务 (<服务商>) / 命中中风险动态 DNS 服务 (<服务商>)
**CDN 检测**: 是 / 否
---
## 4. 关联分析
**解析 IP**: <ip>
**同 IP 域名**: X 个
**子域名发现**: X 个
---
## 5. DNS 安全配置
| 记录 | 状态 |
|------|------|
| SPF | 已配置 / 未配置 |
| DMARC | 已配置 / 未配置 |
---
## 6. 结论与处置建议
**威胁类型**: 钓鱼域名 / C2 域名 / 恶意域名
**活跃状态**: 活跃 / 不活跃
**风险等级**: 高

**评分明细**:
- **快速分析基础分**: 30
- **DGA / 同形字 / CDN / 关联资产增量分**: +15
- **DNS 安全配置增量分**: +0
- **总分**: 45

**处置建议**:
1. [x] 立即阻断 - DNS 黑名单/防火墙规则
2. [x] 内部排查 - 检查是否有解析记录
3. [x] 情报共享 - 上报威胁情报平台
---
## 7. 分析局限性
由 LLM 根据实际分析情况动态填写，例如：
- WHOIS 隐私保护，无法获取注册人信息
- 部分 DNS 记录查询超时
---
## 8. IOC 汇总
**域名**: <domain>
**解析 IP**: <ip>
**关联域名**: <list>
**关联 URL**: <list>
```

---

## 工具命令速查

| 任务 | 命令 |
|------|------|
| 域名验证 | `python <SKILL_DIR>/scripts/domain_validate.py <domain>` |
| WHOIS 查询 | `python <SKILL_DIR>/scripts/domain_whois.py <domain>` |
| DGA 检测 | `python <SKILL_DIR>/scripts/domain_dga.py <domain>` |
| 同形字检测 | `python <SKILL_DIR>/scripts/homograph_detector.py <domain>` |
| CDN 检测 | `python <SKILL_DIR>/scripts/cdn_detector.py <ip>` |

---

## 关联技能调用

| 发现的 IOC | 调用技能 |
|-----------|---------|
| 解析 IP | `ip-analysis` |
| 关联 URL | `url-analysis` |
| 子域名 | 本技能递归分析（深度分析） |

**上游技能**（可能调用本技能）：
- `phishing-analysis` - 分析邮件中的域名
- `url-analysis` - 分析 URL 中的域名
- `traffic-analysis` - 分析流量中的域名

---

## MITRE ATT&CK 技术映射

域名分析覆盖攻击者从侦察到命令控制的完整攻击链：

| 战术 | 技术 ID | 技术名称 | 域名分析关联 |
|------|---------|---------|------------|
| Reconnaissance | T1591.002 | Gather Victim Host Information: DNS | DNS 记录查询揭示目标基础设施 |
| Reconnaissance | T1592.002 | Gather Victim Host Information: Software | DNS TXT/SOA 记录泄露服务版本 |
| Reconnaissance | T1590.002 | Gather Victim Host Information: DNS | 侦察目标域名 DNS 配置弱点 |
| Reconnaissance | T1566.002.001 | Spearphishing Link: Spearphishing Link | 钓鱼域名注册行为检测 |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | C2 域名通过 HTTP/HTTPS 通信 |
| Command and Control | T1071.004 | Application Layer Protocol: DNS | DNS 隧道/DGA 域名检测 |
| Command and Control | T1568.001 | Dynamic Resolution: Fast Flux DNS | Fast-Flux 域名网络检测 |
| Command and Control | T1568.002 | Dynamic Resolution: Domain Generation Algorithms | DGA 算法域名识别 |
| Initial Access | T1566.001 | Spearphishing Attachment | 钓鱼域名邮件附件溯源 |
| Initial Access | T1566.002 | Spearphishing Link | 钓鱼链接域名分析 |
| Defense Evasion | T1027.001 | Obfuscated Files or Information: Binary Obfuscation | DGA 域名混淆特征 |
| Credential Access | T1584.001 | Compromise Infrastructure: Domains | 被攻陷域名基础设施检测 |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | C2 域名持久化信道 |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | C2 域名数据外传信道 |
| Resource Development | T1583.001 | Acquire Infrastructure: Domains | 恶意域名注册行为识别 |

### ATT&CK Mitigations

| Mitigation ID | 名称 | 域名分析应用 |
|--------------|------|------------|
| M1041 | Encrypt Sensitive Information | DNSSEC 验证 |
| M1057 | Data Loss Prevention | 域名外传检测 |
| M1031 | Network Intrusion Prevention | DNS 黑名单/域名阻断 |
| M1021 | Restrict Web-Based Content | 恶意域名过滤 |
| M1047 | Audit | DNS 查询日志审计 |

## OWASP / CWE 映射

| OWASP 类别 | CWE ID | 域名安全关联 |
|-----------|--------|------------|
| A01:2021 Broken Access Control | CWE-200 | WHOIS 信息泄露 |
| A02:2021 Cryptographic Failures | CWE-295 | DNSSEC 配置缺失 |
| A04:2021 Insecure Design | CWE-209 | SPF/DMARC 缺失导致邮件仿冒 |
| A05:2021 Security Misconfiguration | CWE-16 | DNS 记录配置错误 |
| A06:2021 Vulnerable Components | CWE-1357 | 域名指向脆弱服务 |
| A07:2021 Identification and Auth Failures | CWE-287 | 域名验证绕过 |
| A08:2021 Software and Data Integrity Failures | CWE-345 | DNS 劫持/缓存投毒 |
| A09:2021 Security Logging Failures | CWE-778 | DNS 查询日志缺失 |
| A10:2021 SSRF | CWE-918 | DNS Rebinding 攻击 |

## CVE 参考

| CVE ID | 漏洞名称 | 域名分析关联 |
|--------|---------|------------|
| CVE-2020-1350 | SIGRed (Windows DNS) | DNS 缓存投毒风险 |
| CVE-2021-25200 | Windows DNS Server Heap Overflow | DNS 解析可靠性影响 |
| CVE-2023-50164 | Apache Struts2 OGNL Injection | 钓鱼域名+RCE链 |
| CVE-2024-1080 | Command Injection | 恶意域名重定向链 |
| CVE-2023-46604 | Apache ActiveMQ RCE | C2 域名回连检测 |

## Sigma 检测规则

### 规则 1: 可疑 DNS 查询模式检测

```yaml
title: Suspicious DNS Query Pattern - DGA Characteristics
id: 5a3f8e21-6b4c-4d8e-9f2a-7c3b1d6e8f01
status: experimental
description: 检测具有 DGA 特征的高熵域名查询
references:
  - https://attack.mitre.org/techniques/T1568/002/
author: Domain Analysis Skill
date: 2026/06/24
tags:
  - attack.command_and_control
  - attack.t1568.002
logsource:
  product: dns
  service: dns-query
detection:
  selection:
    query:
      - "*.xyz"
      - "*.top"
      - "*.click"
      - "*.tk"
      - "*.ml"
      - "*.ga"
      - "*.cf"
  condition: selection
falsepositives:
  - 合法使用新 TLD 的服务
  - CDN 动态调度
level: low
```

### 规则 2: Fast-Flux 域名网络检测

```yaml
title: Fast-Flux Domain Network Indicator
id: 5a3f8e21-6b4c-4d8e-9f2a-7c3b1d6e8f02
status: experimental
description: 检测短时间内 A 记录频繁变化的域名
references:
  - https://attack.mitre.org/techniques/T1568/001/
author: Domain Analysis Skill
date: 2026/06/24
tags:
  - attack.command_and_control
  - attack.t1568.001
logsource:
  product: dns
  service: dns-query
detection:
  selection:
    record_type: "A"
  timeframe: 1h
  condition: selection | count(query) by src_ip > 10
falsepositives:
  - CDN/GSLB 正常调度
  - 负载均衡
level: medium
```

## YARA 规则

```yara
rule Suspicious_Domain_Pattern_DGA
{
    meta:
        description = "检测 DGA 域名特征模式"
        author = "Domain Analysis Skill"
        date = "2026-06-24"
        reference = "T1568.002"
    strings:
        $high_entropy_1 = /[a-z]{15,}\.(xyz|top|click|tk|ml|ga|cf)/
        $high_entropy_2 = /[a-z0-9]{12,}\.(ru|cn|su)/
        $consonant_cluster = /[bcdfghjklmnpqrstvwzx]{5,}/
    condition:
        $high_entropy_1 or $high_entropy_2 or $consonant_cluster
}

rule Homograph_Domain_Punycode
{
    meta:
        description = "检测 Punycode 同形字攻击域名"
        author = "Domain Analysis Skill"
        date = "2026-06-24"
        reference = "T1566.002"
    strings:
        $punycode = /xn--[a-z0-9-]+/
        $mixed_script = /xn--(.*)(0cct|.*[a-z]-[a-z]{2})/
    condition:
        $punycode and $mixed_script
}
```

## IOC 采集指引

| IOC 类型 | 采集方法 | 存储格式 |
|---------|---------|--------|
| 恶意域名 | WHOIS + 威胁情报 | domain, registrar, created, score |
| 解析 IP | DNS A/AAAA 记录 | ip, domain, first_seen, last_seen |
| NS 记录 | DNS NS 查询 | ns_domain, domain, isp |
| MX 记录 | DNS MX 查询 | mx_domain, domain, mail_server |
| 关联 URL | 威胁情报关联 | url, domain, first_seen |
| 子域名 | 枚举/被动DNS | subdomain, domain, ip |
| C2 域名标签 | 情报源标签 | domain, tag, source, confidence |
| DGA 家族 | DGA 算法匹配 | domain, family, algorithm |

## 合规标准映射

| 标准 | 相关条款 | 域名安全要求 |
|------|---------|------------|
| GDPR | Art.32 | 域名注册数据安全保护 |
| PIPL | 第十三条 | 域名相关个人信息处理合法性 |
| ISO 27001 | A.8.8 | 技术漏洞管理中的 DNS 安全 |
| ISO 27001 | A.5.34 | 隐私和 PII 保护中的 WHOIS 数据 |
| PCI DSS v4.0 | 11.5.1 | DNS 配置变更监控 |
| NIST CSF 2.0 | DE.CM-02 | 恶意域名检测与监测 |
| NIST CSF 2.0 | PR.AC-05 | DNS 访问控制 |
| 等保2.0 | 第八章 | 网络通信安全中的 DNS 安全 |
| 等保2.0 | 第九章 | 域名系统环境安全 |

## 跨技能工作流

### 工作流 1: 钓鱼域名溯源
```
phishing-analysis → domain-analysis (域名提取) → ip-analysis (解析IP) → url-analysis (完整URL) → ttp-extractor (提取TTP) → pdf-report
```

### 工作流 2: C2 基础设施检测
```
traffic-analysis (异常流量) → domain-analysis (域名分析) → dns-cache-detection (DNS缓存) → ip-analysis (IP信誉) → ttp-extractor → office-report
```

### 工作流 3: 品牌保护/反钓鱼
```
brand-impersonation (品牌监控) → domain-analysis (可疑域名) → url-analysis (钓鱼页面) → data-desensitize (PII脱敏) → pdf-report
```

## 参考文件

- [references/report-format.md](references/report-format.md) - 报告格式规范
- [references/cdn-detection.md](references/cdn-detection.md) - CDN 检测与误报规避
- [references/dga-detection.md](references/dga-detection.md) - DGA 检测与家族识别
- [references/homograph-detection.md](references/homograph-detection.md) - 同形字攻击检测
- [references/high-risk-tlds.md](references/high-risk-tlds.md) - 高风险 TLD 列表
