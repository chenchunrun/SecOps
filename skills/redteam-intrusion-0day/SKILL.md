---
name: redteam-intrusion-0day
description: 0day漏洞审查。零日漏洞研究和利用可行性评估。当用户要求"0day分析"、"漏洞利用评估"、"Exploit开发"、"PoC分析"、"漏洞武器化"时使用此技能。仅限授权安全研究使用。
metadata:
  version: 1.1.0
  builtin: true
  category: redteam-intrusion
---

# 0day漏洞审查

零日漏洞研究和利用可行性评估，用于红队作战和安全研究。

> ⚠️ **法律警告**: 本技能仅适用于书面授权的安全研究和红队演练。

## 适用场景

**仅限授权研究**:
- 已知漏洞的利用评估
- 新披露漏洞的影响分析
- 红队定制化利用开发
- 安全研究和漏洞悬赏

## MITRE ATT&CK 漏洞利用技术映射

漏洞利用在 ATT&CK 框架中横跨多个战术，从 Initial Access 到 Privilege Escalation：

### Initial Access — 漏洞利用入口

| ATT&CK ID | 技术名称 | 漏洞类型 | 典型 CVE | 检测信号 |
|-----------|---------|---------|---------|---------|
| **T1190** | Exploit Public-Facing Application | Web RCE | Log4Shell (CVE-2021-44228) | WAF 日志异常、异常 HTTP 请求 |
| T1190.001 | SQL Injection | 注入漏洞 | SQLi in CMS | 异常 SQL 语法、WAF 规则触发 |
| T1190.002 | XSS Exploitation | 跨站脚本 | DOM XSS in framework | 异常 JS 执行、CSP 违规 |
| T1190.003 | SSRF Exploitation | 服务端请求伪造 | Cloud metadata SSRF | 内网 IP 访问、metadata API 调用 |
| **T1210** | Exploitation of Remote Services | 内网服务漏洞 | PrintNightmare (CVE-2021-34527) | 横向移动检测、异常服务调用 |
| T1210.001 | Exploitation of Remote Services: SMB | SMB 漏洞 | EternalBlue (CVE-2017-0144) | SMB 异常会话、MS17-010 探测 |
| T1210.002 | Exploitation of Remote Services: RPC | RPC 漏洞 | BlueKeep (CVE-2019-0708) | RDP 异常、NLA 绕过 |
| **T1068** | Exploitation for Privilege Escalation | 本地提权 | PwnKit (CVE-2021-4034) | 异常 setuid 程序、特权提升日志 |
| **T1053** | Scheduled Task/Job Abuse | 计划任务提权 | Cron path injection | 异常 crontab 修改 |
| **T1078** | Valid Accounts | 凭据利用 | Hardcoded credentials | 异常登录时间/位置 |

### Defense Evasion — 漏洞利用后规避

| ATT&CK ID | 技术名称 | 场景 | 检测信号 |
|-----------|---------|------|---------|
| T1620 | Reflective Code Loading | 内存加载 Payload | 进程内存异常、无文件镜像 |
| T1027 | Obfuscated Files | Payload 混淆 | 编码/加密流量、异常 entropy |
| T1140 | Deobfuscate/Decode | 运行时解码 | 子进程异常、脚本解释器调用 |

### ATT&CK Mitigations

| Mitigation | 描述 | 应用场景 |
|-----------|------|---------|
| **M1048** | Application Isolation and Sandboxing | 应用沙箱隔离 | 限制漏洞利用影响范围 |
| **M1050** | Exploit Protection | 漏洞防护 | DEP/ASLR/CFG 启用 |
| **M1051** | Update Software | 软件更新 | 及时打补丁是最有效防御 |
| **M1026** | Privileged Account Management | 特权账户管理 | 限制提权路径 |
| **M1030** | Network Segmentation | 网络分段 | 限制横向移动 |

## OWASP 漏洞利用映射

| OWASP 2025 | 漏洞类型 | 利用技术 | CWE |
|-----------|---------|---------|-----|
| A03 Injection | SQL注入/命令注入 | T1190.001 | CWE-89 |
| A04 Insecure Design | 缺失输入验证 | 参数篡改 | CWE-20 |
| A06 Vulnerable Components | 已知漏洞组件 | T1190/T1210 | CWE-1035 |
| A08 Software/Data Integrity | 反序列化漏洞 | Java/PHP 反序列化链 | CWE-502 |
| A10 SSRF | 服务端请求伪造 | T1190.003 | CWE-918 |

## 漏洞分类

### 按漏洞类型

| 类型 | 代表漏洞 | 利用难度 | ATT&CK | CWE |
|------|---------|---------|--------|-----|
| 内存破坏 | 缓冲区溢出、UAF | 高 | T1068/T1210 | CWE-120/416 |
| 逻辑漏洞 | 认证绕过、权限提升 | 中 | T1078 | CWE-287/269 |
| 注入漏洞 | SQL注入、命令注入 | 低 | T1190.001 | CWE-89/78 |
| 反序列化 | Java/PHP反序列化 | 中 | T1190 | CWE-502 |
| 配置缺陷 | 默认凭据、错误配置 | 低 | T1078 | CWE-521/732 |

### 按影响范围

| 范围 | 描述 | 价值 | 典型赏金 |
|------|------|------|---------|
| 通用漏洞 | 影响广泛产品 | 极高 | $10K-$250K |
| 产品漏洞 | 特定产品 | 高 | $1K-$50K |
| 配置漏洞 | 特定环境 | 中 | $500-$5K |

## 分析流程

### Phase 1: 漏洞情报

**信息收集**:
- CVE 详情和 CVSS 评分
- 厂商公告和补丁分析
- PoC/Exploit 公开情况
- 在野利用情报

**情报来源**:
| 来源 | 类型 | 及时性 | ATT&CK 覆盖 |
|------|------|-------|------------|
| NVD | 官方 | 中 | CVE + CWE |
| Exploit-DB | PoC | 快 | T1190/T1210 |
| GitHub | PoC | 快 | 全覆盖 |
| Twitter/X | 讨论 | 最快 | 情报线索 |
| 厂商公告 | 官方 | 中 | 补丁分析 |
| AlienVault OTX | 威胁情报 | 快 | TTP + IOC |

### Phase 2: 技术分析

**漏洞成因分析**:
```markdown
## 漏洞分析

### 漏洞类型
[SQL注入 / RCE / 权限绕过等] → ATT&CK T-ID

### 触发条件
1. [前置条件1]
2. [前置条件2]

### 漏洞代码
[关键代码片段分析]

### 利用链
[触发] → [绕过] → [执行] → [获权]
→ 对应 ATT&CK: T1190 → T1068 → T1078
```

**利用条件评估**:
| 条件 | 要求 | 目标环境 | 评估 |
|------|------|---------|------|
| 版本 | 1.0-2.0 | ✅ 符合 | 匹配 |
| 配置 | 默认配置 | ✅ 符合 | 匹配 |
| 权限 | 无需认证 | ✅ 符合 | 匹配 |
| 网络 | 可达目标端口 | ✅ 符合 | 匹配 |

### Phase 3: 利用评估

**可利用性评分矩阵**:

| 维度 | 评分(1-10) | 说明 | ATT&CK 关联 |
|------|-----------|------|------------|
| 稳定性 | X | 是否可靠触发 | 影响 T1190 可靠性 |
| 通用性 | X | 跨版本/环境 | 影响 T1210 适用范围 |
| 隐蔽性 | X | 日志/痕迹 | 影响 T1620/T1027 |
| 复杂度 | X | 利用门槛 | 评估防御难度 |
| 影响面 | X | 危害程度 | CVSS + 业务影响 |

**CVSS v3.1 评估**:
```
Attack Vector: Network (AV:N)
Attack Complexity: Low (AC:L)
Privileges Required: None (PR:N)
User Interaction: None (UI:N)
Scope: Changed (S:C)
Confidentiality: High (C:H)
Integrity: High (I:H)
Availability: High (A:H)

CVSS Score: 9.8 (Critical)
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

### Phase 4: PoC 验证

**验证环境搭建**:
```bash
# Docker 复现环境
docker run -d -p 8080:80 vuln-app:1.0

# 执行 PoC
python exploit.py -t http://target:8080

# 验证结果
[+] Exploit successful
[+] Shell obtained
[+] ATT&CK T1190 confirmed
```

**PoC 来源可靠性**:
| 来源 | 可靠性 | 风险 | ATT&CK 验证 |
|------|-------|------|------------|
| Exploit-DB | 高 | 低 | 编辑审核 |
| GitHub | 中 | 中 | 社区验证 |
| Metasploit | 高 | 低 | 框架测试 |
| 私有 | 不定 | 高 | 需独立验证 |

### Phase 5: 武器化

**定制化需求**:
- 载荷类型（反弹 Shell / Beacon / Webshell）
- 规避需求（AV/EDR 绕过 → ATT&CK T1027）
- 稳定性要求（多次触发 / 资源清理）
- 清理机制（日志清除 → ATT&CK T1070）

**武器化 Checklist**:
- [ ] 修改默认特征（避免 IOC 匹配）
- [ ] 载荷加密/编码（T1027 Obfuscated Files）
- [ ] 添加退出/清理逻辑（T1070 Indicator Removal）
- [ ] 错误处理和重试机制
- [ ] 日志规避（T1562 Disable Tools）

## Sigma 检测规则

### 漏洞利用检测 Sigma 规则

```yaml
title: Potential Exploitation of Public-Facing Application
id: b8c3f5d2-1a4e-4f6b-9c8d-2e3f5a7b8c9d
status: experimental
description: >
    Detects patterns consistent with exploitation of public-facing
    applications, including known CVE exploit signatures
logsource:
    product: webserver
    service: access
detection:
    selection_cve_patterns:
        cs-uri-query|contains:
            - "${jndi:"           # Log4Shell
            - "/%2e%2e/"          # Path traversal
            - "class.module"      # Spring4Shell
            - "Autodiscover/Autodiscover.xml"  # ProxyShell
    selection_error_burst:
        sc-status:
            - 500
            - 502
            - 503
        timeframe: 1m
        condition: select_cve_patterns OR (select_error_burst count() > 20)
falsepositives:
    - Legitimate application errors
    - Security scanning activities
level: high
tags:
    - attack.initial_access
    - attack.t1190
    - attack.t1210
```

### 提权利用检测 Sigma 规则

```yaml
title: Suspicious Privilege Escalation Pattern
id: c4d5e6f7-a8b9-0c1d-2e3f-4a5b6c7d8e9f
status: experimental
description: Detects potential exploitation for privilege escalation
logsource:
    product: linux
    service: auditd
detection:
    selection_pkexec:
        exe: /usr/bin/pkexec
        uid_old: "1000"
        uid_new: "0"
    selection_sudo:
        exe|endswith:
            - "/sudo"
            - "/su"
        uid_new: "0"
    condition: selection_pkexec or (selection_sudo and not user in root_users)
falsepositives:
    - Legitimate administrative activity
level: medium
tags:
    - attack.privilege_escalation
    - attack.t1068
    - attack.t1548.003
```

## IOC 采集要点

漏洞利用产生的 IOC 类型：

| IOC 类型 | 采集来源 | 示例 | ATT&CK |
|---------|---------|------|--------|
| 网络 Payload | NIDS/PCAP | exploit 字符串 | T1190 |
| 文件 Hash | 文件审计 | exploit 脚本 SHA256 | T1190/T1210 |
| 异常进程 | EDR/Syslog | 非标准子进程 | T1068 |
| 内存特征 | 内存扫描 | reflective DLL | T1620 |
| Web 日志 | Web server | 异常 URL 参数 | T1190 |
| 帐户变更 | 审计日志 | 异常特权提升 | T1068/T1078 |

## 常见漏洞利用快速参考

### Web RCE 漏洞

| 漏洞 | CVE | ATT&CK | Payload 特征 |
|------|-----|--------|------------|
| Log4Shell | CVE-2021-44228 | T1190 | `${jndi:ldap://...}` |
| Spring4Shell | CVE-2022-22965 | T1190 | `class.module.classLoader...` |
| ProxyShell | CVE-2021-34473 | T1190 | `/autodiscover/autodiscover.json` |
| ProxyLogon | CVE-2021-26855 | T1190 | `X-BEResource` 头 |

### 系统提权漏洞

| 漏洞 | CVE | ATT&CK | 影响 |
|------|-----|--------|------|
| EternalBlue | CVE-2017-0144 | T1210.001 | Windows SMB RCE |
| BlueKeep | CVE-2019-0708 | T1210.002 | Windows RDP RCE |
| PrintNightmare | CVE-2021-34527 | T1068 | Windows 打印机提权 |
| PwnKit | CVE-2021-4034 | T1068 | Linux pkexec 提权 |
| Dirty Pipe | CVE-2022-0847 | T1068 | Linux 内核任意写入 |

## 检测流程（蓝队视角）

红队技能也需理解检测面，以评估利用的隐蔽性：

```
1. NIDS 规则匹配 → 检查已知 exploit 签名
2. EDR 行为分析 → 进程链异常、内存注入检测
3. SIEM 关联 → 多阶段攻击时间线还原
4. 蜜罐告警 → 内网横向移动探测
5. 日志审计 → ATT&CK 技术覆盖矩阵
```

## 输出规范

### 漏洞评估报告

```markdown
# 漏洞评估报告

## 基本信息
| 字段 | 值 |
|------|-----|
| CVE编号 | CVE-XXXX-XXXXX |
| 漏洞名称 | [名称] |
| 影响产品 | [产品版本] |
| 漏洞类型 | [类型] → CWE-XXX |
| CVSS评分 | X.X |
| ATT&CK映射 | T1190 / T1068 |

## 技术分析
[漏洞成因和利用链分析]

## 利用评估
| 维度 | 评估 | 评分 |
|------|------|------|
| 可利用性 | 高/中/低 | X/10 |
| 稳定性 | 高/中/低 | X/10 |
| 武器化难度 | 高/中/低 | X/10 |
| 检测难度 | 高/中/低 | X/10 |

## 目标适用性
[针对具体目标的评估]

## 利用建议
[红队场景下的使用建议]

## 检测规避
[已知检测方法和规避策略]

## Sigma 规则
[附对应的 Sigma 检测规则]
```

## 合规与标准参考

| 标准 | 相关条款 | 场景 |
|------|---------|------|
| ISO 27001 | A.12.6.1 技术漏洞管理 | 漏洞发现和修复流程 |
| PCI DSS | 6.3 安全漏洞管理 | 支付系统漏洞评估 |
| NIST CSF | ID.RA 风险评估 | 漏洞风险评级 |
| NIST SP 800-115 | 技术安全测试 | 渗透测试方法论 |
| GDPR | Art. 32 | 安全措施有效性验证 |
| 网络安全法 | 第22条 | 漏洞披露合规要求 |

## 资源链接

### 漏洞数据库

| 资源 | 链接 | 用途 | ATT&CK |
|------|------|------|--------|
| NVD | nvd.nist.gov | 官方 CVE + CWE | 全覆盖 |
| Exploit-DB | exploit-db.com | PoC 搜索 | T1190/T1210 |
| CVE Details | cvedetails.com | 统计分析 | 趋势分析 |
| CNVD | cnvd.org.cn | 国内漏洞 | 本地化 |
| MITRE CVE | cve.mitre.org | CVE 标准 | 分类参考 |

### 利用框架

| 框架 | 用途 | 特点 |
|------|------|------|
| Metasploit | 综合利用 | 模块化、社区维护 |
| Cobalt Strike | 红队作战 | 商业、Malleable C2 |
| Sliver | 开源 C2 | Go 实现、跨平台 |
| Havoc | 开源 C2 | 现代 EDR 规避设计 |

## 跨技能生态工作流

| 场景 | 上游技能 | 本技能 | 下游技能 |
|------|---------|-------|---------|
| 漏洞利用链 | researching-vulnerabilities (漏洞情报) | 0day 评估和利用 | ttp-extractor (TTP 提取) |
| 红队作战 | redteam-recon-enterprise (目标侦察) | 漏洞利用入口 | redteam-intrusion-hunter (横向移动) |
| 演练报告 | code-audit (代码审计) | 漏洞验证 | pdf-report (评估报告) |

## 命令速查

```bash
# 漏洞搜索
python scripts/exploit_finder.py "CVE-2024-1234" --deep
python scripts/exploit_finder.py "apache struts" --json

# searchsploit 本地搜索
searchsploit --cve CVE-2024-1234
searchsploit -x 12345   # 查看 exploit 详情
searchsploit -m 12345   # 复制 exploit

# Nuclei 批量扫描
nuclei -u https://target.com -t cves/
nuclei -l urls.txt -t exposures/ -o results.txt
```
