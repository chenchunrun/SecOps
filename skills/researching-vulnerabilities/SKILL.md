---
name: researching-vulnerabilities
description: 漏洞情报与影响评估。当用户提供 CVE 编号、漏洞名称，询问"这个漏洞对我有影响吗"、"有没有 PoC"、"是否在野利用"时使用此技能。
metadata:
  version: 2.1.0
  builtin: true
---

# 漏洞情报与影响评估

从漏洞编号出发，收集威胁情报、评估 Exploit 状态、结合资产测绘判断实际影响，输出处置建议。

## 核心定位

```
用户输入: CVE-XXXX / 漏洞名称 / 受影响产品
           │
           ├─► 威胁情报: 在野利用？勒索软件整合？
           │
           ├─► Exploit状态: 公开PoC？利用难度？
           │
           ├─► 资产影响: 我的资产受影响吗？(测绘关联)
           │
           └─► 处置建议: 优先级 + 缓解措施
```

**不是**: 简单的漏洞查询工具
**而是**: 漏洞情报驱动的影响评估

---

## 工作流

```
Phase 1: 漏洞信息确认
    │
Phase 2: 威胁情报收集 (WebSearch)
    │
Phase 3: Exploit 状态评估
    │
Phase 4: 资产影响评估 (cybersec_cloud_mcp_cyberspace-search)
    │
Phase 5: 风险评估与处置建议
```

---

## Phase 1: 漏洞信息确认

### 1.1 输入解析

| 输入类型 | 示例 | 处理 |
|----------|------|------|
| CVE 编号 | CVE-2024-21762 | 直接使用 |
| 漏洞名称 | Log4Shell | 转换为 CVE-2021-44228 |
| 产品+版本 | FortiOS 7.4.2 | 查询相关 CVE |

### 1.2 确认基础信息

向用户确认或通过搜索获取：

| 字段 | 必需 | 说明 |
|------|------|------|
| CVE 编号 | ✓ | 唯一标识 |
| 受影响产品 | ✓ | 产品名称 |
| 影响版本 | ✓ | 版本范围 |
| 用户资产范围 | 推荐 | 域名/IP/组织名 |

### 1.3 快速 CVSS 获取

```
WebSearch: "CVE-XXXX" CVSS site:nvd.nist.gov
```

---

## Phase 2: 威胁情报收集

**目标**: 判断漏洞的真实威胁程度

### 2.1 在野利用检查 (ITW - In The Wild)

```
WebSearch: "CVE-XXXX" (exploit OR attack OR "in the wild" OR 攻击 OR 利用)
```

关注点：
- 是否有真实攻击事件报道
- 哪些攻击组织在使用
- 攻击目标行业/地区

### 2.2 CISA KEV 检查

```
WebSearch: "CVE-XXXX" site:cisa.gov/known-exploited-vulnerabilities
```

| KEV 状态 | 含义 | 优先级 |
|----------|------|--------|
| ✅ 命中 | 美国政府确认在野利用 | P0 紧急 |
| ❌ 未命中 | 不代表安全 | 继续评估 |

### 2.3 勒索软件整合检查

```
WebSearch: "CVE-XXXX" (ransomware OR 勒索 OR LockBit OR BlackCat OR Conti)
```

**勒索软件整合 = P0 紧急**

### 2.4 APT 关联检查

```
WebSearch: "CVE-XXXX" (APT OR "threat actor" OR 攻击组织)
```

### 2.5 情报汇总表

| 维度 | 状态 | 来源 |
|------|------|------|
| 在野利用 | ✅/❌ | [来源链接] |
| CISA KEV | ✅/❌ | CISA |
| 勒索软件 | ✅/❌ | [来源] |
| APT 关联 | ✅/❌ | [来源] |

---

## Phase 3: Exploit 状态评估

**目标**: 判断利用门槛和公开程度

### 3.1 GitHub PoC 搜索

```
WebSearch: "CVE-XXXX" PoC site:github.com
```

评估维度：
- Star 数量 (流行度)
- 发布时间 (时效性)
- 是否可直接利用

### 3.2 Exploit-DB 检查

```
WebSearch: "CVE-XXXX" site:exploit-db.com
```

### 3.3 Nuclei 模板检查

```
WebSearch: "CVE-XXXX" site:github.com/projectdiscovery/nuclei-templates
```

有 Nuclei 模板 = 可批量扫描 = 风险升高

### 3.4 Metasploit 模块检查

```
WebSearch: "CVE-XXXX" site:rapid7.com/db
```

### 3.5 利用难度评估

| 因素 | 低门槛 🔴 | 高门槛 🟢 |
|------|----------|----------|
| 认证要求 | 无需认证 | 需高权限 |
| 交互要求 | 无需交互 | 需用户点击 |
| 利用稳定性 | 稳定可靠 | 概率性/易崩溃 |
| 工具化程度 | 一键利用 | 需手工调试 |

### 3.6 Exploit 汇总表

| 来源 | 状态 | 链接 | 备注 |
|------|------|------|------|
| GitHub PoC | ✅/❌ | [链接] | Star数/可用性 |
| Exploit-DB | ✅/❌ | [链接] | |
| Nuclei | ✅/❌ | [链接] | 可批量扫描 |
| Metasploit | ✅/❌ | [链接] | |

---

## Phase 4: 资产影响评估 ⭐

**目标**: 判断用户资产是否实际受影响

### 4.1 构建测绘查询

根据漏洞影响产品，构建 `cybersec_cloud_mcp_cyberspace-search` 查询语法：

| 漏洞产品 | 测绘语法示例 |
|----------|-------------|
| FortiOS | `app="Fortinet-FortiGate" && port="443"` |
| Apache Log4j | `app="Apache-Log4j"` |
| Confluence | `app="Atlassian-Confluence"` |
| Exchange | `app="Microsoft-Exchange"` |

### 4.2 限定用户资产范围

如果用户提供了资产范围：

```
# 按组织
app="FortiGate" && org="用户公司名"

# 按域名
app="FortiGate" && domain="example.com"

# 按 IP 段
app="FortiGate" && ip="192.168.1.0/24"
```

### 4.3 调用测绘技能

```
建议调用: cybersec_cloud_mcp_cyberspace-search
查询语法: [构建的语法]
目的: 统计受影响资产数量
```

### 4.4 资产影响汇总

| 项目 | 结果 |
|------|------|
| 测绘查询 | `[语法]` |
| 发现资产 | X 台 |
| 暴露端口 | 443, 8443 |
| 影响判定 | ✅ 受影响 / ❌ 未发现 |

---

## Phase 5: 风险评估与处置

### 5.1 综合风险评分

| 因素 | 权重 | 状态 | 得分 |
|------|------|------|------|
| CVSS 基础分 | 基础 | X.X | - |
| 在野利用 | +3 | ✅/❌ | |
| 公开 Exploit | +2 | ✅/❌ | |
| 资产暴露 | +2 | ✅/❌ | |
| 勒索软件整合 | +3 | ✅/❌ | |

### 5.2 优先级判定

| 优先级 | 条件 | SLA |
|--------|------|-----|
| **P0 紧急** | 在野利用 OR 勒索软件 OR (CVSS≥9 + PoC + 资产暴露) | 24h |
| **P1 高危** | CVSS≥9 OR (CVSS≥7 + PoC) | 72h |
| **P2 中危** | CVSS 7-8.9 无PoC OR (CVSS 4-6.9 + PoC) | 1周 |
| **P3 低危** | CVSS<7 无PoC 无暴露 | 计划内 |

### 5.3 处置建议

```markdown
## 立即行动 (P0/P1)
1. [ ] 隔离受影响资产
2. [ ] 应用临时缓解措施
3. [ ] 通知相关团队

## 修复措施
- 升级版本: X.X.X → Y.Y.Y
- 补丁链接: [厂商公告]
- 缓解措施: [临时方案]

## 验证方法
- 版本检查命令
- 漏洞扫描验证
```

---

## 报告模板

详见 [references/report-format.md](references/report-format.md)

---

## 关联技能

### 本技能调用

| 阶段 | 调用技能 | 用途 |
|------|----------|------|
| Phase 4 | `cybersec_cloud_mcp_cyberspace-search` | 资产测绘查询 |
| Phase 4 | `asset-discovery` | 获取用户资产范围 |
| 后续 | `sca-analyzer` | 代码依赖漏洞检查 |

### 输入来源

| 来源技能 | 场景 |
|----------|------|
| `phishing-analysis` | 钓鱼邮件利用的漏洞 |
| `traffic-analysis` | 流量中发现的漏洞利用 |
| `windows-ir` | 应急响应中发现的漏洞 |

---

## 示例

**输入**: "CVE-2024-21762 对我们有影响吗？我们用 FortiGate"

**输出**:

```markdown
# CVE-2024-21762 影响评估报告

**漏洞**: FortiOS 越界写入导致 RCE
**CVSS**: 9.8 Critical

## 威胁情报
| 维度 | 状态 | 说明 |
|------|------|------|
| 在野利用 | ✅ | 2024-02 多起攻击事件 |
| CISA KEV | ✅ | 2024-02-09 加入 |
| 勒索软件 | ⚠️ | 未确认但高风险 |

## Exploit 状态
| 来源 | 状态 |
|------|------|
| GitHub PoC | ✅ 多个可用 |
| Nuclei | ✅ 有模板 |

## 资产影响
- 测绘查询: `app="Fortinet-FortiGate" && org="YourCompany"`
- 发现资产: **3 台**
- 暴露端口: 443, 10443

## 风险评估
**优先级: P0 紧急** (在野利用 + 资产暴露)

## 处置建议
1. **立即**: 限制管理接口访问
2. **24h内**: 升级到 7.4.3 / 7.2.7 / 7.0.14
3. **验证**: `get system status` 检查版本
```

---

## 参考文件

- [references/report-format.md](references/report-format.md) - 报告模板
- [references/product-fingerprints.md](references/product-fingerprints.md) - 产品测绘指纹

---

## MITRE ATT&CK 技术映射

### 战术与技术覆盖表

| 战术 | 技术 | 子技术 | 场景描述 |
|------|------|--------|---------|
| Initial Access (TA0001) | **T1190** Exploit Public-Facing App | **T1190.001** Web Apps | 漏洞利用获取初始访问权限（Web 漏洞）|
| Initial Access (TA0001) | **T1190** Exploit Public-Facing App | **T1190.002** Network Devices | 网络设备漏洞利用（VPN/防火墙/路由器）|
| Initial Access (TA0001) | **T1190** Exploit Public-Facing App | **T1190.003** VPN Devices | VPN 设备专用漏洞利用 |
| Execution (TA0002) | **T1059** Command and Scripting Interpreter | **T1059.004** Unix Shell | 漏洞利用后通过 Shell 执行命令 |
| Privilege Escalation (TA0004) | **T1068** Exploitation for Privilege Escalation | — | 提权漏洞利用评估 |
| Defense Evasion (TA0005) | **T1211** Exploitation for Defense Evasion | — | 安全设备绕过漏洞 |
| Collection (TA0009) | **T1213** Data from Information Repositories | — | 漏洞利用后数据窃取 |
| Impact (TA0040) | **T1485** Data Destruction | — | 勒索软件利用已知漏洞进行数据破坏 |
| Reconnaissance (TA0043) | **T1595** Active Scanning | **T1595.002** Vulnerability Scanning | Nuclei/Metasploit 模板用于漏洞扫描 |
| Resource Development (TA0042) | **T1588** Obtain Capabilities | **T1588.006** Vulnerabilities | 获取漏洞利用工具和 PoC |

### ATT&CK Mitigations 对应

| Mitigation ID | 名称 | 应用场景 |
|---------------|------|---------|
| M1048 | Application Isolation | 隔离受影响应用减少攻击面 |
| M1050 | Patching | 应用安全补丁修复漏洞（最核心的缓解措施）|
| M1051 | Update Software | 定期软件更新预防漏洞 |
| M1020 | Secure-by-Configuration | 安全配置减少可利用面 |
| M1037 | Filter Network Traffic | 通过 WAF/IPS 过滤漏洞利用流量 |

## OWASP Top 10 / CWE 映射

| OWASP 类别 | CWE ID | 关联场景 |
|-----------|--------|---------|
| **A01** Broken Access Control | CWE-787 | 越界写入漏洞（如 FortiOS CVE-2024-21762）|
| **A03** Injection | CWE-89 | SQL 注入漏洞评估 |
| **A04** Insecure Design | CWE-209 | 信息泄露漏洞帮助攻击者侦察 |
| **A05** Security Misconfiguration | CWE-16 | 默认配置漏洞（如 Confluence CVE-2023-22515）|
| **A06** Vulnerable Components | CWE-1039 | 使用含漏洞的第三方组件（Log4j/Struts）|
| **A08** Software & Data Integrity | CWE-345 | 签名验证缺失漏洞 |
| **A10** SSRF | CWE-918 | 服务端请求伪造漏洞评估 |

## YARA 规则参考

```yaml
rule CVE_2021_44228_Log4Shell_Indicator {
    meta:
        description = "检测 Log4j 漏洞利用特征（JNDI 注入）"
        cve = "CVE-2021-44228"
        severity = "critical"
    strings:
        $jndi1 = "${jndi:ldap://" nocase
        $jndi2 = "${jndi:rmi://" nocase
        $jndi3 = "${jndi:dns://" nocase
        $jndi4 = "${jndi:nds://" nocase
        $payload = "\\$\\{\\${::-j}\\${::-n}\\${::-d}\\${::-i}" nocase
    condition:
        any of ($jndi*) or $payload
}
```

## Sigma 检测规则

### 规则 1: 已知漏洞利用检测（Web 日志）

```yaml
title: 已知 CVE 漏洞利用行为检测
id: b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: 检测 Web 服务器日志中匹配已知 CVE 漏洞利用特征的请求
references:
    - https://attack.mitre.org/techniques/T1190/
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    product: webserver
    category: webserver
detection:
    log4j_exploit:
        cs-method: 'GET'
        c-uri|contains:
            - '${jndi:ldap'
            - '${jndi:rmi'
            - '${jndi:dns'
    confluence_exploit:
        c-uri|contains:
            - '/server-info.action'
            - '/json/setup-localhost.action'
    fortios_exploit:
        c-useragent|contains:
            - 'ReportRunner'
            - 'LocalDelivery_CS'
    condition: log4j_exploit or confluence_exploit or fortios_exploit
falsepositives:
    - 安全扫描器授权测试
level: critical
```

### 规则 2: 漏洞利用后命令执行检测

```yaml
title: 漏洞利用后异常命令执行检测
id: c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: 检测漏洞利用成功后的典型命令执行行为（反弹 Shell/下载载荷）
references:
    - https://attack.mitre.org/techniques/T1059/004/
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    product: linux
    category: process_creation
detection:
    reverse_shell:
        CommandLine|contains:
            - 'bash -i'
            - '/dev/tcp/'
            - 'nc -e'
            - 'python -c import socket'
    curl_download:
        Image|endswith: 'curl'
        CommandLine|contains:
            - 'http://'
            - 'https://'
    wget_download:
        Image|endswith: 'wget'
        CommandLine|contains:
            - 'http://'
            - 'https://'
    timeframe: 5m
    condition: reverse_shell or curl_download or wget_download
falsepositives:
    - 合法运维自动化脚本
level: high
```

## IOC 采集指引

从漏洞研究和评估中提取的 IOC 类型：

| IOC 类型 | 提取方法 | 用途 | 示例 |
|---------|---------|------|------|
| **CVE 编号** | 从用户输入或威胁情报获取 | 漏洞唯一标识 | `CVE-2024-21762` |
| **受影响产品版本** | NVD/厂商公告 | 资产匹配 | `FortiOS 7.4.0-7.4.2` |
| **PoC URL** | GitHub/Exploit-DB 搜索 | 攻击模拟验证 | `github.com/user/CVE-2024-21762-PoC` |
| **C2 地址** | 从在野利用报告中提取 | 威胁阻断 | `185.x.x.x:443` |
| **攻击者 TTP** | 从 APT 报告中提取 | 战术映射 | T1190.002 → T1059.004 → T1485 |
| **勒索软件家族** | 关联勒索软件数据库 | 影响评估 | `LockBit 3.0, BlackCat` |
| **Nuclei 模板** | 搜索 nuclei-templates 仓库 | 批量扫描 | `cves/2024/CVE-2024-21762.yaml` |
| **YARA 规则** | 从漏洞利用特征生成 | 文件检测 | 检测 Log4j JNDI 注入载荷 |

## 合规框架参考

| 标准 | 条款 | 关联说明 |
|------|------|---------|
| **ISO 27001** | A.8.8 技术脆弱性管理 | 漏洞情报驱动的补丁管理流程 |
| **ISO 27001** | A.8.7 恶意软件防范 | 已知漏洞被利用的防护 |
| **NIST SP 800-40** | 补丁管理指南 | 漏洞修复优先级和 SLA |
| **NIST SP 800-53** | RA-5 漏洞扫描 | 定期漏洞评估和修复 |
| **NIST SP 800-53** | SI-2 缺陷修复 | 系统缺陷和漏洞修复流程 |
| **PCI DSS** | 6.3.3 | 安全漏洞修复（CVSS ≥ 4.0 需一个月内修复）|
| **GDPR** | Art. 32 | 已知漏洞不修复导致的数据泄露问责 |
| **PIPL** | 第51条 | 安全漏洞导致个人信息泄露的防护义务 |

## 跨技能工作流

### 工作流 1: 漏洞应急响应全流程

```
researching-vulnerabilities (漏洞评估)
  ├─→ asset-discovery (确认受影响资产)
  ├─→ sca-analyzer (代码依赖检查)
  ├─→ code-audit (源代码审计验证)
  └─→ ttp-extractor → pdf-report (报告生成)
```

### 工作流 2: 红队漏洞利用链

```
redteam-recon-enterprise (目标侦察)
  └─→ researching-vulnerabilities (匹配已知漏洞)
       ├─→ redteam-intrusion-hunter (漏洞扫描验证)
       └─→ redteam-intrusion-0day (0day 利用开发)
```

### 工作流 3: 合规驱动漏洞管理

```
researching-vulnerabilities (漏洞评估)
  └─→ 生成修复优先级清单 (符合 NIST SP 800-40)
       └─→ pdf-report (合规报告)
```

## AI 建议

- 发现漏洞影响特定产品时，建议调用 `cybersec_cloud_mcp_cyberspace-search` 进行资产测绘
- 发现漏洞涉及开源组件时，建议调用 `sca-analyzer` 检查代码依赖
- 发现在野利用时，使用上述 Sigma 规则检测本地日志
- 发现 YARA 特征时，使用 YARA 规则扫描文件系统
