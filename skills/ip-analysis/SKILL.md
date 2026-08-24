---
name: ip-analysis
description: |
  对 IP 地址进行威胁情报分析，包括地理位置、ASN 归属、威胁情报查询、端口扫描。
  触发条件：分析 IP、查询 IP 威胁情报、检查 IP 信誉、IP 归属查询、IP 是否恶意、分析攻击源 IP、C2 IP 分析。
  间接触发：恶意软件分析发现 C2 地址、钓鱼邮件发件人 IP、攻击日志来源 IP。
metadata:
  version: 2.1.0
  builtin: true
---

# IP 威胁分析技能

对 IP 地址进行威胁情报分析，支持**快速分析**和**深度分析**两种模式。

## 模式选择

```
用户输入 IP
    │
    ├─ 默认执行快速分析
    │
    └─ 深度分析（用户主动要求时执行）：
         - 用户明确要求（"深度分析"、"全面分析"、"端口扫描"）
         - 需要确认当前端口状态
```

## 依赖要求

**MCP 服务**:
| MCP | 工具 | 用途 |
|------|------|------|
| cybersec-cloud | cybersec_cloud_mcp_ip_geo_lookup | 地理位置、ASN、运营商 |
| cybersec-cloud | cybersec_cloud_mcp_dns_history | DNS 解析历史 |
| cybersec-cloud | cybersec_cloud_mcp_risk_insight | 多源威胁情报聚合 |
| cybersec-cloud | cybersec_cloud_mcp_ops_portscan | TCP 端口扫描 |
| cybersec-cloud | cybersec_cloud_mcp_cyberspace-search | C 段搜索、同 IP 域名 |

**本地脚本**:
| 脚本 | 用途 |
|------|------|
| ip_validate.py | IP 格式验证、PTR 反向解析 |

**可选脚本**:
| 脚本 | 用途 |
|------|------|
| ip_validate.py | 本地 IP 格式验证（可选，LLM 也可直接判断） |
| extract_ssl_domains.py | 从 SSL 证书文本提取域名（可选） |

---

## 使用决策

| 场景 | 动作 |
|------|------|
| 单个公网 IP | 直接执行快速分析，必要时升级深度分析 |
| 内网 IP (10.x/172.16-31.x/192.168.x) | 跳过情报查询，仅报告类型 |
| 批量 IP (>5) | 询问用户：全部分析 / 仅公网 / 仅高频 |
| 从其他技能调用 | 简洁摘要，不阻塞主流程 |

---

## 快速开始

```bash
# 本地 IP 验证（包含格式、类型、PTR）
python <SKILL_DIR>/scripts/ip_validate.py <IP>
```

---

# 快速分析

> **适用场景**: 日常排查、事件响应、初步研判
> **目标耗时**: <5s

## Phase 1: IP 验证

**执行脚本** `ip_validate.py <IP>`：

| 类型 | 范围 | 处理 |
|------|------|------|
| 私有地址 | 10.x, 172.16-31.x, 192.168.x | 跳过情报查询，仅报告类型 |
| 保留地址 | 0.x, 127.x, 224-255.x | 仅报告类型 |
| 公网地址 | 其他 | 继续 Phase 2 |

脚本同时查询 PTR 反向解析记录。

## Phase 2: 地理位置/ASN

```
工具: cybersec_cloud_mcp_ip_geo_lookup
参数: ip="<IP>"
```

返回数据：国家/城市、ASN/组织、运营商

## Phase 3: 威胁情报查询

```
工具: cybersec_cloud_mcp_risk_insight
参数: indicator="<IP>", kind="ip_address"
```

返回数据：
- 威胁标签 (malware/c2/scanner/botnet)
- 置信度和活跃时间
- 关联样本和域名
- 多源情报汇总

## Phase 4: 风险评估

**评分规则**: 按 [references/risk-scoring.md](references/risk-scoring.md) 执行

**快速分析特有指标**:
| 指标 | 分值 | 说明 |
|------|------|------|
| 多源标记恶意 (≥3 源) | +40 | 多个情报源确认 |
| 多源标记恶意 (2 源) | +30 | 2 个情报源确认 |
| 单源标记恶意 | +20 | 仅 1 个情报源 |
| C2 标签 | +30 | 命令控制服务器 |
| 恶意样本关联 > 10 | +25 | 大量样本通信 |
| 恶意样本关联 1-10 | +15 | 少量样本通信 |
| 高风险国家 | +10 | 参考 references/high-risk-asn.md |
| 防弹主机 ASN | +20 | 已知恶意托管 |
| 商业 VPN | +10 | 匿名但有合法用途 |
| Tor/公共代理 | +15 | 高度匿名 |

**风险等级**:
| 分数 | 等级 | 建议 |
|------|------|------|
| 0-20 | 低风险 | 持续监控 |
| 21-40 | 中风险 | 观察，必要时深度分析 |
| 41-60 | 高风险 | 建议深度分析确认当前状态 |
| 61-100 | 严重 | 建议深度分析确认当前状态 |

## Phase 5: 输出报告

> ⚠️ **必须执行**，按 [references/report-format.md](references/report-format.md) 中的**快速分析报告模板**输出（5 章节）：

```markdown
# [!] IP 威胁分析报告
**威胁等级**: [HIGH] (评分: 55)
**分析时间**: YYYY-MM-DD HH:MM
**分析模式**: 快速分析
---
## 1. 基础信息
- **IP 地址**: <IP>
- **IP 类型**: 公网地址
- **地理位置**: <国家> / <省/州> / <城市>
- **ASN**: AS<号码> (<组织名>)
- **PTR 记录**: <PTR> 或 无
---
## 2. 威胁情报
| 来源 | 判定 | 标签 | 首次发现 | 最后活跃 |
|------|------|------|----------|----------|
| <来源名> | malicious | c2, scanner | YYYY-MM-DD | YYYY-MM-DD |
**关联情报数量**: X 条

**关联家族/标签**: <family/tag list> 或 未返回

**关联 C2 端口**: 端口号 (协议)

**情报时效**: 最新活动 YYYY-MM-DD (<状态>)
---
## 3. 结论与处置建议
**威胁类型**: 扫描器 / C2 服务器 / 僵尸网络
**风险等级**: 中 / 高
**处置建议**:
1. [+] 持续监控
2. [*] 建议深度分析确认端口状态
3. [!] 如确认恶意，阻断该 IP
---
## 4. IOC 汇总
**IP 地址**: <IP>
**PTR 记录**: <PTR> 或 无
**关联域名**: <list> 或 未发现
**关联端口**: <ports> 或 未发现
---
## 5. 分析局限性
未进行深度扫描，缺少如下信息：
- 未进行主动端口扫描
- 未查询 DNS 解析历史
- 未进行 C 段分析
```

## 快速分析强约束

快速分析仅允许执行以下 3 类操作：
1. IP 验证
2. 地理位置/ASN 查询
3. 威胁情报查询

完成上述 3 步后，必须立即输出快速分析报告并结束。

禁止在快速分析中继续调用以下能力：
- 主动端口扫描
- C2/RAT 端口探测
- DNS 历史查询
- 同 IP 域名分析
- C 段分析
- 关联域名递归分析
- 关联 URL 递归分析
- 任何额外的 cyberspace-search 扩展侦察

除非用户明确要求“深度分析”，否则不得进入深度分析阶段。

### 快速分析输出要求

- 默认输出 IP 主分析结论，而不是完整深度报告。
- 快速分析报告仅基于 IP 验证、地理位置 / ASN 查询、威胁情报查询 3 类结果生成，不引入其他 skill 的补充结论。
- 报告格式必须遵循 [references/report-format.md](references/report-format.md) 中的快速分析模板。

---

# 深度分析

> **适用场景**: 全面评估、入侵分析、确认为威胁时
> **目标耗时**: ~30s
> **注意**: 主动扫描需用户确认

## Phase 6: 主动探测

### 端口扫描

**推荐扫描端口**:
| 类别 | 端口 | 说明 |
|------|------|------|
| 基础服务 | 22, 80, 443, 8080, 8443 | SSH/HTTP/HTTPS |
| 数据库 | 3306, 1433, 5432, 6379, 27017 | MySQL/SQL Server/PostgreSQL/Redis/MongoDB |
| 远程管理 | 3389, 5900, 5985 | RDP/VNC/WinRM |
| 高危服务 | 21, 25, 110, 143 | FTP/SMTP/POP3/IMAP |

```
工具: cybersec_cloud_mcp_ops_portscan
参数: target="<IP>", port_spec="22,80,443,3306,3389,6379"
```

### C2/RAT 检测

**推荐检测端口**:
| 端口 | 常见工具 |
|------|---------|
| 4444 | Metasploit 默认 |
| 50050, 50055 | Cobalt Strike |
| 31337 | Back Orifice |
| 40056 | Gh0st RAT |
| 6606 | NjRAT |
| 7707 | Quasar RAT |
| 8808 | xRAT |

```
工具: cybersec_cloud_mcp_ops_portscan
参数: target="<IP>", ports=[4444,50050,50055,31337,40056,6606,7707,8808]
```

详细端口列表和指纹验证方法参见: [references/hacker-tool-ports.md](references/hacker-tool-ports.md)

## Phase 7: DNS 历史与 C 段分析

### DNS 解析历史

```
工具: cybersec_cloud_mcp_dns_history
参数: indicator="<IP>"
返回: 哪些域名曾经解析到这个 IP（A 记录历史）
```

> ⚠️ 注意：DNS 历史记录是历史数据，不代表当前状态。时间差越大，参考价值越低。

### 同 IP 域名

```
工具: cybersec_cloud_mcp_cyberspace-search
参数: query="ip=\"<IP>\"", limit=10, include_raw=true
```

### C 段分析（可选）

```
工具: cybersec_cloud_mcp_cyberspace-search
参数: query="ip=\"<IP前三段>.0/24\"", limit=20, include_raw=true
```

> ⚠️ 必须设置 `include_raw=true`，否则只返回匹配数量，不返回详细数据

**发现关联 IOC 时**:
| 发现的 IOC | 调用技能 | 条件 |
|-----------|---------|------|
| 关联域名 | domain-analysis | ≤5 个自动分析 |
| 关联 URL | url-analysis | ≤3 个自动分析 |

## Phase 8: 深度风险评估

在快速分析评分基础上，增加以下指标：

| 指标 | 分值 | 说明 |
|------|------|------|
| C2 指纹确认 | +40 | 多重指纹匹配 |
| 开放高危端口 | +10 | 如 445/3389 等 |
| 多个可疑端口 (≥3) | +10 | 多个可疑端口组合 |

**历史情报时间衰减**（当端口已关闭时应用）:
| 情报时间 | 衰减系数 |
|----------|---------|
| 7 天内 | ×1.0 |
| 8-30 天 | ×0.8 |
| 31-90 天 | ×0.5 |
| 91-180 天 | ×0.3 |
| 180 天以上 | ×0.1 |

**情报与扫描结果矛盾处理**:
| 场景 | 情报结果 | 扫描结果 | 判定 |
|------|---------|---------|------|
| A | 端口有 C2 活动 | 端口开放 | 高风险：情报与扫描一致 |
| B | 端口有 C2 活动 | 端口关闭 | 中风险：应用时间衰减 |
| C | 无恶意情报 | 端口开放 | 低风险：待验证 |
| D | 无恶意情报 | 端口关闭 | 安全：无威胁迹象 |

## Phase 9: 输出报告

**关联 IOC 填写约束**：
- 只有拿到具体哈希（MD5/SHA1/SHA256）时，才写入“关联样本哈希”
- 家族名（如 Gh0st、Zegost、ShellLoader）必须写入“关联家族名”
- 标签（如 c2、cc、botnet、scanner）必须写入“关联标签”
- 如果情报源只返回数量、未返回明细，明确写“未返回具体明细”，不要臆造内容

> ⚠️ **必须执行**，按 [references/report-format.md](references/report-format.md) 中的**深度分析报告模板**输出（8 章节）：

```markdown
# [!] IP 威胁分析报告
**威胁等级**: [HIGH] (评分: 55)
**分析时间**: YYYY-MM-DD HH:MM
**分析模式**: 深度分析
---
## 1. 基础信息
- **IP 地址**: <IP>
- **IP 类型**: 公网地址
- **地理位置**: <国家> / <省/州> / <城市>
- **ASN**: AS<号码> (<组织名>)
- **ISP**: <ISP名称>
- **PTR 记录**: <PTR> 或 无
- **匿名性**: VPN / Tor / 代理 / 无
---
## 2. 威胁情报
| 来源 | 判定 | 标签 | 首次发现 | 最后活跃 |
|------|------|------|----------|----------|
| <来源名> | malicious | c2, scanner | YYYY-MM-DD | YYYY-MM-DD |

**关联情报数量**: X 条
**关联家族/标签**: <family/tag list> 或 未返回
**关联 C2 端口**: 端口号 (协议)
**情报时效**: 最新活动 YYYY-MM-DD (<状态>)
---
## 3. 开放端口
| 端口 | 服务 | 状态 | Banner |
|------|------|------|--------|
| 22/tcp | SSH | 开放 | OpenSSH 8.2 |
**高危端口检测**: 4444 (C2指纹) - 开放
---
## 4. 关联 IOC
**关联域名** (<X> 个):
- domain[.]example[.]com

**关联样本数量**: X 个

**关联样本哈希**:
- <sha256/md5 list> 或 未返回具体样本哈希

**关联家族名**:
- Gh0st
- Zegost

**关联标签**:
- c2
- cc

**关联 URL** (<X> 个):
- hxxp://domain[.]com/payload
---
## 5. 风险评估
| 指标 | 结果 | 基础分 | 衰减 | 最终分 |
|------|------|--------|------|--------|
| 多源标记恶意 | ✅ X源 | +40 | ×1.0 | +40 |
| C2 标签 | ✅ | +30 | ×1.0 | +30 |
| 恶意样本关联 | 2 个 | +15 | - | +15 |
| 开放高危端口 | ✅ | +10 | - | +10 |
| **总分** | | | | **95** |
---
## 6. 情报与扫描结果对比
**场景**: 情报显示端口有 C2 活动，扫描确认端口开放

**判定**: 高风险 - 情报与扫描一致，C2 活跃
---
## 7. 结论与处置建议
**威胁类型**: C2 服务器
**活跃状态**: 活跃
**风险等级**: 高
**处置建议**:
1. [x] 立即阻断 - 在防火墙中封锁该 IP
2. [x] 内部排查 - 检查是否有主机与该 IP 通信
3. [x] 取证分析 - 保留通信日志和流量样本
4. [x] 持续监控 - 加入威胁情报监控列表
---
## 8. 分析局限性
由 LLM 根据实际分析情况动态填写，例如：
- 情报源返回数据不完整
- 部分端口未扫描
- DNS 历史记录缺失等
```


---

## 工具命令速查

| 任务 | 命令 |
|------|------|
| 本地验证（含PTR） | `python <SKILL_DIR>/scripts/ip_validate.py <IP>` |
| 提取 SSL 证书域名 | `python <SKILL_DIR>/scripts/extract_ssl_domains.py <cert_file>` |

---

## 参考文件

- [references/report-format.md](references/report-format.md) - 报告格式规范（含快速/深度分析两种模板）
- [references/hacker-tool-ports.md](references/hacker-tool-ports.md) - C2/RAT 端口与指纹
- [references/risk-scoring.md](references/risk-scoring.md) - 详细评分规则
- [references/high-risk-asn.md](references/high-risk-asn.md) - 高风险 ASN 列表

## MITRE ATT&CK 映射

| Tactic | Technique | 子技术 | IP 分析场景 |
|--------|-----------|--------|-------------|
| Reconnaissance (TA0043) | **T1595** Active Scanning | **T1595.001** Scanning IP Blocks | 端口扫描源 IP 检测 |
| Reconnaissance (TA0043) | **T1595** Active Scanning | **T1595.002** Vulnerability Scanning | 漏洞扫描源 IP 识别 |
| Reconnaissance (TA0043) | **T1592** Gather Victim Host Information | — | 通过 IP 收集主机信息 |
| Initial Access (TA0001) | **T1190** Exploit Public-Facing Applications | — | 利用源 IP 追踪 |
| Command and Control (TA0011) | **T1071** Application Layer Protocol | **T1071.001** Web Protocols | C2 服务器 IP 检测 |
| Command and Control (TA0011) | **T1071** Application Layer Protocol | **T1071.004** DNS | DNS 隧道 C2 IP |
| Command and Control (TA0011) | **T1573** Encrypted Channel | **T1573.002** Asymmetric Cryptography | 加密 C2 IP 通信 |
| Command and Control (TA0011) | **T1105** Ingress Tool Transfer | — | 下载后续载荷的 C2 IP |
| Discovery (TA0007) | **T1046** Network Service Discovery | — | 内网扫描源 IP |
| Defense Evasion (TA0005) | **T1090** Proxy | **T1090.002** External Proxy | 代理跳板 IP 识别 |
| Defense Evasion (TA0005) | **T1090** Proxy | **T1090.003** Multi-hop Proxy | 多跳代理 IP 链 |
| Defense Evasion (TA0005) | **T1090** Proxy | **T1090.004** Domain Fronting | 域前置隐藏真实 C2 IP |
| Exfiltration (TA0010) | **T1041** Exfiltration Over C2 Channel | — | 数据外传目的 IP |
| Impact (TA0040) | **T1498** Network Denial of Service | **T1498.001** Direct Network Flood | DDoS 攻击源 IP |
| Impact (TA0040) | **T1498** Network Denial of Service | **T1498.002** Reflection Amplification | 反射放大攻击 IP |

### ATT&CK Mitigations

| Mitigation | ID | 应用场景 |
|-----------|-----|--------|
| Network Intrusion Prevention | **M1031** | 基于 IP 威胁情报阻断恶意 IP |
| Filter Network Traffic | **M1037** | IP 黑名单过滤 |
| Network Segmentation | **M1030** | 隔离受感染网段，限制横向 IP 通信 |
| Internet Access | **M1036** | 代理所有出站流量，监控目的 IP |
| Threat Intelligence Program | **M1019** | 建立 IP 威胁情报订阅和集成 |

## OWASP Top 10 / CWE 映射

| OWASP 类别 | CWE | ATT&CK | IP 分析场景 |
|-----------|------|--------|------------|
| **A01 Broken Access Control** | CWE-284 | T1046 | 未授权 IP 访问内部服务 |
| **A05 Security Misconfiguration** | CWE-16 | T1071.001 | 错误配置暴露内部 IP 给公网 |
| **A06 Vulnerable Components** | CWE-1035 | T1190 | 已知漏洞组件被特定 IP 利用 |
| **A09 Logging/Monitoring** | CWE-778 | T1595 | 未记录扫描源 IP |
| **A10 SSRF** | CWE-918 | T1190 | SSRF 利用内网 IP 访问 |

## 合规框架参考

| 标准 | 条款 | IP 分析关联 |
|------|------|-------------|
| **ISO 27001** | A.8.20 网络安全 | 网络边界 IP 监控和阻断 |
| **ISO 27001** | A.8.16 监控活动 | IP 地址活动监控和告警 |
| **NIST SP 800-53** | SI-3 恶意代码防护 | 基于恶意 IP 阻断通信 |
| **NIST SP 800-53** | SC-7 边界保护 | 边界防火墙 IP 过滤 |
| **NIST SP 800-53** | IA-3 设备标识和认证 | IP 设备标识与验证 |
| **GDPR** | Art. 32 安全处理 | IP 地址作为 PII 的处理保护 |
| **PCI DSS** | 1.2 网络安全控制 | 限制到卡数据环境的 IP 访问 |
| **等保2.0** | 8.1.2 网络通信 | IP 地址访问控制和审计 |

## Sigma 检测规则

### Sigma 规则 1：已知恶意 IP 通信检测
```yaml
title: Communication with Known Malicious IP
description: Detects internal hosts communicating with known threat IPs
description: Detects internal hosts communicating with known threat indicator IPs
status: experimental
author: sec-skills
logsource:
    product: firewall
    category: network_connection
detection:
    selection:
        DestinationIp|cidr:
            - '203.0.113.0/24'  # 替换为实际威胁 IP CIDR
            - '198.51.100.0/24'
    condition: selection
falsepositives:
    - Legitimate service on shared hosting
level: high
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1105
```

### Sigma 规则 2：端口扫描行为检测
```yaml
title: Potential Port Scanning Activity
description: Detects single source IP attempting connections to many ports
status: experimental
author: sec-skills
logsource:
    product: firewall
    category: network_connection
detection:
    selection:
        SourceIp: '*'
    timeframe: 1m
    condition: selection | count(DestinationPort) by SourceIp > 20
falsepositives:
    - Network security scanner (Nessus, Nmap)
    - Load balancer health checks
level: medium
tags:
    - attack.reconnaissance
    - attack.t1595.001
    - attack.t1046
```

## YARA 检测规则

```yara
rule Suspicious_Network_Beacon_IP
{
    meta:
        description = "Detects hardcoded C2 IP addresses in binary samples"
        author = "sec-skills"
    strings:
        $ipv4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/
        $port_combo = /(?:\d{1,3}\.){3}\d{1,3}:(\d{2,5})/
        $http_ip = /http:\/\/(?:\d{1,3}\.){3}\d{1,3}/
        $connect = /connect\((?:\d{1,3}\.){3}\d{1,3}/
    condition:
        $ipv4 and ($port_combo or $http_ip or $connect)
}
```

## CVE 参考表

| CVE | 漏洞 | IP 分析关联 |
|-----|------|------------|
| CVE-2021-44228 | Log4Shell JNDI 注入 | C2 回连 IP 检测和阻断 |
| CVE-2017-11882 | Office 公式编辑器 RCE | 恶意文档回连 C2 IP |
| CVE-2023-22515 | Confluence 权限提升 | 攻击者 IP 追踪 |
| CVE-2021-26855 | Exchange ProxyLogon | 邮件服务器攻击源 IP |
| CVE-2023-23375 | Windows SmartScreen 绕过 | 恶意下载源 IP |

## IOC 采集指引

| IOC 类型 | 提取方法 | 格式 | 后续处理 |
|---------|---------|------|--------|
| 源 IP | 防火墙/IDS 日志提取 | `192.168.1.100` | → 威胁情报查询 |
| 目的 IP | 代理/网关日志提取 | `203.0.113.50` | → 威胁情报查询 |
| IP+端口 | netflow/连接日志 | `203.0.113.50:4444` | → C2 端口指纹匹配 |
| PTR 记录 | DNS 反向解析 | `malicious.example.com` | → domain-analysis |
| ASN 信息 | WHOIS/geo 查询 | `AS12345 (ISP Name)` | → 高风险 ASN 比对 |
| CIDR 段 | C 段扫描发现 | `203.0.113.0/24` | → C 段关联分析 |
| 关联域名 | DNS 历史记录 | `domain.com → IP` | → domain-analysis |
| SSL 证书 | 证书 SAN/CN 提取 | `*.malicious.com` | → domain-analysis |

## 跨技能工作流

### 工作流 1：C2 IP 发现与阻断
```
traffic-analysis / binary-reverse-engineering → 发现可疑 C2 IP
  → ip-analysis (威胁情报查询 + 端口扫描)
  → 关联域名 → domain-analysis
  → 部署 Sigma 规则 → SIEM 告警
  → 防火墙阻断 IP
```

### 工作流 2：钓鱼邮件源 IP 追踪
```
phishing-analysis → 提取发件人 IP
  → ip-analysis (地理位置 + 威胁情报)
  → email-osint (邮箱关联)
  → ttp-extractor (技术映射)
  → pdf-report (威胁报告)
```

### 工作流 3：入侵响应 IP 排查
```
linux-ir/windows-ir/macos-ir → 提取异常连接 IP
  → ip-analysis (批量分析公网 IP)
  → auth-log-analysis (关联登录源 IP)
  → traffic-analysis (流量关联)
  → 阻断恶意 IP + 生成 IOC 清单
```

## 技能关联

**上游**（调用本技能）: phishing-analysis, traffic-analysis, binary-reverse-engineering, auth-log-analysis

**下游**（本技能调用）: domain-analysis, url-analysis
