---
name: asset-monitor
description: 企业攻击面资产发现、持续监控与安全基线检测。当用户要求"监控域名"、"资产发现"、"子域名枚举"、"攻击面测绘"、"资产变更"、"扫描资产"、"查看资产"、"EASM"、"两高一弱"、"高危漏洞检测"、"高危端口检测"、"弱口令检测"、"安全基线检测"、"暴露面分析"时使用此技能。
metadata:
  version: 4.3.0
  builtin: true
---

# 攻击面资产监控

集成资产发现、持续监控、变更告警、两高一弱检测的一体化攻击面管理技能。

---

## 依赖要求

**MCP 服务**:
| MCP | 工具 | 用途 |
|------|------|------|
| **asm-server** | asm_* | 资产数据存储与管理 |
| cybersec-cloud | cybersec_cloud_mcp_subdomain_discovery | 子域名发现（首选） |
| cybersec-cloud | cybersec_cloud_mcp_dns_history | DNS 解析历史（关联分析） |
| cybersec-cloud | cybersec_cloud_mcp_cyberspace-search | 网络空间资产搜索 |
| cybersec-cloud | cybersec_cloud_mcp_intel_icp_lookup | ICP 备案查询 |
| cybersec-cloud | cybersec_cloud_mcp_ops_portscan | 端口扫描 |
| cybersec-cloud | cybersec_cloud_mcp_risk_insight | 资产威胁情报 |

---

## 执行检查清单

### 执行前检查

```
MCP 调用: asm_list_targets
参数: {}
```

如果没有目标，需要先创建。

### 发现资产后（必须执行）

```
# 1. 创建监控目标
MCP 调用: asm_create_target
参数: {
  "name": "公司名",
  "type": "organization",
  "seed_domains": ["example.com", "example.cn"]
}
返回: target 对象，记录 id 字段

# 2. 保存发现的资产（必须包含 attributes 和风险标记）
MCP 调用: asm_create_assets
参数: {
  "assets": [
    {
      "target_id": "target_xxx",
      "type": "subdomain",
      "value": "api.example.com",
      "risk_level": "high",
      "risk_reason": "API接口暴露",
      "attributes": {"ip": "1.2.3.4", "port": 443},
      "tags": ["api", "https"]
    },
    {
      "target_id": "target_xxx",
      "type": "subdomain",
      "value": "admin.example.com",
      "risk_level": "high",
      "risk_reason": "管理后台暴露",
      "attributes": {"ip": "1.2.3.5", "port": 443},
      "tags": ["admin"]
    },
    {
      "target_id": "target_xxx",
      "type": "port",
      "value": "1.2.3.4:22",
      "risk_level": "critical",
      "risk_reason": "SSH暴露公网",
      "attributes": {"hostname": "api.example.com", "service": "ssh"},
      "tags": ["ssh", "high-risk-port"]
    }
  ]
}
```

**重要**: `attributes` 字段用于存储 IP、端口、服务等扩展信息，`tags` 用于分类标签。

**子域名自动风险标记规则**：
| 模式 | risk_level | risk_reason |
|------|------------|-------------|
| `*test*`, `*dev*`, `*uat*`, `*staging*` | high | 测试环境暴露 |
| `*admin*`, `*manage*`, `*backend*` | high | 管理后台暴露 |
| `*api*`, `*gateway*` | high | API接口暴露 |
| `*git*`, `*svn*`, `*jenkins*`, `*gitlab*` | critical | DevOps系统暴露 |
| `*vpn*`, `*sslvpn*`, `*remote*` | medium | 远程访问入口 |
| `*mail*`, `*owa*`, `*webmail*` | medium | 邮件系统 |

### 执行结束前（必须验证）

```
# 确认资产已保存
MCP 调用: asm_get_stats
参数: {"target_id": "target_xxx"}
```

### 检查清单摘要

| 阶段 | 必须执行 | MCP 工具 |
|------|----------|----------|
| 开始前 | 检查已有目标 | `asm_list_targets` |
| 目标确认后 | 创建目标 | `asm_create_target` |
| 资产发现后 | **保存资产** | `asm_create_assets` |
| 结束前 | 验证保存 | `asm_get_stats` |

---

## 资产发现工作流

### Phase 1: 目标确认

| 输入类型 | 处理方式 |
|----------|----------|
| 主域名 (example.com) | 直接分析 |
| 企业名称 | ICP 查询获取域名 |
| IP 段 (192.168.1.0/24) | CIDR 搜索 |

**创建监控目标**:
```
MCP 调用: asm_create_target
参数: {
  "name": "示例公司",
  "target_type": "organization",
  "seed_domains": ["example.com", "example.cn"]
}
```

### Phase 2: ICP 备案查询

```
MCP 调用: cybersec_cloud_mcp_intel_icp_lookup
参数: domain = "example.com"
```

提取关联域名和企业信息。

### Phase 3: 子域名枚举

**网络空间搜索（首选）**:
```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com"
参数: include_raw=true, limit=100
```

**高价值子域名识别**:
| 模式 | 风险 | 说明 |
|------|------|------|
| admin/管理/后台 | 高 | 管理入口 |
| api/gateway | 高 | API 接口暴露 |
| dev/test/staging/uat | 高 | 测试环境 |
| git/svn/jenkins | 高 | DevOps |
| vpn/sslvpn | 中 | 远程访问 |
| mail/owa/imap | 中 | 邮件系统 |
| iam/sso | 中 | 身份认证 |

### Phase 4: 敏感资产深度扫描

**测试环境搜索**:
```
MCP: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com" && (hostname="*test*" || hostname="*dev*" || hostname="*uat*")
```

**管理后台搜索**:
```
MCP: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com" && (title="admin" || title="管理" || title="login")
```

**高危端口搜索**:
```
MCP: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com" && (port=22 || port=3389 || port=3306 || port=6379)
```

### Phase 5: 漏洞检测

```
MCP: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com" && vuln!=""
```

### Phase 6: 保存结果（关键步骤）

**从 cybersec_cloud_mcp_cyberspace-search 结果提取并入库**:

cybersec_cloud_mcp_cyberspace-search 返回格式：
```json
{"domain": "api.example.com", "ip": "1.2.3.4", "port": 443, "update_time": "..."}
```

转换为 asm_create_assets 格式：
```
MCP 调用: asm_create_assets
参数: {
  "assets": [
    {
      "target_id": "target_xxx",
      "type": "subdomain",
      "value": "api.example.com",
      "risk_level": "high",
      "risk_reason": "API接口暴露",
      "attributes": {"ip": "1.2.3.4", "port": 443, "last_seen": "2026-01-02"},
      "tags": ["api"]
    },
    {
      "target_id": "target_xxx",
      "type": "ip",
      "value": "1.2.3.4",
      "risk_level": "low",
      "attributes": {"hostnames": ["api.example.com", "admin.example.com"]},
      "tags": ["shared-ip"]
    },
    {
      "target_id": "target_xxx",
      "type": "port",
      "value": "1.2.3.4:22",
      "risk_level": "critical",
      "risk_reason": "SSH暴露公网",
      "attributes": {"hostname": "api.example.com", "service": "ssh", "banner": "OpenSSH 8.0"},
      "tags": ["ssh", "high-risk-port"]
    }
  ]
}
```

**资产字段说明**:
| 字段 | 必需 | 说明 |
|------|------|------|
| target_id | 是 | 来自 asm_create_target |
| type | 是 | subdomain / ip / port / certificate / webapp |
| value | 是 | 资产值（子域名、IP、IP:端口） |
| risk_level | 建议 | safe / low / medium / high / critical / unknown |
| risk_reason | 建议 | 风险原因说明 |
| **attributes** | **建议** | **JSON 对象，存储 IP、端口、服务、banner 等扩展信息** |
| **tags** | 建议 | 字符串数组，用于分类标签 |

**attributes 常用字段**:
| 资产类型 | attributes 示例 |
|----------|----------------|
| subdomain | `{"ip": "1.2.3.4", "port": 443, "title": "登录页面"}` |
| ip | `{"hostnames": ["a.com", "b.com"], "asn": 12345, "geo": "CN"}` |
| port | `{"hostname": "a.com", "service": "nginx", "version": "1.18", "banner": "..."}` |
| certificate | `{"issuer": "DigiCert", "expiry": "2025-06-01", "subject": "*.example.com"}` |
| webapp | `{"title": "管理后台", "status_code": 200, "technologies": ["React", "nginx"]}` |

**验证保存**:
```
MCP 调用: asm_get_stats
参数: {"target_id": "target_xxx"}
```

---

## 两高一弱检测

> **触发词**: "两高一弱"、"高危漏洞检测"、"高危端口检测"、"弱口令检测"、"安全基线检测"

### 高危漏洞检测

```
MCP: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com" && vuln!=""
```

### 高危端口检测

```
MCP: cybersec_cloud_mcp_ops_portscan
参数: target="x.x.x.x", ports=[22,23,445,1433,3306,3389,5432,6379,27017,9200]
```

**高危端口清单**:
| 端口 | 服务 | 风险 |
|------|------|------|
| 22 | SSH | 远程访问 |
| 23 | Telnet | 明文传输 |
| 3389 | RDP | Windows 远程 |
| 3306 | MySQL | 数据库暴露 |
| 6379 | Redis | 未授权访问 |
| 27017 | MongoDB | 数据泄露 |

### 弱口令检测

> 需要授权，仅限自有资产

详细检测流程参见: [references/baseline-detection.md](references/baseline-detection.md)

---

## 查看与管理资产

### 查看资产列表

```
MCP 调用: asm_list_assets
参数: {
  "target_id": "target_xxx",    // 可选：按目标筛选
  "asset_type": "subdomain",    // 可选：按类型筛选
  "risk_level": "high",         // 可选：按风险筛选
  "limit": 50,
  "offset": 0
}
```

### 查看统计信息

```
MCP 调用: asm_get_stats
参数: {"target_id": "target_xxx"}  // 可选
```

### 查看变更告警

```
MCP 调用: asm_list_changes
参数: {
  "target_id": "target_xxx",    // 可选
  "is_acknowledged": false,     // 只看未确认的
  "severity": "high",           // 可选：按严重程度筛选
  "limit": 50
}
```

### 确认变更

```
MCP 调用: asm_acknowledge_change
参数: {
  "id": "change_xxx"           // 确认单个变更
}
// 或
参数: {
  "target_id": "target_xxx"    // 确认该目标所有变更
}
// 或
参数: {
  "all": true                  // 确认所有变更
}
```

---

## MCP 工具速查

### asm-server 工具

| 工具 | 用途 | 关键参数 |
|------|------|----------|
| `asm_create_target` | 创建监控目标 | name, target_type, seed_domains |
| `asm_list_targets` | 列出所有目标 | status, limit |
| `asm_get_target` | 获取目标详情 | id |
| `asm_update_target` | 更新目标 | id, name, status |
| `asm_delete_target` | 删除目标 | id |
| `asm_create_assets` | 批量创建资产 | assets[] |
| `asm_list_assets` | 列出资产 | target_id, asset_type, risk_level |
| `asm_get_asset` | 获取资产详情 | id |
| `asm_update_asset` | 更新资产 | id, risk_level, risk_reason |
| `asm_delete_asset` | 删除资产 | id |
| `asm_get_stats` | 获取统计 | target_id |
| `asm_list_changes` | 列出变更 | target_id, is_acknowledged, severity |
| `asm_acknowledge_change` | 确认变更 | id / target_id / all |

### cybersec-cloud 工具

| 任务 | 命令 |
|------|------|
| **子域名发现** | `cybersec_cloud_mcp_subdomain_discovery: domain="example.com" limit=1000` |
| **DNS 历史** | `cybersec_cloud_mcp_dns_history: indicator="example.com" limit=100` |
| 子域名搜索(补充) | `cybersec_cloud_mcp_cyberspace-search: hostname="*.domain.com"` |
| 高危端口 | `cybersec_cloud_mcp_cyberspace-search: hostname="*.domain.com" && port=22` |
| 漏洞搜索 | `cybersec_cloud_mcp_cyberspace-search: hostname="*.domain.com" && vuln!=""` |
| 测试环境 | `cybersec_cloud_mcp_cyberspace-search: hostname="*test*" \|\| hostname="*uat*"` |
| ICP 查询 | `cybersec_cloud_mcp_intel_icp_lookup: domain` |
| 端口扫描 | `cybersec_cloud_mcp_ops_portscan: target, ports` |

---

## 常见场景

### 场景 1: 新目标监控

用户: "监控 example.com"

1. 创建目标: `asm_create_target`
2. ICP 查询: `cybersec_cloud_mcp_intel_icp_lookup`
3. 子域名发现: `cybersec_cloud_mcp_subdomain_discovery domain="example.com" limit=1000`
4. 端口扫描: `cybersec_cloud_mcp_ops_portscan`
5. 保存结果: `asm_create_assets`
6. 验证统计: `asm_get_stats`

### 场景 2: 查看资产状态

用户: "查看资产" 或 "资产列表"

```
asm_get_stats -> 总览
asm_list_assets -> 详细列表
asm_list_changes -> 最近变更
```

### 场景 3: 处理告警

用户: "资产变更" 或 "有什么新发现"

```
asm_list_changes: is_acknowledged=false, severity=high
asm_acknowledge_change: id=xxx  // 处理后确认
```

---

## 关联技能调用

| 发现的资产 | 调用技能 |
|-----------|---------|
| 可疑域名 | `domain-analysis` |
| 外部 IP | `ip-analysis` |
| Web 服务 | `url-analysis` |

---

---

## ATT&CK 技术映射表

资产监控作为攻击面管理（ASM）技能，覆盖攻击者的侦察和初始访问阶段。

| 战术 | 技术 | 子技术 | 资产监控关联 |
|------|------|--------|-------------|
| Reconnaissance | T1595 | Active Scanning | 检测对资产的端口扫描和服务探测 |
| Reconnaissance | T1595.001 | Scanning IP Blocks | 监控 CIDR 范围内的扫描活动 |
| Reconnaissance | T1595.002 | Vulnerability Scanning | 检测针对暴露资产的漏洞扫描 |
| Reconnaissance | T1592 | Gather Victim Host Info | 资产指纹信息（OS/服务/版本）被攻击者收集 |
| Reconnaissance | T1592.001 | Hardware | 资产硬件信息暴露 |
| Reconnaissance | T1592.002 | Software | 资产软件版本信息暴露 |
| Reconnaissance | T1592.004 | Client Configurations | 客户端配置信息泄露 |
| Reconnaissance | T1590 | Gather Victim Host Information | 子域名/IP/端口等基础设施侦察 |
| Reconnaissance | T1590.001 | Domains | 子域名枚举监控 |
| Reconnaissance | T1590.002 | DNS | DNS 解析历史和子域名发现 |
| Reconnaissance | T1590.004 | Mail | 邮件服务器资产发现 |
| Reconnaissance | T1590.005 | IP Addresses | IP 资产发现和变更监控 |
| Reconnaissance | T1589 | Gather Victim Identity Info | 通过 ICP 备案查询获取企业身份信息 |
| Initial Access | T1190 | Exploit Public-Facing Application | 暴露面资产被利用入口 |
| Initial Access | T1566 | Phishing | 邮件系统资产暴露作为钓鱼目标 |
| Discovery | T1046 | Network Service Discovery | 高危端口扫描和服务发现 |
| Discovery | T1082 | System Information Discovery | 资产指纹和版本信息收集 |
| Defense Evasion | T1036 | Masquerading | 资产伪装检测（非标准端口/服务不匹配） |
| Defense Evasion | T1105 | Ingress Tool Transfer | 检测可疑文件传输到暴露资产 |
| Exfiltration | T1567 | Exfiltration Over Web Service | 数据通过暴露的 Web 资产外传 |

### ATT&CK 缓解措施

| Mitigation ID | 名称 | 资产监控关联 |
|--------------|------|-------------|
| M1056 | Precompromise | 资产发现和攻击面缩减（Attack Surface Reduction） |
| M1041 | Encrypt Sensitive Information | 敏感资产加密通信（HTTPS） |
| M1042 | Disable or Remove Unnecessary Services | 关闭不必要的高危端口和服务 |
| M1035 | Limit Access to Resource Over Network | 资产访问控制（IP 白名单/WAF） |
| M1032 | Multi-factor Authentication | 管理后台和多因子认证 |

---

## OWASP Top 10 映射表

攻击面资产暴露与 Web 安全风险交叉映射。

| OWASP 类别 | CWE | ATT&CK | 资产监控关联 |
|------------|-----|--------|-------------|
| A01 — Broken Access Control | CWE-284 | T1190 | 管理后台暴露（admin.* 子域名） |
| A02 — Cryptographic Failures | CWE-319 | T1040 | 资产明文协议暴露（HTTP/Telnet/FTP） |
| A03 — Injection | CWE-89 | T1190 | 存在漏洞的 Web 应用资产 |
| A04 — Insecure Design | CWE-209 | T1592 | 资产信息泄露（错误信息/banner） |
| A05 — Security Misconfiguration | CWE-16 | T1036 | 默认凭证/配置错误的服务暴露 |
| A06 — Vulnerable & Outdated Components | CWE-1035 | T1592.002 | 过时软件版本和服务暴露 |
| A07 — Identification & Authentication Failures | CWE-287 | T1566 | 弱口令和认证缺失资产 |
| A08 — Software & Data Integrity Failures | CWE-506 | T1190 | 未签名/不可信的代码部署 |
| A09 — Security Logging & Monitoring Failures | CWE-778 | T1595 | 资产变更和扫描行为缺乏监控 |
| A10 — SSRF | CWE-918 | T1190 | 内网资产被 SSRF 利用 |

---

## Sigma 检测规则

### 规则 1: 高危端口暴露检测

```yaml
title: 高危端口暴露到公网
id: 5a3c2d8e-1b2c-4d5e-9f01-a2b3c4d5e6f7
status: experimental
description: 检测防火墙日志中暴露在公网的高危端口（SSH/RDP/数据库等）
author: asset-monitor
logsource:
    product: firewall
    service: connection
detection:
    selection:
        action: accept
        dst_port:
            - 22
            - 23
            - 445
            - 1433
            - 3306
            - 3389
            - 5432
            - 6379
            - 27017
            - 9200
    condition: selection
falsepositives:
    - 合法运维管理访问（需验证白名单）
level: high
tags:
    - attack.reconnaissance
    - attack.discovery
    - attack.t1595
    - attack.t1046
    - owasp.a05.2021
```

### 规则 2: 子域名异常变更检测

```yaml
title: 新增可疑子域名告警
id: 7e8f9a0b-1c2d-4e3f-8a90-b1c2d3e4f5a6
status: experimental
description: 检测 DNS 日志中新增的包含高危关键词的子域名（可能是影子资产或攻击者注册）
author: asset-monitor
logsource:
    product: dns
    service: query
detection:
    selection_new:
        event_type: answer
        answer_type: A
    filter_high_risk:
        query:
            contains:
                - admin
                - dev
                - test
                - staging
                - uat
                - git
                - jenkins
                - vpn
                - sslvpn
                - backup
                - internal
    condition: selection_new and filter_high_risk
falsepositives:
    - 业务部门合法新增子域名
    - DNS 缓存残留记录
level: medium
timeframe: 24h
tags:
    - attack.reconnaissance
    - attack.t1590.001
    - attack.t1590.002
    - owasp.a05.2021
```

---

## CVE 参考表

资产监控需要关注的典型 CVE 暴露场景。

| CVE | 漏洞名称 | 影响资产类型 | 检测方法 |
|-----|---------|-------------|----------|
| CVE-2021-44228 | Log4Shell (Log4j RCE) | Java Web 应用 | `cyberspace-search: hostname="*.com" && vuln="Log4Shell"` |
| CVE-2022-22965 | Spring4Shell (Spring RCE) | Spring Framework 应用 | `cyberspace-search: hostname="*.com" && vuln="Spring4Shell"` |
| CVE-2017-0144 | EternalBlue (MS17-010) | Windows SMB (445) | `cyberspace-search: port=445 && vuln!=""` |
| CVE-2019-0708 | BlueKeep (RDP RCE) | Windows RDP (3389) | `cyberspace-search: port=3389 && vuln!=""` |
| CVE-2021-26855 | ProxyLogon (Exchange) | Exchange 邮件服务器 | `cyberspace-search: hostname="*mail*" && vuln!=""` |

---

## IOC 采集指引

资产监控过程中提取的 IOC 应标准化存储并转发到下游分析技能。

| IOC 类型 | 采集来源 | 格式 | 优先级 | 处置 |
|---------|---------|------|--------|------|
| 恶意 IP | 端口扫描源 IP / 资产访问日志 | IPv4/IPv6 | 🔴 高 | 转发 → `ip-analysis` |
| 可疑域名 | 新增子域名 / DNS 变更 | FQDN | 🟡 中 | 转发 → `domain-analysis` |
| 恶意 URL | Web 应用漏洞扫描结果 | HTTP/HTTPS URL | 🔴 高 | 转发 → `url-analysis` |
| 暴露端口 | 端口扫描结果 | IP:Port | 🔴 高 | 记录 → `asm_create_assets` |
| 服务 Banner | 资产指纹识别 | 字符串 | 🟡 中 | 记录 → `attributes.banner` |
| SSL 证书信息 | 证书监控 | PEM/Subject/Issuer | 🟡 中 | 记录 → `attributes.certificate` |
| CVE 标识 | 漏洞扫描结果 | CVE-YYYY-NNNNN | 🔴 高 | 转发 → `researching-vulnerabilities` |
| ICP 备案 | 企业资产关联 | JSON | 🟢 低 | 记录 → `target.attributes` |
| 资产指纹 | 服务版本识别 | Server/Version 字符串 | 🟡 中 | 记录 → `attributes.service` |
| 变更记录 | 资产对比 | JSON (added/removed/changed) | 🟡 中 | 记录 → `asm_list_changes` |

---

## 合规标准参考

| 标准 | 章节 | 资产监控关联 |
|------|------|-------------|
| ISO 27001 | A.8.1 资产管理 | 资产清单和分类是 ISMS 基础 |
| ISO 27001 | A.12.5 运行软件技术漏洞 | 暴露面漏洞检测和修复验证 |
| ISO 27001 | A.13.1 网络安全管理 | 高危端口暴露和网络分段验证 |
| NIST SP 800-53 | RA-3 风险评估 | 资产风险评估和暴露面分析 |
| NIST SP 800-53 | CM-8 信息系统资产清单 | 资产发现和持续监控 |
| NIST SP 800-53 | SC-7 边界保护 | 高危端口暴露检测和访问控制 |
| NIST SP 800-40 | 补丁管理 | 漏洞资产识别和修复优先级 |
| NIST CSF | Identify (ID.AM) | 资产识别是网络安全框架基础 |
| GDPR | Art.32 | 安全措施需要资产可见性和暴露面管理 |
| PIPL | 第五十五条 | 重要数据资产的安全风险评估 |
| 等保2.0 | 第八章 网络通信安全 | 资产发现和高危端口检测是网络边界安全基础 |
| 等保2.0 | 第九章 环境安全 | 资产清单和攻击面管理是环境安全基线 |

---

## 跨技能工作流

### 工作流 1: 资产发现 → 深度分析

```
asset-monitor (发现资产)
  ├→ domain-analysis (可疑域名深度分析)
  ├→ ip-analysis (恶意 IP 关联分析)
  ├→ url-analysis (Web 服务 URL 分析)
  └→ researching-vulnerabilities (漏洞研究和验证)
```

### 工作流 2: 资产变更 → 应急响应

```
asset-monitor (检测变更)
  ├→ traffic-analysis (关联流量异常)
  ├→ linux-ir / windows-ir / macos-ir (主机应急响应)
  └→ ttp-extractor (提取攻击者 TTP)
```

### 工作流 3: 暴露面报告 → 安全评估

```
asset-monitor (攻击面报告)
  ├→ asset-discovery (补充资产发现)
  ├→ code-audit (暴露 Web 应用代码审计)
  ├→ pdf-report (生成评估报告)
  └→ data-desensitize (报告脱敏处理)
```

---

## 参考文件

- [references/report-format.md](references/report-format.md) - 报告格式规范
- [references/risk-assessment.md](references/risk-assessment.md) - 风险评估标准
- [references/baseline-detection.md](references/baseline-detection.md) - 两高一弱检测详情
