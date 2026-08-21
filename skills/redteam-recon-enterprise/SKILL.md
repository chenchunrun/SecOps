---
name: redteam-recon-enterprise
description: 企业级目标情报收集。对目标企业进行资产发现、技术栈识别和攻击面测绘。当用户要求"企业资产发现"、"攻击面测绘"、"目标侦察"、"企业情报收集"、"外部资产发现"时使用此技能。
metadata:
  version: 2.1.0
  builtin: true
  category: redteam-recon
---

# 企业级目标情报

对目标企业进行全面的资产发现和攻击面测绘，为渗透测试提供情报支持。

## 依赖要求

**Python 环境**: Python 3.8+

**安装依赖**:
```bash
pip3 install -r requirements.txt
```

**环境检测**:
```bash
python3 scripts/check_env.py
```

## 执行超时说明

> ⚠️ **重要**: 企业侦察涉及多阶段扫描，需要较长执行时间，请耐心等待。

| 工具/阶段 | 默认超时 | 说明 |
|----------|---------|------|
| `enterprise_recon.py` (完整) | **~5分钟** | 完整侦察流程 |
| subfinder | **120s** (2分钟) | 子域名枚举 |
| crt.sh 查询 | 30s | 证书透明度 |
| 端口扫描 | ~2s/端口 | 取决于端口数量 |
| HTTP 探测 | 10s/目标 | Web 指纹识别 |
| dig DNS | 10s | DNS 记录查询 |

**超时原因**：
- 子域名枚举需要查询多个数据源
- 端口扫描数量大时耗时增加
- 大型企业可能有数十个子域名需要探测

## 核心能力

| 能力 | 实现方式 | 说明 |
|------|----------|------|
| 资产发现 | MCP + 本地脚本 | 子域名、IP、云资产枚举 |
| 技术识别 | 本地脚本 | Web技术栈、服务指纹 |
| 人员情报 | 关联 email-osint | 关键人员识别和画像 |
| 供应链分析 | MCP 搜索 | 第三方服务和依赖 |

## 工具矩阵

### MCP 云服务 (推荐)

通过 Claude 直接调用，无需安装：

| MCP 工具 | 用途 | 调用示例 |
|----------|------|----------|
| `cybersec_cloud_mcp_subdomain_discovery` | 子域名发现 | 查询 target.com 的子域名 |
| `cybersec_cloud_mcp_ops_portscan` | 端口扫描 | 扫描 1.2.3.4 的开放端口 |
| `cybersec_cloud_mcp_intel_icp_lookup` | ICP 备案 | 查询 target.com 的备案信息 |
| `cybersec_cloud_mcp_cyberspace-search` | 空间搜索 | 搜索 domain="target.com" |
| `cybersec_cloud_mcp_dns_history` | DNS 历史 | 查询 target.com 的历史解析 |

### 本地自动化脚本

```bash
# 完整扫描
python3 scripts/enterprise_recon.py -d target.com

# 输出 JSON
python3 scripts/enterprise_recon.py -d target.com --json -o result.json

# 详细模式
python3 scripts/enterprise_recon.py -d target.com -v
```

### 可选本地工具

| 工具 | 用途 | 安装命令 |
|------|------|----------|
| subfinder | 子域名枚举 | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | HTTP探测 | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nmap | 端口扫描 | `brew install nmap` |
| whatweb | Web指纹 | `gem install whatweb` |

---

## 工作流程

```
输入: target.com
     │
     ├─► Phase 1: 基础信息 (ICP备案、WHOIS)
     │     └─► MCP: cybersec_cloud_mcp_intel_icp_lookup
     │
     ├─► Phase 2: 子域名枚举
     │     ├─► MCP: cybersec_cloud_mcp_subdomain_discovery
     │     └─► 本地: enterprise_recon.py (crt.sh + subfinder)
     │
     ├─► Phase 3: IP 资产映射
     │     ├─► MCP: cybersec_cloud_mcp_dns_history
     │     └─► MCP: cybersec_cloud_mcp_cyberspace-search
     │
     ├─► Phase 4: 端口扫描
     │     ├─► MCP: cybersec_cloud_mcp_ops_portscan
     │     └─► 本地: enterprise_recon.py
     │
     ├─► Phase 5: 技术栈识别
     │     └─► 本地: enterprise_recon.py (Web指纹)
     │
     ├─► Phase 6: 人员情报 (可选)
     │     └─► 关联: /email-osint
     │
     └─► 输出: 侦察报告
```

---

## Phase 1: 基础信息

### 1.1 ICP 备案查询

```
MCP 调用: cybersec_cloud_mcp_intel_icp_lookup
参数: domain = "target.com"

提取信息:
- 备案主体 (公司全称)
- 备案号
- 网站名称
- 审核时间
```

### 1.2 WHOIS 查询

```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询: whois domain="target.com"

提取信息:
- 注册商
- 注册时间
- 到期时间
- 联系邮箱 (可能已隐私保护)
```

---

## Phase 2: 子域名枚举

### 2.1 MCP 方式 (推荐)

```
MCP 调用: cybersec_cloud_mcp_subdomain_discovery
参数: domain = "target.com"
```

### 2.2 本地脚本

```bash
python3 scripts/enterprise_recon.py -d target.com
```

脚本自动执行:
- crt.sh 证书透明度查询
- subfinder 被动枚举 (如已安装)
- DNS 记录解析

### 2.3 关键子域名分类

| 类型 | 模式 | 风险等级 | 攻击建议 |
|------|------|---------|---------|
| 邮件 | mail., webmail., owa. | 中 | 钓鱼入口、凭证爆破 |
| VPN | vpn., remote., sslvpn. | 高 | 远程访问入口 |
| API | api., gateway., rest. | 高 | 接口漏洞测试 |
| 开发 | dev., test., staging. | 🔴极高 | 弱配置、测试账号 |
| 管理 | admin., portal., cms. | 高 | 后台入口 |
| 数据库 | db., mysql., redis. | 🔴极高 | 未授权访问 |

---

## Phase 3: IP 资产映射

### 3.1 DNS 解析

```
MCP 调用: cybersec_cloud_mcp_dns_history
参数: domain = "target.com"
```

### 3.2 C 段关联

```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询: ip="1.2.3.0/24"
```

### 3.3 云资产识别

| 云服务 | IP 范围特征 | 存储桶命名 |
|--------|------------|-----------|
| AWS | 特定 IP 段 | s3://target-* |
| Azure | 特定 IP 段 | blob.core.windows.net |
| 阿里云 | 特定 IP 段 | oss-*.aliyuncs.com |
| 腾讯云 | 特定 IP 段 | cos.*.myqcloud.com |

---

## Phase 4: 端口扫描

### 4.1 MCP 扫描

```
MCP 调用: cybersec_cloud_mcp_ops_portscan
参数:
  target = "1.2.3.4"
  ports = "1-1000"  # 或 "top1000"
```

### 4.2 本地扫描

```bash
# 脚本内置扫描
python3 scripts/enterprise_recon.py -d target.com

# nmap (如已安装)
nmap -sV -T4 --top-ports 1000 target.com
```

### 4.3 高价值端口

| 端口 | 服务 | 攻击向量 |
|------|------|---------|
| 21 | FTP | 匿名登录、弱口令 |
| 22 | SSH | 弱口令、密钥泄露 |
| 23 | Telnet | 明文传输、弱口令 |
| 80/443 | HTTP/S | Web 漏洞 |
| 445 | SMB | EternalBlue、弱口令 |
| 1433 | MSSQL | 弱口令、xp_cmdshell |
| 3306 | MySQL | 弱口令、UDF 提权 |
| 3389 | RDP | 弱口令、BlueKeep |
| 6379 | Redis | 未授权访问 |
| 27017 | MongoDB | 未授权访问 |

---

## Phase 5: 技术栈识别

### 5.1 自动检测

```bash
python3 scripts/enterprise_recon.py -d target.com
```

检测内容:
- Server 响应头
- X-Powered-By 头
- 前端框架 (React, Vue, Angular)
- 后端框架 (Django, Laravel, Spring)
- CMS (WordPress, Drupal, Joomla)

### 5.2 空间搜索指纹

```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询: domain="target.com" AND header="Server: nginx"
```

---

## Phase 6: 人员情报 (关联技能)

### 6.1 邮箱格式推断

| 格式 | 示例 | 常见度 |
|------|------|--------|
| first.last | john.doe@target.com | 高 |
| flast | jdoe@target.com | 中 |
| first_last | john_doe@target.com | 中 |
| first | john@target.com | 低 |

### 6.2 调用 email-osint

```bash
# 在 email-osint skill 目录下
python3 scripts/holehe_run.py admin@target.com
python3 scripts/blackbird_run.py -u johndoe
```

---

## 输出规范

### 侦察报告模板

```markdown
# 企业侦察报告: Target Corp

**扫描时间**: 2024-01-15 10:30:00
**目标域名**: target.com

## 执行摘要

- 发现子域名: 45 个
- 活跃 IP: 12 个
- 开放端口: 28 个
- 高危入口: 3 个

## 子域名清单

| 子域名 | IP | 类型 | 风险 |
|--------|-----|------|------|
| dev.target.com | 1.2.3.6 | 开发环境 | 🔴高 |
| vpn.target.com | 1.2.3.5 | VPN | 🟡中 |
| www.target.com | 1.2.3.4 | Web | 🟢低 |

## 开放端口

| IP | 端口 | 服务 | 版本 |
|----|------|------|------|
| 1.2.3.4 | 443 | HTTPS | nginx/1.18 |
| 1.2.3.5 | 1194 | OpenVPN | 2.5.1 |

## 技术栈

- **Web服务器**: Nginx 1.18
- **后端语言**: Python/Django
- **前端框架**: React
- **数据库**: PostgreSQL (推测)
- **CDN**: Cloudflare

## 攻击面评估

| 入口点 | 风险等级 | 攻击建议 |
|--------|---------|---------|
| dev.target.com | 🔴高 | 测试弱口令、默认配置 |
| vpn.target.com | 🟡中 | VPN 凭证爆破 |
| api.target.com | 🟡中 | API 接口测试 |

## 下一步建议

1. 对 dev.target.com 进行漏洞扫描
2. 收集 VPN 登录页面信息
3. 测试 API 端点认证机制
```

---

## 与其他技能的关联

### 输入来源

| 来源技能 | 产出 | 用途 |
|----------|------|------|
| `phishing-analysis` | 发件域名 | 钓鱼基础设施分析 |
| `domain-analysis` | 可疑域名 | 关联企业资产 |

### 输出调用

| 发现内容 | 调用技能 | 说明 |
|---------|---------|------|
| 关键人员邮箱 | `/email-osint` | 个人情报收集 |
| 可疑域名 | `/domain-analysis` | 威胁情报查询 |
| Web 应用 | `/redteam-vulnscan` | 漏洞扫描 |
| 开放端口 | `/redteam-exploit` | 漏洞利用 |
| 关键人物 | `/redteam-recon-person` | 社工预研 |

---

## MITRE ATT&CK 技术映射

### 战术与技术覆盖表

| 战术 | 技术 | 子技术 | 场景描述 |
|------|------|--------|---------|
| Reconnaissance (TA0043) | **T1592** Gather Victim Host Info | **T1592.001** Hardware Security | 识别目标硬件设备、安全设备型号 |
| Reconnaissance (TA0043) | **T1592** Gather Victim Host Info | **T1592.002** Client Configurations | 获取目标客户端软件配置信息 |
| Reconnaissance (TA0043) | **T1592** Gather Victim Host Info | **T1592.004** Client Configurations | 检测目标使用的安全产品版本 |
| Reconnaissance (TA0043) | **T1589** Gather Victim Identity Info | — | 收集目标企业员工身份信息 |
| Reconnaissance (TA0043) | **T1590** Gather Victim Network Info | **T1590.002** DNS | 子域名枚举和 DNS 历史解析 |
| Reconnaissance (TA0043) | **T1590** Gather Victim Network Info | **T1590.004** Network Topology | IP C 段关联分析、网络架构映射 |
| Reconnaissance (TA0043) | **T1590** Gather Victim Network Info | **T1590.005** Registered Domain Names | WHOIS 查询、域名注册信息 |
| Reconnaissance (TA0043) | **T1591** Gather Victim Org Info | **T1591.001** Determine Physical Locations | ICP 备案查询获取企业物理位置 |
| Reconnaissance (TA0043) | **T1591** Gather Victim Org Info | **T1591.002** Identify Business Tempo | 识别目标业务节奏（工作时间和运维周期）|
| Reconnaissance (TA0043) | **T1591** Gather Victim Org Info | **T1591.003** Identify Roles/Responsibilities | 识别关键人员角色（管理员/开发/高管）|
| Reconnaissance (TA0043) | **T1595** Active Scanning | **T1595.001** Scanning IP Blocks | 端口扫描和 C 段扫描 |
| Reconnaissance (TA0043) | **T1595** Active Scanning | **T1595.002** Vulnerability Scanning | 识别已知漏洞（配合漏洞扫描技能） |
| Reconnaissance (TA0043) | **T1592.005** Gather Victim Host Info | Software | 技术栈指纹识别（Server 头/X-Powered-By） |
| Resource Development (TA0042) | **T1583** Develop Capabilities | **T1583.001** Domains | 注册相似域名用于钓鱼 |
| Resource Development (TA0042) | **T1588** Obtain Capabilities | **T1588.006** Vulnerabilities | 获取目标系统漏洞利用工具 |

### ATT&CK Mitigations 对应

| Mitigation ID | 名称 | 应用场景 |
|---------------|------|---------|
| M1056 | Pre-compromise | 限制公开暴露的系统信息（WHOIS 隐私、DNS 隐藏）|
| M1041 | Encrypt Sensitive Information | 传输中数据加密减少指纹泄露 |
| M1031 | Network Intrusion Prevention | WAF/IPS 检测主动扫描行为 |
| M1024 | Restrict Registry Permissions | 限制 WHOIS/DNS 信息暴露 |

## OWASP Top 10 / CWE 映射

| OWASP 类别 | CWE ID | 关联场景 |
|-----------|--------|---------|
| **A01** Broken Access Control | CWE-200 | 信息暴露：DNS/WHOIS 泄露内部架构 |
| **A04** Insecure Design | CWE-209 | 信息泄露通过错误消息暴露技术栈 |
| **A05** Security Misconfiguration | CWE-16 | 开发/测试环境暴露在公网（dev/staging 子域名）|
| **A06** Vulnerable Components | CWE-1039 | 识别目标使用的过时组件版本 |
| **A09** Security Logging | CWE-778 | 侦察活动未被检测和告警 |
| **A10** SSRF | CWE-918 | 内网探测通过 SSRF 漏洞 |

## CVE 参考表（企业侦察相关高危漏洞）

| CVE ID | 产品 | 影响 | CVSS | 侦察场景 |
|--------|------|------|------|---------|
| CVE-2023-23397 | Outlook | 特权提升 | 9.8 | 识别邮件服务器版本 |
| CVE-2021-44228 | Log4j | RCE | 10.0 | 检测 Java 后端指纹 |
| CVE-2023-46604 | Apache ActiveMQ | RCE | 10.0 | 识别消息队列服务版本 |
| CVE-2023-49103 | ownCloud | 信息泄露 | 10.0 | 检测文件共享服务暴露 |
| CVE-2024-21887 | Ivanti Connect Secure | RCE | 9.1 | 识别 VPN 设备型号和版本 |

## Sigma 检测规则

### 规则 1: 大规模 DNS 子域名枚举检测

```yaml
title: 大规模子域名枚举活动检测
id: 9c3e1f2a-b4d5-4e6f-8a9b-0c1d2e3f4a5b
status: experimental
description: 检测对目标域名进行大规模子域名枚举的侦察行为（证书透明度日志查询/DNS 爆破）
references:
    - https://attack.mitre.org/techniques/T1590/002/
    - https://attack.mitre.org/techniques/T1590/
tags:
    - attack.reconnaissance
    - attack.t1590.002
logsource:
    product: dns
    category: dns_query
detection:
    bulk_query:
        query_type: 'A'
        queried_domain|re: .*\\.target\\.com$
    threshold:
        timeframe: 1m
        condition: selection_count > 20
falsepositives:
    - 合法 DNS 监控系统
    - CDN 健康检查
level: medium
```

### 规则 2: Nmap 端口扫描检测

```yaml
title: Nmap 端口扫描行为检测
id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: 检测 Nmap 或类似工具的端口扫描行为（SYN scan / connect scan / service detection）
references:
    - https://attack.mitre.org/techniques/T1595/001/
    - https://attack.mitre.org/techniques/T1595/
tags:
    - attack.reconnaissance
    - attack.t1595.001
logsource:
    product: linux
    category: network_connection
detection:
    scan_pattern:
        DestinationPort:
            - 21
            - 22
            - 80
            - 443
            - 445
            - 3389
    rapid_connections:
        timeframe: 10s
        condition: selection_count > 15
falsepositives:
    - 合法网络管理工具
    - 安全扫描器授权使用
level: high
```

## IOC 采集指引

从企业侦察中可提取的 IOC 和情报要素：

| IOC 类型 | 提取方法 | 用途 | 示例 |
|---------|---------|------|------|
| **子域名** | DNS 枚举 / crt.sh 查询 | 攻击面映射 | `dev.target.com`, `vpn.target.com` |
| **IP 地址** | DNS 解析 / C 段关联 | C2 基础设施比对 | `103.x.x.x` |
| **开放端口** | 端口扫描 | 服务指纹识别 | `443/tcp open https` |
| **技术栈版本** | HTTP 响应头分析 | 漏洞匹配 | `nginx/1.18`, `Django/3.2` |
| **域名注册信息** | WHOIS 查询 | 攻击者关联 | 注册人邮箱、注册商 |
| **CDN/WAF 识别** | HTTP 头分析 | 基础设施分析 | `Cloudflare`, `Akamai` |
| **证书信息** | 证书透明度日志 | 子域名发现 | SAN 列表中的域名 |
| **云存储桶** | 命名规则猜测 | 数据泄露检测 | `s3://target-backups` |

## 合规框架参考

| 标准 | 条款 | 关联说明 |
|------|------|---------|
| **ISO 27001** | A.8.9 访问控制 | 限制公网暴露的资产信息 |
| **ISO 27001** | A.5.7 威胁情报 | 威胁情报驱动的安全评估 |
| **NIST SP 800-53** | RA-3 风险评估 | 定期进行企业资产侦察评估 |
| **NIST SP 800-53** | SC-7 边界保护 | 检测和阻断主动扫描行为 |
| **NIST SP 800-115** | 技术安全测试指南 | 渗透测试侦察阶段标准化 |
| **GB/T 20984** | 信息安全风险评估方法 | 资产识别和风险评估 |
| **PCI DSS** | 11.3 | 定期渗透测试（含侦察阶段） |
| **GDPR** | Art. 32 | 企业侦察中发现的个人数据保护问题 |

## 跨技能工作流

### 工作流 1: 企业攻击面评估

```
redteam-recon-enterprise (企业侦察)
  ├─→ asset-discovery (深度资产发现)
  ├─→ redteam-recon-person (关键人员情报)
  │    └─→ redteam-intrusion-social (社工攻击)
  ├─→ redteam-intrusion-hunter (漏洞扫描)
  │    └─→ redteam-intrusion-0day (漏洞利用)
  └─→ ttp-extractor → pdf-report (报告生成)
```

### 工作流 2: 资产监控与变更追踪

```
redteam-recon-enterprise (基线侦察)
  └─→ asset-monitor (持续监控)
       └─→ 发现新资产/端口变更
            └─→ redteam-recon-enterprise (差异分析)
```

### 工作流 3: 合规驱动的渗透测试

```
redteam-recon-enterprise (合规侦察)
  └─→ 生成资产清单 (符合 ISO 27001 A.8.9)
       ├─→ code-audit (源代码审计)
       └─→ pdf-report (合规报告)
```

## 参考文件

- [references/report-format.md](references/report-format.md) - 报告格式规范
