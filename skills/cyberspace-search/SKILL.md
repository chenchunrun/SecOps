---
name: cyberspace-search
description: |
  网络空间资产搜索与威胁狩猎。当用户要求"搜索网络资产"、"资产测绘"、"空间测绘"、"C段探测"、
  "真实IP发现"、"C2追踪"、"APT狩猎"、"威胁狩猎"、"狩猎"、"攻击面测绘"、"旁站查询"、
  "绕过CDN"、"查C段"、"同C段"、"证书关联"、"图标搜索"、"IOC关联"、"动态DNS"、
  "僵尸网络"、"恶意软件家族"时使用此技能。
metadata:
  version: 2.3.0
  builtin: true
---

# 网络空间资产搜索技能

网络空间资产测绘与威胁狩猎，核心能力：**C段感知、证书关联、图标追踪、C2狩猎、IOC关联分析**。

---

## 核心 MCP 工具

| MCP 工具 | 用途 |
|----------|------|
| `cybersec_cloud_mcp_cyberspace-search` | 资产搜索主接口 |
| `cybersec_cloud_mcp_ops_portscan` | 端口验证（发现后立即验证存活） |
| `cybersec_cloud_mcp_risk_insight` | IP/域名威胁情报 |
| `cybersec_cloud_mcp_intel_icp_lookup` | ICP 备案查询 |

---

## 搜索语法速查

### 基础语法

| 语法 | 示例 | 说明 |
|------|------|------|
| `ip="x.x.x.x"` | `ip="1.2.3.4"` | 单 IP 查询 |
| `cidr="x.x.x.x/24"` | `cidr="192.168.1.0/24"` | 网段查询 |
| `hostname="*.xxx"` | `hostname="*.target.com"` | 子域名查询 |
| `port="xx"` | `port="443"` | 端口筛选 |
| `title="xxx"` | `title="admin"` | 页面标题 |
| `ssl="xxx"` | `ssl="target.com"` | 证书搜索 |
| `body="xxx"` | `body="nginx"` | 响应内容 |

### 高级语法

```bash
# 图标哈希 - 追踪同源资产
iconhash:"f3418a443e7d841097c714d69ec4bcb8"

# SSL 证书序列号 - 绕过 CDN
ssl:"证书序列号"

# 文件哈希 - 恶意文件溯源
filehash:"0b5ce08db7fb8fffe4e14d05588d49d9"
```

完整语法参见: [references/search-syntax.md](references/search-syntax.md)

---

## 核心分析连招

### 连招 1: 单点突破 → 全面展开

```
已知: 1.2.3.4

1. ip="1.2.3.4"                    → 获取域名、证书、端口
2. cidr="1.2.3.0/24"               → C 段环境
3. ssl="发现的证书特征"              → 证书关联资产
4. iconhash:"发现的图标hash"         → 图标关联资产
5. hostname="*.发现的域名"           → 子域名展开
6. cybersec_cloud_mcp_ops_portscan 验证每个发现的 IP
```

### 连招 2: 域名入手 → 穿透 CDN

```
已知: target.com (使用CDN)

1. hostname="*.target.com"         → 收集子域名
2. ssl="target.com"                → 证书关联找源站
3. iconhash 搜索                    → 找同图标的非 CDN 站点
4. 绑定 hosts 验证真实 IP
```

### 连招 3: C2 基础设施追踪

```
发现可疑 C2: 5.6.7.8

1. ip="5.6.7.8"                    → 当前服务信息
2. cidr="5.6.7.0/24"               → 同网段其他 C2
3. ssl 证书特征全网搜索
4. cybersec_cloud_mcp_risk_insight 查威胁情报
```

更多连招参见: [references/hunting-combos.md](references/hunting-combos.md)

---

## C 段快速打点

### Step 1: 全量感知
```bash
cidr="1.2.3.0/24"
```

### Step 2: Web 入口发现
```bash
cidr="1.2.3.0/24" && (port="80" || port="443" || port="8080")
```

### Step 3: 高价值目标
```bash
# 数据库
cidr="1.2.3.0/24" && (port="3306" || port="6379" || port="27017")

# 远程管理
cidr="1.2.3.0/24" && (port="22" || port="3389")
```

### Step 4: 端口验证（关键！）
```
MCP: cybersec_cloud_mcp_ops_portscan
参数: target="1.2.3.4", ports=[80,443,3306,6379]
```

> ⚠️ **发现的每个高价值端口都要用 cybersec_cloud_mcp_ops_portscan 验证**

---

## 威胁狩猎

### Cobalt Strike
```bash
ssl="6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C"  # 默认证书
port="50050"                                      # 默认端口
```

### 常见 RAT
```bash
# AsyncRAT
domain="duckdns.org" && port="6606"

# NjRAT
domain="linkpc.net" && port="5552"
```

### 动态 DNS 滥用
```bash
domain="duckdns.org"   # 862+ 关联资产
domain="ydns.eu"       # 495+ 关联资产
domain="linkpc.net"    # 98+ 关联资产
```

完整威胁狩猎模板: [references/threat-hunting.md](references/threat-hunting.md)

---

## 真实 IP 发现

| 方法 | 搜索语法 |
|------|----------|
| 证书关联 | `ssl="目标域名"` |
| 图标哈希 | `iconhash:"xxx"` |
| 邮件服务器 | `hostname="mail.target.com"` |
| 测试环境 | `hostname="*test*.target.com"` |

---

## 分析输出流程

```
1. 明确目标类型（域名/IP/组织名）
2. 构建初始查询 → cybersec_cloud_mcp_cyberspace-search
3. 分析结果，提取关联线索
4. 扩展搜索（证书/图标/C段）
5. 端口验证 → cybersec_cloud_mcp_ops_portscan
6. 威胁情报 → cybersec_cloud_mcp_risk_insight
7. 输出报告
```

---

## 安全映射

### ATT&CK 战术与技术映射

| 战术 | 技术 | ID | 网空搜索关联 |
|------|------|-----|-------------|
| Reconnaissance | Active Scanning | T1595 | 通过网空搜索进行主动资产扫描 |
| Reconnaissance | Scanning IP Blocks | T1595.001 | C段扫描和IP段发现 |
| Reconnaissance | Gather Victim Host Info | T1592 | 收集目标主机信息（端口/服务/证书） |
| Reconnaissance | Gather Victim Identity Info | T1589 | 通过证书/域名关联收集身份信息 |
| Reconnaissance | Search Open Technical Databases | T1596 | 查询公开技术数据库（类似网空搜索） |
| Reconnaissance | Search Open Technical Databases — DNS | T1596.002 | DNS记录查询和关联 |
| Reconnaissance | Search Open Technical Databases — WHOIS | T1596.001 | WHOIS查询和关联 |
| Reconnaissance | Search Open Technical Databases — Digital Certificates | T1596.003 | SSL证书搜索和关联 |
| Reconnaissance | Search Open Websites/Domains | T1593 | 开放网络资源搜索 |
| Discovery | Network Service Discovery | T1046 | 端口和服务发现 |
| Command and Control | Encrypted Channel | T1573 | C2基础设施证书特征搜索 |
| Initial Access | External Remote Services | T1133 | 远程服务入口发现 |
| Defense Evasion | Hidden Marking | T1027 | 隐蔽C2基础设施识别 |
| Collection | Data from Information Repositories | T1213 | 公开信息仓库收集 |

### OWASP Top 10 映射

| OWASP 类别 | CWE | 网空搜索关联 |
|-----------|------|-------------|
| A01 Broken Access Control | CWE-200 | 信息暴露导致未授权访问 |
| A04 Insecure Design | CWE-209 | 暴露敏感系统信息 |
| A05 Security Misconfiguration | CWE-16 | 服务配置错误（开放端口/默认凭证） |
| A06 Vulnerable & Outdated Components | CWE-1035 | 过时服务版本和服务指纹 |
| A08 Software and Data Integrity Failures | CWE-506 | 恶意基础设施检测 |

### CVE 参考表

| CVE | 描述 | 网空搜索应用 |
|-----|------|-------------|
| CVE-2021-44228 | Log4Shell | 搜索 Java 应用+443端口潜在目标 |
| CVE-2023-46604 | Apache ActiveMQ RCE | 搜索 61616 端口开放服务 |
| CVE-2024-21887 | Ivanti Connect Secure RCE | 搜索 Ivanti 设备特征证书 |
| CVE-2023-23375 | Microsoft Power Platform RCE | 搜索特定端口和特征 |
| CVE-2022-26134 | Atlassian Confluence OGNL RCE | 搜索 Confluence 实例 |

### Sigma 检测规则

**规则1: C2 基础设施搜索检测**
```yaml
title: Suspicious Cyberspace Search for C2 Infrastructure
status: experimental
description: 检测通过网空搜索API查询已知C2基础设施特征
detection:
  selection:
    EventType: "api_call"
    CommandLine|contains:
      - "ssl=\"6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C\""
      - "port=\"50050\""
      - "iconhash:\"f3418a443e7d841097c714d69ec4bcb8\""
  condition: selection
level: medium
tags:
  - attack.t1595
  - attack.t1596.003
```

**规则2: 大规模资产测绘行为检测**
```yaml
title: Bulk Asset Discovery via Cyberspace Search
status: experimental
description: 检测大规模网空资产测绘行为，可能为攻击侦察阶段
detection:
  selection:
    EventType: "api_call"
    QueryType|contains:
      - "cidr="
      - "hostname=*."
    Count|gt: 50
  condition: selection and Count > 50
level: low
tags:
  - attack.t1595.001
  - attack.t1592
```

### IOC 采集指引

| IOC 类型 | 采集方法 | 网空搜索应用 |
|---------|---------|-------------|
| IP 地址 | 搜索结果提取 | C2服务器/钓鱼站点IP |
| SSL证书指纹 | ssl语法搜索 | C2证书关联 |
| 域名 | hostname语法搜索 | 恶意域名和子域名 |
| 端口 | port语法筛选 | 异常端口开放服务 |
| 图标哈希 | iconhash语法 | 同源钓鱼站点 |
| 响应体特征 | body语法搜索 | Webshell/后门特征 |
| DNS记录 | 域名关联查询 | DNS绑定和CDN绕过 |

### 合规标准参考

| 标准 | 适用场景 | 网空搜索关联 |
|------|---------|-------------|
| GDPR Art. 32 | 数据安全 | 发现暴露的个人数据服务 |
| ISO 27001 A.8.9 | 技术漏洞管理 | 资产测绘发现暴露的漏洞服务 |
| ISO 27001 A.5.7 | 威胁情报 | 威胁狩猎数据源 |
| NIST SP 800-53 RA-3 | 风险评估 | 资产风险评估数据源 |
| NIST SP 800-53 SC-5 | 拒绝服务防护 | C2基础设施发现 |
| PCI DSS 11.2 | 内外部扫描 | 外部攻击面发现 |
| NIST CSF Identify | 资产识别 | 资产发现和分类 |
| NIST SP 800-40 | 补丁管理 | 暴露服务版本识别 |

### 跨技能工作流

**工作流1: C2 追踪与威胁狩猎**
```
流量分析/linux-ir: 发现可疑C2 IP
→ cyberspace-search: C2基础设施全网搜索
→ domain-analysis: 关联域名分析
→ ip-analysis: IP威胁情报
→ ttp-extractor: 提取攻击技术
→ pdf-report: 生成威胁狩猎报告
```

**工作流2: 攻击面管理**
```
asset-discovery: 内部资产清单
→ cyberspace-search: 外部暴露面搜索
→ brand-impersonation: 品牌仿冒检测
→ pdf-report: 生成攻击面报告
```

**工作流3: 钓鱼基础设施追踪**
```
phishing-analysis: 发现钓鱼站点
→ cyberspace-search: 图标哈希/证书关联搜索
→ url-analysis: URL分析
→ ttp-extractor: 攻击技术提取
```

### 误报排除指南

| 场景 | 排除方法 |
|------|----------|
| CDN IP | 检查是否为已知CDN服务商IP段 |
| 共享主机 | 同IP多个域名可能是虚拟主机而非C2 |
| 云服务 | AWS/Azure/GCP IP段排除 |
| 历史数据 | 搜索结果可能过期，需端口验证确认存活 |


## 参考文件

- [references/search-syntax.md](references/search-syntax.md) - 完整语法
- [references/hunting-combos.md](references/hunting-combos.md) - 分析连招
- [references/threat-hunting.md](references/threat-hunting.md) - 威胁狩猎模板
- [references/report-format.md](references/report-format.md) - 报告格式
