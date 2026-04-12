---
name: asset-discovery
description: 企业攻击面资产发现与测绘。当用户要求"资产发现"、"子域名枚举"、"攻击面测绘"、"暴露面分析"、"资产清点"、"影子资产发现"、"外部资产发现"、"EASM"、"两高一弱"、"高危漏洞检测"、"高危端口检测"、"弱口令检测"、"安全基线检测"时使用此技能。
metadata:
  version: 1.4.0
  builtin: true
---

# 攻击面资产发现技能

## 扫描模式

本技能支持两种扫描模式：

| 模式 | 工具 | 适用场景 | 特点 |
|------|------|----------|------|
| **MCP 云服务** | cybersec-cloud MCP | 快速查询、无需安装 | 聚合多源数据 |
| **本地 PD 工具链** | ProjectDiscovery 工具 | 深度扫描、完整控制 | 本地执行、可定制 |

## 本地扫描模式 (PD 工具链)

### 快速开始

```bash
# 使用脚本
python3 scripts/pd_scan.py --domain example.com --mode standard --output ./output

# 扫描模式
#   quick:    subfinder → dnsx → httpx           (~5分钟)
#   standard: + naabu + tlsx                     (~15分钟)
#   full:     + katana + nuclei                  (~30分钟+)
```

### 执行超时说明

> ⚠️ **重要**: 资产发现涉及大规模扫描，需要较长执行时间，请耐心等待。

| 工具/脚本 | 默认超时 | 说明 |
|----------|---------|------|
| `pd_scan.py` (quick) | **~5分钟** | subfinder + dnsx + httpx |
| `pd_scan.py` (standard) | **~15分钟** | 增加 naabu + tlsx |
| `pd_scan.py` (full) | **~30分钟+** | 增加 katana + nuclei |
| subfinder | 600s | 子域名枚举，多源聚合 |
| dnsx | 600s | DNS 解析验证 |
| naabu | 600s | 端口扫描（可能更久） |
| httpx | 600s | HTTP 探测 |
| tlsx | 300s | TLS 证书抓取 |
| CT Logs 查询 | 30s | crt.sh 证书透明度 |

**超时原因**：
- 子域名枚举需要查询多个数据源
- 端口扫描数量大时需要更长时间
- 大型企业可能有数百个子域名需要探测
- 建议先用 quick 模式评估规模，再决定是否使用 full 模式

### 工具链流程

```
subfinder → dnsx → naabu → httpx → tlsx → [nuclei]
  2499      844     1331    1303    668
子域名    存活域名   端口    HTTP服务  TLS证书
```

### 输出结构

```
output/
├── 1_subdomains.txt    # 子域名列表
├── 2_alive.txt         # 存活域名
├── 3_ports.txt         # host:port 格式
├── 4_http.json         # HTTP 服务 (技术栈、标题)
├── 5_tls.json          # TLS 证书信息
├── assets.db           # SQLite 数据库
└── summary.json        # 扫描摘要 (高价值目标统计)
```

### 高价值目标自动识别

脚本自动识别并标记：
- **登录入口**: login, signin, auth, sso
- **API 端点**: api, gateway, openapi
- **管理后台**: admin, console, dashboard
- **测试环境**: test, dev, uat, staging

详细工具参数参考: [references/pd-toolchain.md](references/pd-toolchain.md)

---

## MCP 云服务模式

## 依赖要求

**Python 版本**: 3.8+

**外部 MCP 服务**:
| MCP | 工具 | 用途 |
|------|------|------|
| cybersec-cloud | cybersec_cloud_mcp_subdomain_discovery | 子域名发现（首选） |
| cybersec-cloud | cybersec_cloud_mcp_dns_history | DNS 解析历史（关联分析） |
| cybersec-cloud | cybersec_cloud_mcp_cyberspace-search | 网络空间资产搜索 |
| cybersec-cloud | cybersec_cloud_mcp_ops_portscan | TCP 端口扫描 |
| cybersec-cloud | cybersec_cloud_mcp_risk_insight | 资产威胁情报 |
| cybersec-cloud | cybersec_cloud_mcp_intel_icp_lookup | ICP 备案查询 |

**可选工具**:
```bash
# DNS 工具
brew install dig whois

# 证书透明度
curl  # 用于 crt.sh 查询
```

## 快速使用

```bash
# 子域名发现
dig example.com NS
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq

# 网络空间搜索
# MCP: cybersec_cloud_mcp_cyberspace-search
# 查询: hostname="*.example.com"
```

## 分析工作流

### Phase 1: 信息收集

#### 1.1 目标确认

| 输入类型 | 示例 | 处理方式 |
|----------|------|----------|
| 主域名 | example.com | 直接分析 |
| 企业名称 | XX科技有限公司 | 先查 ICP 获取域名 |
| IP 段 | 192.168.1.0/24 | CIDR 搜索 |
| ASN | AS12345 | ASN 资产搜索 |

#### 1.2 根域名收集

**ICP 备案反查**（中国企业）：
```
MCP 调用: cybersec_cloud_mcp_intel_icp_lookup
用途: 通过企业名称查询所有备案域名
```

**证书透明度查询**：
```bash
# 查询所有历史证书，提取域名
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
  jq -r '.[].name_value' | sort -u
```

### Phase 2: 子域名枚举

#### 2.1 子域名发现（首选）

```
MCP 调用: cybersec_cloud_mcp_subdomain_discovery
参数:
  domain: "example.com"    # 根域名
  limit: 1000              # 返回数量限制，最大 1000
```

**特点**: 聚合多源数据，单次可获取数百个子域名

#### 2.2 网络空间搜索（补充）

```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询语法: hostname="*.example.com"
限制: limit=100
```

**高价值子域名识别**：

| 模式 | 风险等级 | 说明 |
|------|----------|------|
| admin/管理/后台 | 🔴 高 | 管理入口 |
| api/gateway | 🔴 高 | API 接口暴露 |
| dev/test/staging | 🔴 高 | 测试环境，安全较弱 |
| git/svn/jenkins | 🔴 高 | DevOps，可能泄露源码 |
| vpn/sslvpn | 🟡 中 | 远程访问入口 |
| mail/owa/webmail | 🟡 中 | 邮件系统 |
| oa/erp/crm | 🟡 中 | 业务系统 |

#### 2.3 证书透明度 (CT Logs)

```bash
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
domains = set()
for cert in data:
    for name in cert.get('name_value', '').split('\n'):
        domains.add(name.strip())
for d in sorted(domains):
    print(d)
"
```

#### 2.4 DNS 记录枚举

```bash
# 常见子域名字典爆破（如有工具）
# 或使用 DNS 记录关联
dig example.com MX +short  # 邮件服务器
dig example.com NS +short  # DNS 服务器
dig example.com TXT +short # SPF 等记录中的域名
```

### Phase 3: 服务识别

#### 3.1 端口扫描 (内网/外网)

```
MCP 调用: cybersec_cloud_mcp_ops_portscan
参数:
  target: "192.168.1.1"           # 目标 IP
  port_spec: "22,80,443,3306"     # 端口列表或范围 "1-1000"
  mode: "connect"                  # connect 或 socks5
  concurrency: 100                 # 并发数
  timeout_ms: 1000                 # 超时毫秒
```

**限制**: 单次最多 10000 端口

**快速扫描示例**:
```
# 常用端口快速扫描
cybersec_cloud_mcp_ops_portscan: target="x.x.x.x" port_spec="22,23,80,443,3306,3389,6379,8080,27017"

# 全端口扫描 (分批)
cybersec_cloud_mcp_ops_portscan: target="x.x.x.x" port_spec="1-10000" concurrency=200
cybersec_cloud_mcp_ops_portscan: target="x.x.x.x" port_spec="10001-20000" concurrency=200
...
```

#### 3.2 网络空间资产查询

```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询: hostname="sub.example.com"
字段: ip, port, service, title, banner
```

**高危端口清单**：

| 端口 | 服务 | 风险 |
|------|------|------|
| 22 | SSH | 远程访问 |
| 23 | Telnet | 明文传输 |
| 3389 | RDP | Windows 远程 |
| 3306 | MySQL | 数据库暴露 |
| 6379 | Redis | 未授权访问 |
| 27017 | MongoDB | 数据库暴露 |
| 9200 | Elasticsearch | 数据泄露 |
| 8080/8443 | Web | 管理后台 |

#### 3.2 Web 服务指纹

```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com" && port="80 443 8080"
字段: title, server, framework
```

**关注的 Web 应用**：

| 类型 | 关键词 | 风险 |
|------|--------|------|
| 登录页面 | login, 登录, signin | 凭证攻击面 |
| 管理后台 | admin, 管理, dashboard | 高权限入口 |
| API 文档 | swagger, api-docs | 接口暴露 |
| 开发工具 | phpinfo, debug | 信息泄露 |

### Phase 4: 关联资产发现

#### 4.1 同 IP 资产

```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询: ip="<目标IP>"
```

**判断托管类型**：
| 同 IP 域名数 | 判断 |
|-------------|------|
| < 10 | 独立服务器 |
| 10-100 | 共享主机 |
| > 100 | CDN/云服务 |

#### 4.2 C 段资产

```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询: cidr="<IP前三段>.0/24"
```

用途：发现同一网段的其他资产

#### 4.3 SSL 证书关联

```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询: ssl="example.com"
```

从证书的 CN 和 SAN 字段提取关联域名

#### 4.4 DNS 历史关联

```
MCP 调用: cybersec_cloud_mcp_dns_history
参数:
  indicator: "example.com"  # 域名或 IP
  limit: 100                # 返回数量限制
```

**用途**：
- 域名 → 发现历史解析过的 IP（可能暴露真实 IP）
- IP → 发现历史绑定过的域名（关联资产）
- 追踪 CDN 切换前的真实服务器

### Phase 5: 云资产识别

#### 5.1 云服务商识别

| ASN/IP 特征 | 云服务商 |
|-------------|----------|
| AS45090 | 腾讯云 |
| AS37963 | 阿里云 |
| AS16509 | AWS |
| AS8075 | Azure |

#### 5.2 对象存储桶

搜索模式：
- `{company}-bucket.oss-cn-*.aliyuncs.com`
- `{company}.s3.amazonaws.com`
- `{company}.blob.core.windows.net`

#### 5.3 SaaS 服务

检查是否使用：
- 企业邮箱：腾讯企业邮、阿里企业邮、Google Workspace
- 协作工具：钉钉、飞书、企业微信
- 代码托管：GitHub、GitLab、Gitee

### Phase 6: 两高一弱检测

> **触发词**: "两高一弱检测"、"高危漏洞检测"、"高危端口检测"、"弱口令检测"、"安全基线检测"

#### 6.1 高危漏洞检测

**检测范围**: CVSS ≥ 7.0 的漏洞

```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com"
字段: vuln (漏洞信息)
```

**高危漏洞类型**:

| 类型 | CVE 示例 | 风险等级 |
|------|----------|----------|
| 远程代码执行 (RCE) | Log4Shell, Spring4Shell | 🔴 严重 |
| SQL 注入 | - | 🔴 严重 |
| 未授权访问 | Redis/MongoDB 未授权 | 🔴 高 |
| 任意文件读取 | - | 🔴 高 |
| SSRF | - | 🟡 中高 |

**漏洞与资产关联查询**:
```
# 查询某 CVE 影响的资产
cybersec_cloud_mcp_cyberspace-search: vuln="CVE-2024-XXXX"

# 查询某资产的所有漏洞
cybersec_cloud_mcp_cyberspace-search: hostname="target.com" && vuln!=""
```

#### 6.2 高危端口检测

**高危端口定义**:

| 端口 | 服务 | 风险描述 | 检测建议 |
|------|------|----------|----------|
| 22 | SSH | 远程登录，暴力破解风险 | 限制来源 IP |
| 23 | Telnet | 明文传输，严禁使用 | 必须关闭 |
| 3389 | RDP | Windows 远程，漏洞频发 | 限制访问 |
| 445 | SMB | 永恒之蓝等漏洞 | 内网隔离 |
| 1433 | MSSQL | 数据库暴露 | 禁止公网 |
| 3306 | MySQL | 数据库暴露 | 禁止公网 |
| 5432 | PostgreSQL | 数据库暴露 | 禁止公网 |
| 6379 | Redis | 未授权访问风险 | 设置密码 |
| 27017 | MongoDB | 未授权访问风险 | 设置认证 |
| 9200 | Elasticsearch | 数据泄露风险 | 禁止公网 |

**批量端口扫描**:
```
MCP 调用: cybersec_cloud_mcp_ops_portscan
参数:
  target: "<资产IP>"
  ports: [22, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017, 9200]
  timeout_ms: 2000
```

#### 6.3 弱口令检测

**检测服务**:

| 服务 | 默认端口 | 常见弱口令 |
|------|----------|------------|
| SSH | 22 | root:root, admin:admin |
| RDP | 3389 | Administrator:123456 |
| MySQL | 3306 | root:root, root:空 |
| Redis | 6379 | 无密码 |
| FTP | 21 | anonymous:空 |
| Tomcat | 8080 | admin:admin, tomcat:tomcat |

**检测策略**:
1. 先通过端口扫描确定开放服务
2. 针对开放服务检测默认凭证
3. 输出弱口令清单和加固建议

#### 6.4 两高一弱报告格式

```markdown
## 两高一弱检测报告

**检测目标**: example.com
**检测时间**: 2024-XX-XX
**检测范围**: XX 个资产

### 1. 高危漏洞统计
| 漏洞编号 | 影响资产 | CVSS | 状态 |
|----------|----------|------|------|
| CVE-XXXX | 3 台 | 9.8 | 待修复 |

### 2. 高危端口统计
| 端口 | 服务 | 暴露数量 | 风险 |
|------|------|----------|------|
| 22 | SSH | 5 | 🔴 高 |
| 3306 | MySQL | 2 | 🔴 高 |

### 3. 弱口令统计
| 服务 | 资产 | 账号 | 状态 |
|------|------|------|------|
| SSH | 1.2.3.4 | root | 弱口令 |

### 4. 修复建议
1. **高优先级**: 立即修复 RCE 漏洞
2. **高优先级**: 关闭不必要的高危端口
3. **中优先级**: 修改所有弱口令
```

### Phase 7: 风险评估

#### 7.1 子域名自动风险标记（入库时必须执行）

| 模式 | risk_level | risk_reason |
|------|------------|-------------|
| `*test*`, `*dev*`, `*uat*`, `*staging*` | high | 测试环境暴露 |
| `*admin*`, `*manage*`, `*backend*` | high | 管理后台暴露 |
| `*api*`, `*gateway*` | high | API 接口暴露 |
| `*git*`, `*svn*`, `*jenkins*`, `*gitlab*` | critical | DevOps 系统暴露 |
| `*vpn*`, `*sslvpn*`, `*remote*` | medium | 远程访问入口 |
| `*mail*`, `*owa*`, `*webmail*` | medium | 邮件系统 |

**入库示例**：
```json
{"type": "subdomain", "value": "devtest.example.com", "risk_level": "high", "risk_reason": "测试环境暴露"}
```

#### 7.2 暴露面评分

| 维度 | 权重 | 评估标准 |
|------|------|----------|
| 高危漏洞 | 30% | CVSS ≥ 7.0 数量 |
| 高危端口暴露 | 20% | SSH/RDP/DB 数量 |
| 弱口令 | 15% | 弱口令服务数量 |
| 测试环境暴露 | 15% | dev/test/staging/uat |
| 敏感服务暴露 | 10% | 管理后台、API、DevOps |
| 过期证书 | 5% | SSL 证书状态 |
| 其他 | 5% | 历史解析、影子资产等 |

#### 7.3 资产分类

```
┌─────────────────────────────────────┐
│           企业资产全景               │
├─────────────┬───────────────────────┤
│   核心资产   │ 官网、主业务系统      │
├─────────────┼───────────────────────┤
│   支撑资产   │ 邮件、OA、VPN        │
├─────────────┼───────────────────────┤
│   开发资产   │ Git、Jenkins、测试环境│
├─────────────┼───────────────────────┤
│   影子资产   │ 未登记、个人搭建      │
└─────────────┴───────────────────────┘
```

### Phase 8: 报告生成

按 `references/report-format.md` 输出报告

## 工具命令速查

| 任务 | 命令/MCP |
|------|----------|
| **子域名发现** | `cybersec_cloud_mcp_subdomain_discovery: domain="example.com" limit=1000` |
| **DNS 历史** | `cybersec_cloud_mcp_dns_history: indicator="example.com" limit=100` |
| **端口扫描** | `cybersec_cloud_mcp_ops_portscan: target="x.x.x.x" port_spec="1-1000"` |
| **高危端口扫描** | `cybersec_cloud_mcp_ops_portscan: target="x.x.x.x" ports=[22,23,445,3306,3389,6379]` |
| **漏洞资产查询** | `cybersec_cloud_mcp_cyberspace-search: vuln="CVE-XXXX"` |
| **资产漏洞查询** | `cybersec_cloud_mcp_cyberspace-search: hostname="x.com" && vuln!=""` |
| 子域名搜索(补充) | `cybersec_cloud_mcp_cyberspace-search: hostname="*.domain.com"` |
| IP 资产搜索 | `cybersec_cloud_mcp_cyberspace-search: ip="x.x.x.x"` |
| C 段搜索 | `cybersec_cloud_mcp_cyberspace-search: cidr="x.x.x.0/24"` |
| SSL 关联 | `cybersec_cloud_mcp_cyberspace-search: ssl="domain.com"` |
| CT Logs | `curl "https://crt.sh/?q=%.domain.com&output=json"` |
| ICP 查询 | `cybersec_cloud_mcp_intel_icp_lookup: domain` |
| WHOIS | `whois domain.com` |

## 输出格式

### 资产清单 (CSV)

```csv
子域名,IP,端口,服务,标题,风险等级,备注
admin.example.com,1.2.3.4,443,nginx,管理后台,高,需要加固
api.example.com,1.2.3.5,8080,tomcat,API网关,中,检查认证
```

### 暴露面统计

```
总子域名: 156
活跃资产: 89
高危暴露: 12
  - SSH 暴露: 3
  - 数据库暴露: 2
  - 管理后台: 7
```

## 关联技能调用

| 发现的资产 | 调用技能 |
|-----------|---------|
| 可疑域名 | `domain-analysis` |
| 外部 IP | `ip-analysis` |
| Web 服务 | `url-analysis` |
| 开放端口 | `cybersec_cloud_mcp_cyberspace-search` 深入分析 |

## 参考文件

- **[references/pd-toolchain.md](references/pd-toolchain.md)** - PD 工具链详细参数和使用
- **[references/report-format.md](references/report-format.md)** - 报告格式规范
- [references/high-value-targets.md](references/high-value-targets.md) - 高价值目标识别
- [references/cloud-fingerprints.md](references/cloud-fingerprints.md) - 云资产指纹
- [references/high-risk-ports.md](references/high-risk-ports.md) - 高危端口清单

---

## AI 建议

发现邮箱地址时，可建议用户使用 `email-osint` 技能进行深入调查。
