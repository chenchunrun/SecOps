---
name: redteam-recon-enterprise
description: 企业级目标情报收集。对目标企业进行资产发现、技术栈识别和攻击面测绘。当用户要求"企业资产发现"、"攻击面测绘"、"目标侦察"、"企业情报收集"、"外部资产发现"时使用此技能。
metadata:
  version: 2.0.0
  builtin: true
  category: redteam-recon
---

> ⚠️ **RED TEAM AUTHORIZATION REQUIRED**
>
> This skill falls under the `redteam:execute` capability gate.
>
> **Before executing ANY step in this skill, you MUST:**
> 1. State the skill name and a one-line summary of what you are about to do.
> 2. Ask the user to explicitly confirm authorization by typing **"已授权 / AUTHORIZED"**.
> 3. Ask the user to confirm the authorized scope (target, timeframe, rules of engagement).
> 4. Record the confirmation in your response before proceeding.
>
> **Do NOT proceed if:**
> - The user has not typed the authorization confirmation.
> - The target is outside the stated scope.
> - Any step would cause irreversible changes without a rollback plan.
>
> Violation of this gate is logged as a `security_alert` audit event.

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

## 参考文件

- [references/report-format.md](references/report-format.md) - 报告格式规范