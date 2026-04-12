---
name: cyberspace-search
description: |
  网络空间资产搜索与威胁狩猎。当用户要求"搜索网络资产"、"资产测绘"、"空间测绘"、"C段探测"、
  "真实IP发现"、"C2追踪"、"APT狩猎"、"威胁狩猎"、"狩猎"、"攻击面测绘"、"旁站查询"、
  "绕过CDN"、"查C段"、"同C段"、"证书关联"、"图标搜索"、"IOC关联"、"动态DNS"、
  "僵尸网络"、"恶意软件家族"时使用此技能。
metadata:
  version: 2.2.0
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

## 参考文件

- [references/search-syntax.md](references/search-syntax.md) - 完整语法
- [references/hunting-combos.md](references/hunting-combos.md) - 分析连招
- [references/threat-hunting.md](references/threat-hunting.md) - 威胁狩猎模板
- [references/report-format.md](references/report-format.md) - 报告格式
