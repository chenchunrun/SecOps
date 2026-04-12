---
name: redteam-intrusion-hunter
description: 漏洞猎人扫描。自动化漏洞扫描和利用验证。当用户要求"漏洞扫描"、"Nuclei扫描"、"批量漏洞检测"、"Web漏洞扫描"、"PoC扫描"时使用此技能。仅限授权渗透测试使用。
metadata:
  version: 1.0.0
  builtin: true
  category: redteam-intrusion
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



# 漏洞猎人扫描

自动化漏洞扫描和利用验证，快速发现目标系统漏洞。

## 适用场景

**仅限授权测试**:
- 渗透测试漏洞发现
- 红队快速打点
- 资产漏洞盘点
- 安全评估自动化

## 扫描类型

### 1. Web漏洞扫描

| 漏洞类型 | 工具 | 检测率 |
|---------|------|-------|
| SQL注入 | sqlmap | 高 |
| XSS | XSStrike | 中 |
| SSRF | SSRFmap | 中 |
| RCE | Nuclei | 高 |
| 文件包含 | Nuclei | 高 |

### 2. 服务漏洞扫描

| 目标 | 工具 | 用途 |
|------|------|------|
| 全端口 | nmap/masscan | 端口发现 |
| 服务版本 | nmap -sV | 版本识别 |
| CVE匹配 | nmap scripts | 漏洞匹配 |

### 3. 综合扫描

| 工具 | 特点 | 推荐场景 |
|------|------|---------|
| Nuclei | 模板化、快速 | 通用扫描 |
| Afrog | 中文、简单 | 国内资产 |
| Xray | 被动扫描 | 配合爬虫 |

## Nuclei使用

### 基础扫描

```bash
# 单目标扫描
nuclei -u https://target.com

# 批量扫描
nuclei -l urls.txt

# 指定模板
nuclei -u https://target.com -t cves/

# 严重性过滤
nuclei -u https://target.com -severity critical,high
```

### 高级用法

```bash
# 使用代理
nuclei -u https://target.com -proxy http://127.0.0.1:8080

# 速率限制
nuclei -l urls.txt -rate-limit 100

# 输出JSON
nuclei -l urls.txt -json -o results.json

# 使用工作流
nuclei -u https://target.com -w workflows/
```

### 模板类别

| 类别 | 说明 | 命令 |
|------|------|------|
| cves | CVE漏洞 | `-t cves/` |
| vulnerabilities | 通用漏洞 | `-t vulnerabilities/` |
| misconfigurations | 配置错误 | `-t misconfigurations/` |
| exposures | 敏感暴露 | `-t exposures/` |
| takeovers | 子域名接管 | `-t takeovers/` |

## sqlmap使用

### 基础扫描

```bash
# GET参数
sqlmap -u "http://target.com/page?id=1"

# POST请求
sqlmap -u "http://target.com/login" --data="user=admin&pass=123"

# Cookie注入
sqlmap -u "http://target.com" --cookie="id=1*"
```

### 高级用法

```bash
# 指定数据库类型
sqlmap -u "..." --dbms=mysql

# 提取数据
sqlmap -u "..." --dbs
sqlmap -u "..." -D dbname --tables
sqlmap -u "..." -D dbname -T users --dump

# 获取shell
sqlmap -u "..." --os-shell
```

## 扫描工作流

### Phase 1: 资产准备

```bash
# 子域名收集
subfinder -d target.com -o subs.txt

# 存活探测
httpx -l subs.txt -o alive.txt

# 端口扫描
naabu -l subs.txt -p - -o ports.txt
```

### Phase 2: 指纹识别

```bash
# Web指纹
httpx -l alive.txt -tech-detect -title -status-code

# 服务指纹
nmap -sV -iL hosts.txt
```

### Phase 3: 漏洞扫描

```bash
# Nuclei全量扫描
nuclei -l alive.txt -severity critical,high,medium

# 针对性扫描
nuclei -l alive.txt -t cves/2024/

# SQL注入批量测试
sqlmap -m urls_with_params.txt --batch
```

### Phase 4: 验证利用

```bash
# 验证单个漏洞
nuclei -u https://target.com -t specific-template.yaml -debug

# 获取详细信息
nuclei -u https://target.com -t template.yaml -v
```

## 输出规范

### 扫描报告

```markdown
# 漏洞扫描报告

## 扫描概况
| 项目 | 数值 |
|------|------|
| 目标数量 | XX |
| 扫描耗时 | XX分钟 |
| 发现漏洞 | XX |

## 风险统计
| 等级 | 数量 |
|------|------|
| 🔴 严重 | X |
| 🟠 高危 | X |
| 🟡 中危 | X |
| 🟢 低危 | X |

## 漏洞详情

### [CRITICAL] CVE-2024-XXXX
| 字段 | 值 |
|------|-----|
| 目标 | https://target.com/path |
| 类型 | RCE |
| 模板 | cves/2024/CVE-2024-XXXX.yaml |

**验证请求**:
\`\`\`http
GET /vulnerable/path HTTP/1.1
Host: target.com
\`\`\`

**响应特征**:
\`\`\`
[匹配到的响应内容]
\`\`\`

**修复建议**:
[修复方案]

---

## 后续建议
- 优先修复严重和高危漏洞
- 需要手动验证的漏洞列表
- 建议的深入测试方向
```

## 工具安装

### Nuclei

```bash
# Go安装
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 更新模板
nuclei -update-templates
```

### 相关工具

| 工具 | 安装 | 用途 |
|------|------|------|
| httpx | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | HTTP探测 |
| subfinder | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | 子域名 |
| naabu | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` | 端口扫描 |

## 规避与调优

### 速率控制

```bash
# 限制请求速率
nuclei -l urls.txt -rate-limit 50

# 并发控制
nuclei -l urls.txt -c 10

# 超时设置
nuclei -l urls.txt -timeout 10
```

### WAF绕过

```bash
# 随机UA
nuclei -l urls.txt -H "User-Agent: Mozilla/5.0..."

# 使用代理
nuclei -l urls.txt -proxy http://127.0.0.1:8080

# 延迟扫描
nuclei -l urls.txt -rate-limit 10
```

## 与其他技能的关联

| 发现内容 | 调用技能 | 说明 |
|---------|---------|------|
| 漏洞利用 | `/redteam-intrusion-0day` | 深入分析 |
| 资产发现 | `/redteam-recon-enterprise` | 扩大范围 |
| 漏洞研究 | `/researching-vulnerabilities` | 情报查询 |
| 利用执行 | `/redteam-exploit` | 获取权限 |