---
name: redteam-intrusion-hunter
description: 漏洞猎人扫描。自动化漏洞扫描和利用验证。当用户要求"漏洞扫描"、"Nuclei扫描"、"批量漏洞检测"、"Web漏洞扫描"、"PoC扫描"时使用此技能。仅限授权渗透测试使用。
metadata:
  version: 1.1.0
  builtin: true
  category: redteam-intrusion
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

## MITRE ATT&CK 技术映射

漏洞猎人扫描覆盖以下 ATT&CK 战术和技术：

### 战术覆盖

| 战术 | ID | 扫描覆盖 |
|------|-----|---------|
| Reconnaissance | T1595 | 主动扫描（端口/服务/Web） |
| Initial Access | TA0001 | 漏洞利用面发现 |
| Discovery | TA0007 | 服务/账户/配置发现 |

### 技术映射表

| ATT&CK 技术 | 子技术 | 漏洞类型 | 检测工具 |
|-------------|--------|---------|---------|
| T1595.001 | Scanning IP Blocks | 网络扫描 | nmap/masscan/naabu |
| T1595.002 | Scanning IP Blocks (Active) | 端口扫描 | masscan |
| T1592.001 | Gather Victim Host Info | Web指纹 | httpx/wappalyzer |
| T1592.002 | Gather Victim OS Info | 服务版本 | nmap -sV |
| T1190 | Exploit Public-Facing Application | Web漏洞 | Nuclei/sqlmap |
| T1190.001 | SQL Injection | SQL注入 | sqlmap |
| T1190.002 | XSS | 跨站脚本 | XSStrike |
| T1190.003 | SSRF | 服务端请求伪造 | SSRFmap |
| T1190.004 | File Inclusion | 文件包含 | Nuclei |
| T1210 | Exploitation of Remote Services | 服务漏洞 | Nuclei/metasploit |
| T1210.001 | Remote Services: RCE | 远程代码执行 | Nuclei |
| T1087.001 | Account Discovery: Local | 本地账户 | nmap script |
| T1046 | Network Service Discovery | 网络服务 | nmap/masscan |
| T1595.003 | Wordlist Scanning | 目录爆破 | ffuf/dirsearch |
| T1068 | Exploitation for Privilege Escalation | 提权漏洞 | LinPEAS/WinPEAS |

### ATT&CK Mitigations

| Mitigation | ID | 适用场景 |
|-----------|-----|---------|
| Attack Surface Reduction | M1047 | 减少暴露面 |
| Application Isolation | M1048 | 沙箱隔离 |
| Update Software | M1051 | 补丁管理 |
| Disable Unnecessary Features | M1042 | 关闭不必要服务 |
| Network Segmentation | M1030 | 网络分段 |

## OWASP Top 10 映射

| OWASP 类别 | CWE | 漏洞类型 | 扫描工具 |
|-----------|------|---------|---------|
| A01 Broken Access Control | CWE-284 | 越权访问 | Nuclei |
| A02 Cryptographic Failures | CWE-327 | 弱加密 | Nuclei |
| A03 Injection | CWE-89 | SQL注入 | sqlmap |
| A03 Injection | CWE-79 | XSS | XSStrike |
| A04 Insecure Design | CWE-209 | 信息泄露 | Nuclei |
| A05 Security Misconfiguration | CWE-16 | 配置错误 | Nuclei |
| A06 Vulnerable Components | CWE-1035 | 过期组件 | Nuclei |
| A08 Software/Data Integrity | CWE-502 | 反序列化 | Nuclei |
| A09 Logging Failures | CWE-778 | 日志缺失 | 人工检查 |
| A10 SSRF | CWE-918 | SSRF | SSRFmap |

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

## Sigma 检测规则

### 规则1: Nuclei 扫描检测（防御视角）

```yaml
title: Nuclei Vulnerability Scanner Activity
id: 5f86e7d2-3e1a-4b9f-8c2d-6e7f8a9b0c1d
status: experimental
description: Detects Nuclei scanner activity based on User-Agent and request patterns
references:
    - https://github.com/projectdiscovery/nuclei
author: SecSkill Evolution
date: 2026/06/18
logsource:
    product: webserver
    category: webserver_access
detection:
    selection_ua:
        user_agent|contains:
            - 'Nuclei'
            - 'OpenRA'
    selection_patterns:
        request_path|contains:
            - '/.env'
            - '/actuator'
            - '/wp-admin'
            - '/.git/config'
    condition: selection_ua or (selection_patterns and selection_ua)
falsepositives:
    - Authorized penetration testing
    - Security scanning tools
level: medium
tags:
    - attack.reconnaissance
    - attack.t1595
    - attack.t1595.001
```

### 规则2: SQL注入尝试检测

```yaml
title: SQL Injection Attempt via sqlmap
id: 7a9b8c2d-3e4f-4a5b-9c6d-7e8f9a0b1c2e
status: experimental
description: Detects SQL injection patterns characteristic of sqlmap automated tool
references:
    - https://github.com/sqlmapproject/sqlmap
author: SecSkill Evolution
date: 2026/06/18
logsource:
    product: webserver
    category: webserver_access
detection:
    selection_sqli_patterns:
        request_uri|contains:
            - 'UNION SELECT'
            - 'AND 1=1'
            - 'AND 1=2'
            - "' OR '1'='1"
            - 'SLEEP('
            - 'BENCHMARK('
    selection_sqlmap_ua:
        user_agent|contains:
            - 'sqlmap'
    condition: selection_sqlmap_ua or selection_sqli_patterns
falsepositives:
    - Authorized penetration testing
    - Application security testing
level: high
tags:
    - attack.initial_access
    - attack.t1190
    - attack.t1190.001
```

## CVE 参考表

| CVE 范围 | 漏洞类型 | Nuclei 模板 | 风险等级 |
|----------|---------|------------|---------|
| CVE-2024-XXXX | RCE | cves/2024/ | 严重 |
| CVE-2023-34362 | MOVEit SQLi | cves/2023/CVE-2023-34362.yaml | 严重 |
| CVE-2023-32315 | Openfire Auth Bypass | cves/2023/CVE-2023-32315.yaml | 高 |
| CVE-2024-3094 | XZ Utils Backdoor | cves/2024/CVE-2024-3094.yaml | 严重 |
| CVE-2023-22515 | Confluence Privilege Escalation | cves/2023/CVE-2023-22515.yaml | 严重 |

## IOC 采集指引

| IOC 类型 | 采集方法 | 示例 |
|---------|---------|------|
| 恶意 IP | 扫描日志中的攻击源 IP | `192.168.1.100` |
| 恶意域名 | Nuclei 检测到的钓鱼域名 | `phishing.example.com` |
| 文件哈希 | 检测到的 Web Shell 哈希 | `SHA256: a1b2c3...` |
| User-Agent | 扫描器 UA 特征 | `Nuclei - Open-source Project` |
| URL 路径 | 恶意请求路径 | `/.env, /wp-admin/setup-config.php` |

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

## 误报排除指南

| 误报场景 | 排除方法 | 说明 |
|---------|---------|------|
| Nuclei 模板匹配宽泛 | 检查 `-debug` 输出的匹配规则 | 确认是否真正触发漏洞 |
| sqlmap 误报 | 使用 `--risk=1 --level=1` | 降低注入测试激进程度 |
| 服务版本误报 | 使用 `nmap -sV --version-intensity 5` | 调整版本检测强度 |
| 配置错误类误报 | 手动验证目标响应 | 确认暴露面真实存在 |

## 合规标准参考

| 标准 | 相关条款 | 扫描覆盖 |
|------|---------|---------|
| GB/T 22239-2019 | 8.1.4 漏洞和风险管理 | 漏洞扫描覆盖 |
| ISO 27001 | A.12.6 Technical Vulnerability Management | 漏洞识别与修复 |
| PCI DSS v4.0 | 11.3 Internal/External Scanning | 定期漏洞扫描 |
| NIST SP 800-115 | Technical Guide to Information Security Testing | 渗透测试方法论 |
| OWASP WSTG | WSTG-ATHN/ATHZ | 认证/授权测试指南 |
| GDPR | Art.32 Security of Processing | 安全措施验证 |
| PIPL | 第51条 安全保障义务 | 数据安全漏洞管理 |
| 等保2.0 | 三级以上要求 | 漏洞扫描和修复 |

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
| ATT&CK | T1190 Exploit Public-Facing Application |
| OWASP | A03 Injection (CWE-89) |

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

## 跨技能工作流

### 工作流1: 红队全流程打点
```
asset-discovery → redteam-recon-enterprise → redteam-intrusion-hunter → redteam-intrusion-0day → ttp-extractor → pdf-report
```
资产发现 → 企业侦察 → 漏洞扫描 → 0day利用 → TTP提取 → 报告生成

### 工作流2: Web应用安全评估
```
code-audit → redteam-intrusion-hunter → sca-analyzer → researching-vulnerabilities → pdf-report
```
代码审计 → 漏洞扫描 → 组件分析 → 漏洞研究 → 报告生成

### 工作流3: 应急响应漏洞确认
```
linux-ir / windows-ir → redteam-intrusion-hunter → auth-log-analysis → ttp-extractor → pdf-report
```
IR排查 → 漏洞确认（找到入侵路径）→ 日志分析 → TTP提取 → 报告生成

## 与其他技能的关联

| 发现内容 | 调用技能 | 说明 |
|---------|---------|------|
| 漏洞利用 | `/redteam-intrusion-0day` | 深入分析 |
| 资产发现 | `/redteam-recon-enterprise` | 扩大范围 |
| 漏洞研究 | `/researching-vulnerabilities` | 情报查询 |
| 利用执行 | `/redteam-exploit` | 获取权限 |
| TTP 提取 | `/ttp-extractor` | 从扫描结果提取 TTP |
| 代码审计 | `/code-audit` | 白盒结合黑盒 |
| 报告生成 | `/pdf-report` | 扫描结果报告化 |
