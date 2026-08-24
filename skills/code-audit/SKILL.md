---
name: code-audit
description: 源代码安全审计。当用户要求"代码审计"、"安全审计"、"漏洞扫描"、"代码安全检查"、"SAST分析"时使用此技能。支持 Python、Java、JavaScript、PHP、Go、C/C++ 等主流语言。检测 OWASP Top 10、CWE Top 25 等常见漏洞，输出包含风险评级、CWE 映射和修复建议的审计报告。
metadata:
  version: 1.1.0
  builtin: true
---

# 代码安全审计

静态分析源代码，识别安全漏洞，评估风险等级，生成可操作的修复报告。

## 支持语言

| 语言 | 检测能力 | 推荐工具 |
|------|---------|---------|
| Python | 完整 | Bandit, Semgrep |
| JavaScript/TS | 完整 | ESLint, Semgrep |
| Java | 完整 | Semgrep, SpotBugs |
| PHP | 完整 | Semgrep, PHPStan |
| Go | 完整 | gosec, Semgrep |
| C/C++ | 基础 | cppcheck, Semgrep |
| Ruby | 基础 | Brakeman |
| C# | 基础 | Semgrep |

## 审计工作流

### Phase 1: 代码收集

确认审计范围：
- 单文件 / 目录 / Git 仓库
- 语言类型（自动检测或用户指定）
- 重点关注区域（认证、输入处理、数据库操作等）

### Phase 2: 自动化扫描

```bash
# Python
bandit -r ./src -f json -o bandit_report.json

# JavaScript
npx eslint --ext .js,.ts ./src --format json

# 通用（推荐）
semgrep --config=auto ./src --json > semgrep_report.json
```

### Phase 3: 人工复审

重点检查：
1. **认证与授权** - 登录、会话、权限控制
2. **输入验证** - 用户输入处理、参数校验
3. **敏感数据** - 密钥、密码、API Token
4. **数据库操作** - SQL 查询、ORM 使用
5. **文件操作** - 路径处理、文件上传
6. **命令执行** - 系统调用、Shell 命令
7. **加密实现** - 算法选择、随机数生成

### Phase 4: 风险评级

| 等级 | 条件 | 处理优先级 |
|------|------|-----------|
| 严重 | RCE、SQL注入、认证绕过 | 立即修复 |
| 高危 | XSS、SSRF、敏感信息泄露 | 24小时内 |
| 中危 | CSRF、路径遍历、弱加密 | 1周内 |
| 低危 | 信息泄露、配置问题 | 下个版本 |

### Phase 5: 报告生成

按 `references/report-format.md` 格式输出报告。

## 常见漏洞检测

### 注入类漏洞

#### SQL 注入
```python
# 危险模式
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# 安全写法
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

#### 命令注入
```python
# 危险模式
os.system(f"ping {user_input}")

# 安全写法
subprocess.run(["ping", user_input], shell=False)
```

#### XSS
```javascript
// 危险模式
element.innerHTML = userInput;

// 安全写法
element.textContent = userInput;
```

### 认证与会话

#### 硬编码凭据
```python
# 危险 - 检测模式
password = "admin123"
api_key = "sk-xxxx"
secret = "my_secret_key"
```

#### 弱密码策略
```python
# 检查密码强度验证
if len(password) < 8:  # 不够 - 应检查复杂度
    raise ValueError("密码太短")
```

### 敏感数据

#### 日志泄露
```python
# 危险模式
logger.info(f"User login: {username}, password: {password}")

# 安全写法
logger.info(f"User login: {username}")
```

#### 不安全传输
```python
# 危险模式
requests.get("http://api.example.com/data")

# 安全写法
requests.get("https://api.example.com/data", verify=True)
```

### 文件操作

#### 路径遍历
```python
# 危险模式
file_path = os.path.join("/uploads", user_filename)

# 安全写法
safe_name = secure_filename(user_filename)
file_path = os.path.join("/uploads", safe_name)
if not file_path.startswith("/uploads"):
    raise SecurityError("路径遍历攻击")
```

## 依赖要求

**Python 版本**: 3.8+

**推荐工具**:

| 工具 | 安装命令 | 用途 |
|------|---------|------|
| Semgrep | `pip install semgrep` | 通用静态分析 |
| Bandit | `pip install bandit` | Python 安全扫描 |

```bash
pip install semgrep bandit
```

**可选工具**:

| 工具 | 安装 | 用途 |
|------|------|------|
| ESLint | `npm install -g eslint` | JavaScript 扫描 |
| gosec | `go install github.com/securego/gosec/v2/cmd/gosec@latest` | Go 扫描 |
| cppcheck | `brew install cppcheck` | C/C++ 扫描 |

## 检测规则

### OWASP Top 10 (2021)

| 编号 | 类别 | 检测模式 |
|------|------|---------|
| A01 | 访问控制失效 | 权限检查缺失、IDOR |
| A02 | 加密失败 | 弱算法、明文存储 |
| A03 | 注入 | SQL/命令/LDAP/XPath |
| A04 | 不安全设计 | 业务逻辑漏洞 |
| A05 | 安全配置错误 | DEBUG模式、默认凭据 |
| A06 | 脆弱组件 | 已知漏洞依赖 |
| A07 | 认证失败 | 弱密码、会话固定 |
| A08 | 数据完整性失败 | 反序列化、CI/CD |
| A09 | 日志监控失败 | 敏感数据日志 |
| A10 | SSRF | 未验证的URL请求 |

### CWE Top 25 (2023)

详见 [references/cwe-patterns.md](references/cwe-patterns.md)

## 快速检测命令

```bash
# Python 项目
bandit -r ./src -ll -ii

# JavaScript 项目
npx eslint ./src --ext .js,.ts

# 通用扫描
semgrep --config=p/security-audit ./src

# 依赖漏洞检查
pip-audit  # Python
npm audit  # JavaScript
```

## 输出规范

报告必须包含：

1. **审计概要** - 范围、时间、发现统计
2. **风险总览** - 按等级分类的漏洞数量
3. **漏洞详情** - 每个漏洞的完整信息
   - 位置（文件:行号）
   - 风险等级
   - CWE 编号
   - 漏洞描述
   - 修复建议
   - 代码示例
4. **修复优先级** - 按风险排序的修复清单
5. **安全建议** - 通用加固建议

## MITRE ATT&CK 技术映射

### 代码漏洞与 ATT&CK 对应关系

| ATT&CK 技术 | 技术名称 | 对应代码漏洞 | CWE | 检测方法 |
|-------------|----------|-------------|-----|----------|
| T1059.004 | Unix Shell | 命令注入 (os.system/subprocess+shell=True) | CWE-78 | Bandit B602, Semgrep |
| T1059.006 | Python | Python代码执行漏洞 | CWE-94 | Bandit B102, Semgrep |
| T1190 | Exploit Public-Facing Application | SQL注入/XSS/SSRF | CWE-89, CWE-79, CWE-918 | Semgrep p/default |
| T1078.004 | Cloud Accounts | 硬编码云凭据 | CWE-798 | Semgrep, TruffleHog |
| T1552.001 | Credentials In Files | 硬编码密码/密钥 | CWE-798 | Bandit B105, TruffleHog |
| T1213.002 | Sharepoint | 文件上传漏洞 | CWE-434 | Semgrep |
| T1046 | Network Service Discovery | SSRF漏洞 | CWE-918 | Semgrep custom rules |
| T1505.003 | Web Shell | 文件上传+Web Shell | CWE-434, CWE-94 | YARA + Semgrep |
| T1055 | Process Injection | 不安全的反序列化 | CWE-502 | Semgrep |
| T1573 | Encrypted Channel | 弱加密/不安全传输 | CWE-327 | Bandit B0401 |

### ATT&CK 战术覆盖

| 战术 | 相关代码安全问题 |
|------|-----------------|
| Initial Access (TA0001) | 公开接口注入漏洞(A03)、默认凭据(A07) |
| Execution (TA0002) | 命令注入(A03)、代码注入(A03)、反序列化(A08) |
| Persistence (TA0003) | Web Shell上传、后门代码 |
| Privilege Escalation (TA0004) | 权限检查缺失(A01)、IDOR |
| Defense Evasion (TA0005) | 日志禁用、混淆代码、弱加密(A02) |
| Credential Access (TA0006) | 硬编码凭据(A02)、凭据日志泄露 |
| Discovery (TA0007) | SSRF信息泄露、调试接口暴露(A05) |
| Collection (TA0009) | 敏感数据过度收集、日志泄露 |
| Exfiltration (TA0010) | 不安全的数据外发通道 |
| Impact (TA0040) | 资源耗尽、缺少速率限制 |

## CVE 参考表

| CVE ID | 影响组件 | 漏洞类型 | 代码审计检测 |
|--------|----------|----------|-------------|
| CVE-2024-21633 | LangChain | 代码注入 | 检查 langchain 版本 + eval() 使用 |
| CVE-2023-36188 | LangChain | 代码执行 | 检查 LLMChain/agent 使用模式 |
| CVE-2023-29174 | ChatGPT Plugin | 间接注入 | 检查插件输入验证逻辑 |
| CVE-2023-44467 | Go-Aws-Sdk | DoS | 检查 AWS SDK 版本 |
| CVE-2024-21633 | Semgrep Rules | 规则绕过 | 确保 p/default 规则集最新 |

## OWASP Top 10 (2021) 详细映射

| 编号 | 类别 | 检测模式 | CWE | ATT&CK | 严重性 |
|------|------|---------|-----|--------|--------|
| A01 | 访问控制失效 | 权限检查缺失、IDOR | CWE-284, CWE-639 | T1078 | 高危 |
| A02 | 加密失败 | 弱算法、明文存储、硬编码密钥 | CWE-327, CWE-798 | T1552.001, T1573 | 严重 |
| A03 | 注入 | SQL/命令/LDAP/XPath/Template | CWE-89, CWE-78 | T1059, T1190 | 严重 |
| A04 | 不安全设计 | 业务逻辑漏洞、缺少速率限制 | CWE-209 | N/A | 中危 |
| A05 | 安全配置错误 | DEBUG模式、默认凭据、CORS配置 | CWE-16, CWE-1188 | T1190 | 高危 |
| A06 | 脆弱组件 | 已知漏洞依赖 | CWE-1035, CWE-1104 | T1195 | 高危 |
| A07 | 认证失败 | 弱密码、会话固定、JWT漏洞 | CWE-287, CWE-384 | T1078 | 高危 |
| A08 | 数据完整性失败 | 反序列化、CI/CD漏洞 | CWE-502, CWE-829 | T1055 | 严重 |
| A09 | 日志监控失败 | 敏感数据日志、缺少审计日志 | CWE-532 | N/A | 中危 |
| A10 | SSRF | 未验证的URL请求 | CWE-918 | T1046, T1190 | 高危 |

## Semgrep 规则集配置

### 推荐规则集（p/default 替代已弃用的 p/owasp-top-ten）

```yaml
# .semgrep.yml — Semgrep 配置文件
rules:
  # 使用 p/default（包含 OWASP Top 10 覆盖）
  - id: default-config
    paths:
      include:
        - "src/**"
        - "lib/**"
        - "app/**"
      exclude:
        - "tests/**"
        - "node_modules/**"
        - "vendor/**"
```

```bash
# Semgrep 推荐命令
semgrep --config=p/default ./src --json > semgrep_report.json

# 按语言选择
semgrep --config=p/python ./src --json > python_report.json
semgrep --config=p/javascript ./src --json > js_report.json
semgrep --config=p/java ./src --json > java_report.json

# 自定义规则（检测业务逻辑漏洞）
semgrep --config=custom-rules.yml ./src
```

## npm audit 集成

### JavaScript/TypeScript 项目依赖检查

```bash
# 基本审计
npm audit --json > npm_audit_report.json

# 仅高危和严重
npm audit --audit-level=high

# 自动修复
npm audit fix

# 检查特定包
npm audit --package=lodash
```

### npm audit JSON 解析

```python
import json
import subprocess

def run_npm_audit():
    """运行 npm audit 并解析结果"""
    result = subprocess.run(
        ['npm', 'audit', '--json'],
        capture_output=True, text=True
    )
    audit_data = json.loads(result.stdout)

    vulnerabilities = []
    for pkg, info in audit_data.get('vulnerabilities', {}).items():
        vulnerabilities.append({
            'package': pkg,
            'severity': info.get('severity', 'unknown'),
            'via': info.get('via', []),
            'fix_available': info.get('fixAvailable', False),
            'cwe': extract_cwe(info),
        })
    return vulnerabilities

def extract_cwe(vuln_info):
    """从 npm audit 结果提取 CWE"""
    cwes = []
    for via in vuln_info.get('via', []):
        if isinstance(via, dict) and 'cwe' in via:
            cwes.extend(via['cwe'])
    return list(set(cwes))
```

### Python 依赖检查

```bash
# pip-audit（推荐）
pip-audit --format json > pip_audit_report.json

# safety
safety check --json > safety_report.json

# 查看 CVE 详情
pip-audit --desc
```

### YARA 规则：检测 Web Shell

```yara
rule WebShell_PHP_Generic {
    meta:
        description = "检测 PHP Web Shell"
        author = "sec-skills"
        date = "2025-06-17"
        reference = "ATT&CK T1505.003"
    strings:
        $eval = "eval("
        $system = "system("
        $shell_exec = "shell_exec("
        $passthru = "passthru("
        $base64_decode = "base64_decode("
        $str_rot13 = "str_rot13("
        $gzinflate = "gzinflate("
        $assert = "assert("
    condition:
        any 3 of ($eval, $system, $shell_exec, $passthru) or
        ($base64_decode and $gzinflate)
}

rule WebShell_JSP_Generic {
    meta:
        description = "检测 JSP Web Shell"
        author = "sec-skills"
        date = "2025-06-17"
        reference = "ATT&CK T1505.003"
    strings:
        $runtime = "Runtime.getRuntime()"
        $process_builder = "ProcessBuilder"
        $exec = ".exec("
    condition:
        any 2 of them
}
```

### Sigma 规则：代码审计发现 SIEM 告警

```yaml
title: Critical Vulnerability Found in Source Code Audit
id: 3f7a2b1c-5d8e-4f6a-9b3c-1e2d3a4b5c6d
status: experimental
description: Triggered when code audit finds critical severity vulnerabilities
references:
    - https://owasp.org/Top10/
    - https://attack.mitre.org/techniques/T1059/
date: 2025/06/17
logsource:
    product: ci-cd
    service: code-audit
detection:
    selection:
        event_type: vulnerability_found
        severity: critical
        cwe:
            - "CWE-78"
            - "CWE-89"
            - "CWE-502"
            - "CWE-798"
    condition: selection
falsepositives:
    - Intentional test code in test directories
    - Known false positive patterns
level: critical
tags:
    - attack.execution
    - attack.t1059
    - attack.initial_access
    - attack.t1190
    - owasp.a03
    - owasp.a02
```

## IOC 采集指引

| IOC 类型 | 来源 | 提取方法 | 用途 |
|----------|------|----------|------|
| 硬编码凭据 | 源代码 | Bandit B105/B106, TruffleHog | 凭据泄露追踪 |
| 硬编码 URL/IP | 源代码 | Semgrep 自定义规则 | 恶意基础设施关联 |
| 可疑域名 | 源代码 | 正则提取 + WHOIS | C2 通道发现 |
| 加密 Bitcoin 地址 | 源代码 | 正则匹配 | 勒索软件关联 |
| 后门特征码 | 源代码 | YARA 规则匹配 | APT 活动关联 |

## 合规标准参考

| 标准 | 相关条款 | 代码审计要求 |
|------|----------|-------------|
| PCI DSS 4.0 | Req. 6.2.4, 6.3 | 面向公众应用需代码审查 + SAST |
| OWASP ASVS 4.0 | V1.14, V5.x | 安全验证标准要求 |
| ISO/IEC 27001:2022 | A.8.25, A.8.26 | 安全开发生命周期要求 |
| ISO/IEC 27034 | 全文 | 应用安全生命周期 |
| NIST SSDF 1.1 | PW.7, PW.8 | 静态分析与代码审查 |
| GDPR | Art. 25(1), Art. 32 | 数据保护设计与默认 |
| PIPL (中国) | 第51条, 第57条 | 采取技术措施保障安全 |
| SOC 2 | CC7.1 | 系统监控与漏洞管理 |

## 跨技能工作流

### 工作流 1: 完整应用安全评估
```
code-audit → sca-analyzer → prompt-injection-detect → ttp-extractor → pdf-report
```

1. `code-audit` 对源代码执行 SAST 分析
2. `sca-analyzer` 对依赖执行 SCA 分析
3. `prompt-injection-detect` 检测 AI 相关漏洞（如适用）
4. `ttp-extractor` 提取攻击技术矩阵
5. `pdf-report` 生成完整评估报告

### 工作流 2: CI/CD 安全门禁
```
code-audit → researching-vulnerabilities → pdf-report
```

1. `code-audit` 扫描代码变更
2. `researching-vulnerabilities` 查询依赖漏洞
3. `pdf-report` 生成门禁报告（通过/不通过）

### 工作流 3: 恶意代码检测
```
code-audit → url-analysis → ip-analysis → pdf-report
```

1. `code-audit` 检测可疑代码模式（后门/Web Shell）
2. `url-analysis` 分析代码中的可疑 URL
3. `ip-analysis` 分析代码中的可疑 IP
4. `pdf-report` 生成威胁狩猎报告

## 与其他技能的关联

| 发现内容 | 调用技能 | 关系 |
|---------|---------|------|
| 硬编码 URL | `url-analysis` | 下游：分析嵌入的 URL |
| 硬编码 IP | `ip-analysis` | 下游：分析嵌入的 IP |
| 可疑依赖 | `researching-vulnerabilities` / `sca-analyzer` | 下游：查询依赖漏洞 |
| AI/LLM 代码漏洞 | `prompt-injection-detect` | 下游：AI 安全检测 |
| 攻击技术提取 | `ttp-extractor` | 下游：TTP 映射 |
| 报告生成 | `pdf-report` | 下游：生成报告 |
| 知识检索 | `rga-knowledge-search` | 下游：历史案例检索 |

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 报告格式规范（必读）
- [references/cwe-patterns.md](references/cwe-patterns.md) - CWE 检测模式
- [references/language-specific.md](references/language-specific.md) - 语言特定检测
- [references/fix-examples.md](references/fix-examples.md) - 修复代码示例
