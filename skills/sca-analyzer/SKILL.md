---
name: sca-analyzer
description: 软件成分分析与供应链安全检测。当用户要求"依赖分析"、"SCA扫描"、"组件漏洞检测"、"SBOM生成"、"供应链安全"、"第三方库漏洞"、"依赖风险评估"、"开源组件分析"时使用此技能。
metadata:
  version: 1.1.0
  builtin: true
---

# 软件成分分析技能

## 依赖要求

**分析环境**: 跨平台

**支持的包管理器**:
| 语言 | 包管理器 | 锁文件 |
|------|----------|--------|
| JavaScript | npm/yarn/pnpm | package-lock.json, yarn.lock, pnpm-lock.yaml |
| Python | pip/poetry/pipenv | requirements.txt, Pipfile.lock, poetry.lock |
| Java | Maven/Gradle | pom.xml, build.gradle |
| Go | go mod | go.sum |
| Rust | Cargo | Cargo.lock |
| PHP | Composer | composer.lock |
| Ruby | Bundler | Gemfile.lock |
| .NET | NuGet | packages.config, *.csproj |

**外部 MCP 服务**:
| MCP | 工具 | 用途 |
|------|------|------|
| cybersec-cloud | websearch | CVE 详情查询 |

**可选工具**:
| 工具 | 用途 | 获取 |
|------|------|------|
| syft | SBOM 生成 | `brew install syft` |
| grype | 漏洞扫描 | `brew install grype` |
| trivy | 容器/代码扫描 | `brew install trivy` |
| npm audit | npm 漏洞检查 | 内置 |
| pip-audit | Python 漏洞检查 | `pip install pip-audit` |

## 快速使用

```bash
# SBOM 生成
syft /path/to/project -o json > sbom.json

# 漏洞扫描
grype sbom:sbom.json -o json > vulns.json

# npm 项目快速扫描
npm audit --json

# Python 项目快速扫描
pip-audit -r requirements.txt --format json
```

## 分析工作流

### Phase 1: 依赖清单收集

#### 1.1 识别项目类型

| 文件 | 项目类型 |
|------|----------|
| package.json | Node.js |
| requirements.txt / pyproject.toml | Python |
| pom.xml | Java Maven |
| build.gradle | Java Gradle |
| go.mod | Go |
| Cargo.toml | Rust |
| composer.json | PHP |
| Gemfile | Ruby |
| *.csproj | .NET |
| Dockerfile | 容器 |

#### 1.2 提取依赖信息

**Node.js**:
```bash
# 从 package-lock.json 提取
cat package-lock.json | jq '.packages | to_entries[] | {name: .key, version: .value.version}'

# 或使用 npm
npm ls --all --json
```

**Python**:
```bash
# 从 requirements.txt
cat requirements.txt | grep -v "^#" | grep -v "^$"

# 从 poetry.lock
cat poetry.lock | grep -A2 '\[\[package\]\]' | grep -E "^name|^version"

# pip freeze
pip freeze
```

**Java Maven**:
```bash
# 依赖树
mvn dependency:tree -DoutputType=json

# 或直接解析 pom.xml
cat pom.xml | grep -A3 '<dependency>'
```

#### 1.3 生成 SBOM

```bash
# 使用 syft 生成 CycloneDX 格式
syft /path/to/project -o cyclonedx-json > sbom-cyclonedx.json

# 生成 SPDX 格式
syft /path/to/project -o spdx-json > sbom-spdx.json
```

### Phase 2: 漏洞数据库查询

#### 2.1 主要漏洞数据库

| 数据库 | 覆盖范围 | API |
|--------|----------|-----|
| NVD | 全语言 CVE | https://nvd.nist.gov/vuln |
| OSV | 开源生态 | https://osv.dev/api |
| GitHub Advisory | GitHub 项目 | GraphQL API |
| npm advisory | npm 包 | npm audit |
| PyPI Advisory | Python 包 | pip-audit |

#### 2.2 漏洞查询方式

**OSV API 查询**:
```bash
curl -X POST "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{
    "package": {
      "name": "lodash",
      "ecosystem": "npm"
    },
    "version": "4.17.20"
  }'
```

**NVD API 查询**:
```bash
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=lodash"
```

#### 2.3 批量扫描

```bash
# Grype 扫描 SBOM
grype sbom:sbom.json -o json

# Trivy 扫描项目
trivy fs /path/to/project --format json

# npm audit
npm audit --json

# pip-audit
pip-audit --format json
```

### Phase 3: 漏洞分析

#### 3.1 漏洞严重性评估

| CVSS 分数 | 等级 | 优先级 |
|-----------|------|--------|
| 9.0-10.0 | 严重 | 立即修复 |
| 7.0-8.9 | 高危 | 24小时内 |
| 4.0-6.9 | 中危 | 计划修复 |
| 0.1-3.9 | 低危 | 评估后处理 |

#### 3.2 可利用性评估

| 维度 | 权重 | 说明 |
|------|------|------|
| 是否有 PoC | 30% | 公开 exploit |
| 攻击复杂度 | 25% | 低复杂度=高风险 |
| 是否需认证 | 20% | 无需认证=高风险 |
| 影响范围 | 25% | 远程执行=高风险 |

#### 3.3 依赖路径分析

```
直接依赖 vs 传递依赖：

直接依赖 (高优先级):
  project -> vulnerable-package@1.0.0

传递依赖 (需评估):
  project -> package-a -> package-b -> vulnerable-package@1.0.0
```

**可达性分析**:
- 直接依赖：必须修复
- 传递依赖：检查是否实际调用漏洞函数
- 开发依赖：评估是否影响构建安全

### Phase 4: 许可证合规分析

#### 4.1 许可证分类

| 类型 | 许可证 | 风险 |
|------|--------|------|
| 宽松 | MIT, Apache-2.0, BSD | 低 |
| 弱 Copyleft | LGPL, MPL | 中 |
| 强 Copyleft | GPL, AGPL | 高 |
| 商业限制 | SSPL, Commons Clause | 高 |
| 未知 | - | 需审查 |

#### 4.2 许可证兼容性

```
项目许可证: MIT
依赖许可证检查:
  ✅ MIT - 兼容
  ✅ Apache-2.0 - 兼容
  ✅ BSD-3-Clause - 兼容
  ⚠️ LGPL-2.1 - 需注意链接方式
  ❌ GPL-3.0 - 不兼容（需使用 GPL）
```

### Phase 5: 供应链风险评估

#### 5.1 包健康度评估

| 维度 | 检查项 | 风险信号 |
|------|--------|----------|
| 维护状态 | 最后更新时间 | >2年未更新 |
| 社区活跃度 | Stars/Issues | 活跃度低 |
| 维护者 | 维护者数量 | 单一维护者 |
| 下载量 | 周下载量 | 异常波动 |
| 代码来源 | 仓库地址 | 非官方源 |

#### 5.2 恶意包检测

| 风险信号 | 说明 |
|----------|------|
| 名称混淆 | lodas, lodassh (Typosquatting) |
| 安装脚本 | postinstall 执行可疑命令 |
| 网络请求 | 包内有外连代码 |
| 文件操作 | 读取敏感文件 |
| 新包高下载 | 异常增长模式 |

#### 5.3 依赖劫持风险

```
检查项:
□ 依赖是否使用精确版本 (=1.0.0 vs ^1.0.0)
□ 是否使用锁文件
□ 是否有依赖完整性校验 (npm integrity)
□ 是否有私有包命名空间 (@company/package)
```

### Phase 6: 修复建议

#### 6.1 修复优先级矩阵

| 严重性 | 可利用 | 直接依赖 | 优先级 |
|--------|--------|----------|--------|
| 严重 | 是 | 是 | P0 - 立即 |
| 严重 | 是 | 否 | P1 - 24h |
| 高危 | 是 | 是 | P1 - 24h |
| 高危 | 否 | 是 | P2 - 本周 |
| 中危 | - | 是 | P3 - 本月 |
| 低危 | - | - | P4 - 评估 |

#### 6.2 修复方式

**升级依赖**:
```bash
# npm
npm update vulnerable-package
npm install vulnerable-package@safe-version

# Python
pip install --upgrade vulnerable-package

# 批量升级
npm audit fix
```

**锁定版本**:
```json
// package.json - 使用精确版本
"dependencies": {
  "lodash": "4.17.21"
}
```

**替换依赖**:
```
如果包已废弃或无修复版本：
  lodash -> lodash-es (ESM 版本)
  request -> axios/got (已废弃包替换)
```

**临时缓解**:
- WAF 规则阻断已知利用
- 运行时补丁
- 功能降级

### Phase 7: 持续监控

#### 7.1 CI/CD 集成

```yaml
# GitHub Actions 示例
name: SCA Scan
on: [push, pull_request]
jobs:
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          severity: 'HIGH,CRITICAL'
          exit-code: '1'
```

#### 7.2 告警规则

```yaml
rules:
  - name: "严重漏洞"
    condition:
      - cvss: >= 9.0
      - direct_dependency: true
    action: block_merge

  - name: "高危漏洞"
    condition:
      - cvss: >= 7.0
    action: alert_slack

  - name: "许可证违规"
    condition:
      - license: ["GPL-3.0", "AGPL-3.0"]
    action: review_required
```

## 工具命令速查

| 任务 | 命令 |
|------|------|
| 生成 SBOM | `syft /path -o cyclonedx-json` |
| 漏洞扫描 | `grype sbom:sbom.json` |
| npm 审计 | `npm audit --json` |
| Python 审计 | `pip-audit -r requirements.txt` |
| 容器扫描 | `trivy image nginx:latest` |
| 依赖树 | `npm ls --all` / `pip show -f package` |

## 输出格式

### 漏洞报告

```csv
组件,版本,漏洞ID,严重性,CVSS,修复版本,依赖路径
lodash,4.17.20,CVE-2021-23337,高危,7.2,4.17.21,直接
minimist,1.2.5,CVE-2021-44906,严重,9.8,1.2.6,传递:mkdirp->minimist
```

### SBOM 摘要

```markdown
# 软件物料清单 (SBOM)

**项目**: example-app
**扫描时间**: 2024-01-01

## 依赖统计

| 类型 | 数量 |
|------|------|
| 直接依赖 | 45 |
| 传递依赖 | 312 |
| 总计 | 357 |

## 许可证分布

| 许可证 | 数量 |
|--------|------|
| MIT | 280 |
| Apache-2.0 | 52 |
| BSD-3-Clause | 15 |
| ISC | 8 |
| GPL-3.0 | 2 |
```

## MITRE ATT&CK 技术映射

软件成分分析覆盖以下 ATT&CK 战术和技术：

### 战术覆盖

| 战术 | ID | SCA 场景 |
|------|-----|---------|
| Initial Access | TA0001 | 供应链攻击入口 |
| Execution | TA0002 | 恶意包执行代码 |
| Persistence | TA0003 | 依赖劫持维持访问 |
| Defense Evasion | TA0005 | 混淆恶意包 |
| Collection | TA0009 | 恶意包收集数据 |

### 技术映射表

| ATT&CK 技术 | 子技术 | SCA 相关场景 |
|-------------|--------|------------|
| T1190 | Exploit Public-Facing Application | 利用已知漏洞组件 |
| T1195.001 | Compromise Software Dependencies: Open Source Repo | 开源仓库投毒 |
| T1195.002 | Compromise Software Supply Chain: Second Stage | 二阶供应链攻击 |
| T1195.003 | Compromise Hardware Supply Chain | 硬件供应链 |
| T1588.006 | Obtain Capabilities: Vulnerabilities | 获取漏洞利用 |
| T1078 | Valid Accounts | 利用默认/弱凭证依赖 |
| T1059.007 | Command and Scripting Interpreter: JavaScript | 恶意 npm 包执行 |
| T1059.006 | Command and Scripting Interpreter: Python | 恶意 PyPI 包执行 |
| T1036.005 | Masquerading: Match Legitimate Name | Typosquatting 包名 |
| T1105 | Ingress Tool Transfer | 安装脚本下载恶意载荷 |
| T1055.001 | Process Injection: DLL Injection | 恶意依赖注入代码 |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | 恶意包加密外连 |
| T1554 | Compromise Client Software Binary | 修改客户端软件二进制 |
| T1199 | Trusted Relationship | 利用信任的包仓库 |

### ATT&CK Mitigations

| Mitigation | ID | 适用场景 |
|-----------|-----|---------|
| Software Configuration | M1054 | 配置依赖锁定和校验 |
| Update Software | M1051 | 及时更新依赖版本 |
| Code Signing | M1045 | 验证包签名 |
| Application Isolation | M1048 | 沙箱执行不可信依赖 |
| Vulnerability Scanning | M1016 | 定期 SCA 扫描 |

## OWASP Top 10 映射

| OWASP 类别 | CWE | SCA 场景 |
|-----------|------|---------|
| A06 Vulnerable Components | CWE-1035 | 使用含已知漏洞的组件 |
| A08 Software/Data Integrity | CWE-502 | 不安全的反序列化依赖 |
| A05 Security Misconfiguration | CWE-16 | 默认不安全配置的依赖 |
| A04 Insecure Design | CWE-209 | 缺乏依赖安全设计 |
| A09 Logging Failures | CWE-778 | 依赖漏洞未被监控 |
| A07 Auth Failures | CWE-287 | 依赖组件认证缺陷 |

## Sigma 检测规则

### 规则1: 恶意 npm 包安装检测

```yaml
title: Suspicious npm Package Installation
id: c3d4e5f6-7a8b-4c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: Detects installation of npm packages with suspicious postinstall scripts or known typosquatting patterns
references:
    - https://attack.mitre.org/techniques/T1195/001
author: SecSkill Evolution
date: 2026/06/18
logsource:
    product: linux
    category: process_creation
detection:
    selection_npm:
        process: npm
        cmdline|contains: 'install'
    suspicious_postinstall:
        cmdline|contains:
            - 'curl'
            - 'wget'
            - 'eval'
            - 'base64'
    selection_typosquat:
        cmdline|contains:
            - 'lodas'
            - 'reactt'
            - 'expresss'
    condition: (selection_npm and suspicious_postinstall) or selection_typosquat
falsepositives:
    - Legitimate packages with complex install scripts
level: high
tags:
    - attack.initial_access
    - attack.t1195.001
    - attack.t1059.007
```

### 规则2: pip 可疑包安装

```yaml
title: Suspicious pip Package Installation
id: d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8a
status: experimental
description: Detects pip install of packages with suspicious names or from untrusted indexes
references:
    - https://attack.mitre.org/techniques/T1195/001
author: SecSkill Evolution
date: 2026/06/18
logsource:
    product: linux
    category: process_creation
detection:
    selection_pip:
        process: pip
        cmdline|contains: 'install'
    suspicious_flags:
        cmdline|contains:
            - '--index-url'
            - '--trusted-host'
            - 'http://'
    selection_typosquat:
        cmdline|contains:
            - 'requets'
            - 'djangoa'
            - 'flaskk'
    condition: (selection_pip and suspicious_flags) or (selection_pip and selection_typosquat)
falsepositives:
    - Private package indexes
    - Custom package names
level: medium
tags:
    - attack.initial_access
    - attack.t1195.001
    - attack.t1059.006
```

## YARA 规则

```yara
rule Suspicious_NPM_Package {
    meta:
        description = "Detects suspicious patterns in npm packages"
        author = "SecSkill Evolution"
        date = "2026-06-18"
    strings:
         = "postinstall" ascii
         = "curl" ascii
         = "wget" ascii
         = "base64 -d" ascii
         = "eval(" ascii
         = "/dev/tcp/" ascii
    condition:
         and 2 of (, , , , )
}

rule Known_Malicious_Package_Patterns {
    meta:
        description = "Patterns from known supply chain attacks"
        author = "SecSkill Evolution"
        date = "2026-06-18"
    strings:
         = "process.env" ascii
         = "discord.com/api/webhooks" ascii
         = "pastebin.com/raw" ascii
         = "ngrok.io" ascii
         = ".ssh/id_rsa" ascii
    condition:
        3 of them
}
```

## CVE 参考表

| CVE | 组件 | 影响 | 供应链场景 |
|-----|------|------|-----------|
| CVE-2021-23337 | lodash | Prototype Pollution | 传递依赖漏洞 |
| CVE-2021-44906 | minimist | Prototype Pollution | 传递依赖漏洞 |
| CVE-2024-3094 | xz-utils | 后门 | 供应链投毒 |
| CVE-2021-44228 | log4j | RCE | 传递依赖漏洞 |
| CVE-2022-23812 | node-ip | RCE | 供应链投毒 |
| CVE-2020-8193 | Citrix | ACL Bypass | 直接依赖漏洞 |
| CVE-2024-21490 | Django | ReDoS | 框架漏洞 |

## IOC 采集指引

| IOC 类型 | 采集方法 | 示例 |
|---------|---------|------|
| 恶意包名 | npm advisory / OSV | `event-stream` |
| 恶意域名 | postinstall 脚本分析 | `malware-cdn.evil.com` |
| 恶意 IP | 网络流量监控 | `45.133.1.23` |
| 文件哈希 | 恶意包 tarball hash | `SHA256: e5d6...` |
| C2 URL | 安装脚本外连地址 | `hxxp://c2.evil.com/beacon` |
| 注册邮箱 | npm/pypi 注册信息 | `attacker@protonmail.com` |

## 合规标准参考

| 标准 | 相关条款 | SCA 覆盖 |
|------|---------|---------|
| GB/T 22239-2019 | 8.1.4 漏洞和风险管理 | 组件漏洞管理 |
| ISO 27001 | A.8.25 Secure Development Lifecycle | 开发生命周期安全 |
| ISO/IEC 27036 | 供应链安全 | 供应商安全管理 |
| PCI DSS v4.0 | 6.3 Security Vulnerability Management | 组件漏洞扫描 |
| NIST SP 800-161 | Supply Chain Risk Management | 供应链风险管理 |
| NIST SP 800-218 | SSDF | 安全软件开发框架 |
| GDPR | Art.32 Security of Processing | 第三方组件安全保障 |
| PIPL | 第51条 安全保障义务 | 数据处理组件安全 |

## 跨技能工作流

### 工作流1: 开发安全全流程
```
code-audit -> sca-analyzer -> researching-vulnerabilities -> pdf-report
```
代码审计 -> 组件分析 -> 漏洞研究 -> 报告生成

### 工作流2: 供应链事件响应
```
sca-analyzer -> binary-reverse-engineering -> ttp-extractor -> office-report
```
组件分析发现恶意包 -> 二进制逆向 -> TTP 提取 -> 事件报告

### 工作流3: AI 安全供应链
```
sca-analyzer -> code-audit -> prompt-injection-detect -> ttp-extractor
```
组件分析 -> 代码审计 -> AI 注入检测 -> TTP 提取

## 关联技能调用

| 场景 | 调用技能 |
|------|----------|
| CVE 详情 | `researching-vulnerabilities` |
| 恶意包分析 | `binary-reverse-engineering` |
| 代码审计 | `code-audit` |
| TTP 提取 | `ttp-extractor` |
| AI 安全检测 | `prompt-injection-detect` |
| 报告生成 | `pdf-report` |
| 事件报告 | `office-report` |

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 报告格式规范
- [references/cve-databases.md](references/cve-databases.md) - CVE 数据库清单
- [references/license-compatibility.md](references/license-compatibility.md) - 许可证兼容性矩阵
- [references/remediation-guide.md](references/remediation-guide.md) - 修复指南
