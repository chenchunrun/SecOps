---
name: ttp-extractor
description: 从安全报告和威胁情报中提取攻防技战法，映射到 MITRE ATT&CK 框架并生成检测规则。当用户要求"TTP 分析"、"ATT&CK 映射"、"提取攻击技术"、"生成 Sigma 规则"、"威胁狩猎规则提取"时使用此技能。
metadata:
  version: 1.1.0
  builtin: true
---

# 攻防技战法提取 (TTP Extractor)

## 核心任务

从安全报告、威胁情报、事件分析、漏洞披露等文档中提取：
1. **攻击技术** (Attack Techniques) - 攻击者使用的具体技术手段
2. **防御技术** (Defense Techniques) - 对应的检测和防御方法
3. **战术阶段** (Tactics) - 攻击所处的阶段（初始访问、执行、持久化等）

## 输出格式

### 标准输出格式
```markdown
# 攻防技战法分析报告

## 攻击技术

### [T1566] 钓鱼攻击
- **战术阶段**: 初始访问 (Initial Access)
- **技术描述**: 通过伪装的邮件附件投递恶意载荷
- **具体手法**:
  - 使用 .docm 宏文档
  - 伪装为发票/简历
- **IOC 指标**:
  - 发件人: xxx@malicious.com
  - 附件哈希: abc123...
- **检测规则**:
  ```yaml
  title: 可疑 Office 宏执行
  detection:
    selection:
      EventID: 1
      ParentImage|endswith: '\WINWORD.EXE'
      Image|endswith: '\cmd.exe'
  ```

### [T1059.001] PowerShell 执行
- **战术阶段**: 执行 (Execution)
- **技术描述**: 使用 PowerShell 下载并执行恶意脚本
- **具体手法**:
  - Base64 编码命令
  - 绕过执行策略
- **命令示例**: `powershell -enc JABjAD0A...`
- **检测规则**:
  ```sigma
  detection:
    selection:
      CommandLine|contains:
        - '-enc'
        - '-encodedcommand'
        - 'downloadstring'
  ```

## 防御技术

### 针对 [T1566] 的防御
| 防御层 | 措施 | 优先级 |
|--------|------|--------|
| 邮件网关 | 阻止宏文档附件 | 高 |
| 终端 | 禁用 Office 宏 | 高 |
| 用户 | 安全意识培训 | 中 |
| 监控 | 部署 Sigma 检测规则 | 高 |

### 针对 [T1059.001] 的防御
| 防御层 | 措施 | 优先级 |
|--------|------|--------|
| 策略 | 启用 Constrained Language Mode | 高 |
| 日志 | 启用 PowerShell 脚本块日志 | 高 |
| 终端 | 部署 AMSI 集成方案 | 中 |

## 攻击链路图

```
钓鱼邮件 → 宏执行 → PowerShell下载 → 持久化 → C2通信 → 数据窃取
[T1566]    [T1204]   [T1059.001]      [T1053]   [T1071]   [T1041]
```

## ATT&CK 矩阵映射

| 战术 | 技术 | 子技术 |
|------|------|--------|
| 初始访问 | T1566 钓鱼 | T1566.001 附件 |
| 执行 | T1059 脚本 | T1059.001 PowerShell |
| 持久化 | T1053 计划任务 | - |
| C2 | T1071 应用层协议 | T1071.001 HTTP |

## 威胁狩猎查询

### Splunk
```spl
index=windows EventCode=4688
| where ParentImage like "%WINWORD.EXE%"
| where Image like "%cmd.exe%" OR Image like "%powershell.exe%"
```

### KQL (Microsoft Sentinel)
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe")
| where FileName in~ ("cmd.exe", "powershell.exe")
```
```

## 提取规则

### 识别攻击技术
从文档中识别以下内容并映射到 ATT&CK：
- **漏洞利用**: CVE 编号、利用方式、影响范围
- **恶意软件行为**: 进程创建、文件操作、注册表修改、网络连接
- **攻击工具**: Cobalt Strike、Mimikatz、PsExec 等
- **攻击手法**: 钓鱼、水坑、供应链、暴力破解等

### 识别防御技术
- **检测方法**: 日志分析、行为监控、签名检测
- **防护措施**: 网络隔离、权限控制、补丁修复
- **响应动作**: 隔离主机、阻断IP、重置凭据

### ATT&CK 映射
自动将提取的技术映射到 MITRE ATT&CK 框架：
- 战术 (Tactics): 14 个阶段
- 技术 (Techniques): T 编号
- 子技术 (Sub-techniques): .xxx 编号

## 使用方式

### 分析安全报告
```
用户：分析这份 APT 报告，提取攻防技战法
```

### 从事件中提取
```
用户：从这个安全事件描述中提取攻击技术和防御建议
```

### 生成检测规则
```
用户：提取攻击技术并生成 Sigma 检测规则
```

### 生成防御手册
```
用户：分析这个攻击，给出完整的防御方案
```

## 工作流程

1. **读取文档**: 读取安全报告/事件描述
2. **识别攻击指标**: 提取 IOC、恶意行为、攻击工具
3. **ATT&CK 映射**: 将行为映射到技术编号
4. **生成防御措施**: 针对每个攻击技术生成防御建议
5. **输出报告**: 按标准格式输出分析结果

## 输出选项

| 选项 | 说明 |
|------|------|
| `--format markdown` | Markdown 报告（默认）|
| `--format json` | 结构化 JSON |
| `--with-sigma` | 包含 Sigma 检测规则 |
| `--with-hunt` | 包含威胁狩猎查询 |
| `--defense-only` | 仅输出防御措施 |
| `--attack-only` | 仅输出攻击技术 |

## ATT&CK v16 新增技术覆盖

| 技术 ID | 技术名称 | 战术 | 描述 |
|---------|----------|------|------|
| T1195.004 | Compromise Software Dependencies | Initial Access | 供应链依赖投毒 |
| T1199 | Trusted Relationship | Initial Access | 利用可信关系 |
| T1027.013 | Encrypted/Encoded File | Defense Evasion | 加密/编码文件 |
| T1140.004 | AppleScript Deobfuscation | Defense Evasion | AppleScript 去混淆 |
| T1059.013 | PowerShell | Execution | PowerShell (v16重新定义) |
| T1071.008 | DNS Calculation | C2 | DNS 计算通信 |
| T1573.002 | Asymmetric Cryptography | C2 | 非对称加密C2 |
| T1567.002 | Exfiltration to Cloud Storage | Exfiltration | 数据外发到云存储 |
| T1567.003 | Exfiltration to Text Storage Sites | Exfiltration | 数据外发到文本存储站点 |
| T1090.005 | Device Proxy | Defense Evasion/C2 | 设备代理 |

## OWASP 与 ATT&CK 交叉映射

| OWASP 类别 | 相关 ATT&CK 技术 | 应用场景 |
|-----------|----------------|----------|
| A01 Access Control | T1078 Valid Accounts, T1548 Abuse Elevation Control | Web应用权限提升 |
| A02 Crypto Failures | T1573 Encrypted Channel, T1552 Unsecured Credentials | 加密通信与凭据 |
| A03 Injection | T1059 Command & Scripting, T1190 Exploit Public App | 注入攻击 |
| A04 Insecure Design | T1059, T1548 | 设计缺陷利用 |
| A05 Security Misconfig | T1098 Account Manipulation, T1078 | 配置错误利用 |
| A06 Vulnerable Components | T1195 Supply Chain Compromise, T1210 Exploitation of Remote Services | 脆弱组件 |
| A07 Auth Failures | T1110 Brute Force, T1078 Valid Accounts | 认证攻击 |
| A08 Data Integrity | T1055 Process Injection, T1546 Event Triggered Exec | 完整性破坏 |
| A09 Logging Failures | T1070 Indicator Removal, T1562 Impair Defenses | 日志破坏 |
| A10 SSRF | T1046 Network Service Discovery, T1190 | SSRF利用 |

## CVE 参考表

| CVE ID | 产品 | ATT&CK 技术 | TTP提取价值 |
|--------|------|-------------|-------------|
| CVE-2024-21413 | Microsoft Outlook | T1566.001 (Spearphishing Attachment) | 远程代码执行通过特制邮件 |
| CVE-2024-1086 | Linux nf_tables | T1068 (Exploitation for Privilege Escalation) | 内核提权 |
| CVE-2023-46805 | Ivanti Connect Secure | T1190 (Exploit Public-Facing Application) | VPN网关绕过 |
| CVE-2024-21887 | Ivanti Connect Secure | T1068, T1190 | 命令注入 |
| CVE-2023-46604 | Apache ActiveMQ | T1190, T1059 (Remote Code Execution) | RCE利用 |
| CVE-2024-23897 | Jenkins | T1190, T1552.001 | 任意文件读取 |
| CVE-2024-3094 | XZ Utils | T1195.002 (Compromise Software Supply Chain) | 后门植入 |

## YARA 规则示例

### 检测 Cobalt Strike Beacon

```yara
rule Cobalt_Strike_Beacon_Generic {
    meta:
        description = "检测 Cobalt Strike Beacon 内存加载"
        author = "sec-skills"
        date = "2025-06-17"
        reference = "ATT&CK T1059.001, T1071.001"
        mitre_attack_id = "T1071.001"
    strings:
        $pipe = "\\\\\\.\\pipe\\" ascii
        $beacon = { 4D 5A 90 00 03 00 00 00 }
        $reflective = "ReflectiveLoader" ascii
        $msf = "msf_buffer" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($reflective, $msf) or
        ($pipe and $beacon)
}
```

### 检测 Mimikatz

```yara
rule Mimikatz_Generic_Signatures {
    meta:
        description = "检测 Mimikatz 凭据提取工具"
        author = "sec-skills"
        date = "2025-06-17"
        reference = "ATT&CK T1003.001"
        mitre_attack_id = "T1003.001"
    strings:
        $sekurlsa = "sekurlsa" ascii nocase
        $lsadump = "lsadump" ascii nocase
        $kerberos = "kerberos::" ascii nocase
        $privilege = "privilege::debug" ascii nocase
        $mimikatz = "mimikatz" ascii nocase
        $gentilkiwi = "gentilkiwi" ascii nocase
    condition:
        3 of them
}
```

### 检测 PowerShell 混淆

```yara
rule PowerShell_Obfuscation_Patterns {
    meta:
        description = "检测 PowerShell 混淆模式"
        author = "sec-skills"
        date = "2025-06-17"
        reference = "ATT&CK T1027, T1059.001"
        mitre_attack_id = "T1059.001"
    strings:
        $base64 = "-enc" ascii nocase
        $bypass = "-exec bypass" ascii nocase
        $hidden = "-w hidden" ascii nocase
        $noprofile = "-nop" ascii nocase
        $download = "DownloadString" ascii nocase
        $invoke = "IEX(" ascii nocase
        $reflection = "[Reflection.Assembly]" ascii nocase
    condition:
        2 of them
}
```

## IOC 类型与提取规则

| IOC 类型 | 格式 | 正则表达式 | ATT&CK 映射 |
|----------|------|-----------|-------------|
| IPv4 地址 | xxx.xxx.xxx.xxx | `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b` | T1071 |
| 域名 | example.com | `\b[a-z0-9]([a-z0-9-]*[a-z0-9])?\.[a-z]{2,}\b` | T1071 |
| 文件哈希 (MD5) | 32位hex | `\b[a-fA-F0-9]{32}\b` | T1027 |
| 文件哈希 (SHA256) | 64位hex | `\b[a-fA-F0-9]{64}\b` | T1027 |
| URL | http(s)://... | `https?://[^\s<>"]+` | T1566.002 |
| 邮箱地址 | x@x.com | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | T1566.001 |
| CVE 编号 | CVE-YYYY-NNNN | `CVE-\d{4}-\d{4,}` | T1190 |
| C2 端口 | 数字 | 常见: 443, 8443, 8080, 4444, 1337 | T1071 |
| Bitcoin 地址 | bc1/1/3... | `[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59}` | T1486 |

## Sigma 规则生成模板

### 模板 1: 进程创建检测

```yaml
title: {{rule_title}}
id: {{generate_uuid}}
status: experimental
description: {{description}}
references:
    - {{reference_url}}
date: {{date}}
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        {{field}}|{{operator}}:
            - {{value_1}}
            - {{value_2}}
    condition: selection
falsepositives:
    - {{false_positive_notes}}
level: {{severity}}
tags:
    - attack.{{tactic}}
    - attack.t{{technique_id}}
```

### 模板 2: 网络连接检测

```yaml
title: {{rule_title}}
id: {{generate_uuid}}
status: experimental
description: {{description}}
date: {{date}}
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        DestinationIp|cidr:
            - '{{cidr_range}}'
        DestinationPort:
            - {{port}}
    condition: selection
falsepositives:
    - {{false_positive_notes}}
level: {{severity}}
tags:
    - attack.command_and_control
    - attack.t1071
```

### 模板 3: 文件创建检测

```yaml
title: {{rule_title}}
id: {{generate_uuid}}
status: experimental
description: {{description}}
date: {{date}}
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - '{{path_pattern}}'
        TargetFilename|endswith:
            - '{{extension}}'
    condition: selection
falsepositives:
    - {{false_positive_notes}}
level: {{severity}}
tags:
    - attack.{{tactic}}
    - attack.t{{technique_id}}
```

## 合规标准参考

| 标准 | 相关条款 | TTP提取要求 |
|------|----------|-------------|
| NIST SP 800-150 | 全文 | 网络威胁信息共享指南 |
| ISO/IEC 27001:2022 | A.5.7 | 威胁情报收集与分发 |
| PCI DSS 4.0 | Req. 5.2, 10.3 | 恶意软件检测与日志分析 |
| MITRE ATT&CK v16 | 全文 | 技术映射标准参考 |
| STIX 2.1 | 全文 | 威胁情报交换格式 |
| TAXII 2.1 | 全文 | 威胁情报传输协议 |
| GDPR | Art. 33(1) | 安全事件通知中的技术分析 |
| PIPL (中国) | 第57条 | 安全事件技术分析义务 |

## 跨技能工作流

### 工作流 1: 从事件响应到检测规则
```
linux-ir / windows-ir → ttp-extractor → pdf-report
```

1. `linux-ir` 或 `windows-ir` 进行事件响应，收集证据
2. `ttp-extractor` 从事件中提取攻击技术矩阵并生成检测规则
3. `pdf-report` 生成完整事件响应报告

### 工作流 2: 从威胁报告到狩猎规则
```
rga-knowledge-search → ttp-extractor → pdf-report
```

1. `rga-knowledge-search` 检索相关威胁情报报告
2. `ttp-extractor` 提取TTP并生成狩猎查询
3. `pdf-report` 生成威胁狩猎指南

### 工作流 3: 从代码审计到攻击面映射
```
code-audit → ttp-extractor → pdf-report
```

1. `code-audit` 发现应用代码中的漏洞
2. `ttp-extractor` 将漏洞映射到ATT&CK技术，评估攻击面
3. `pdf-report` 生成攻击面评估报告

### 工作流 4: AI安全事件分析
```
prompt-injection-detect → ttp-extractor → pdf-report
```

1. `prompt-injection-detect` 检测到提示注入攻击
2. `ttp-extractor` 提取攻击者的TTP并映射到ATT&CK
3. `pdf-report` 生成AI安全事件分析报告

## 附加资源

- [ATT&CK 战术列表](references/attack-tactics.md)
- [常见攻击技术映射](references/common-techniques.md)
- [Sigma 规则模板](references/sigma-templates.md)
