---
name: data-desensitize
description: 对文档、日志、代码中的敏感信息进行智能识别和脱敏处理，生成可安全分享的版本。当用户要求"数据脱敏"、"脱敏处理"、"PII 脱敏"、"日志脱敏"、"敏感信息替换"、"隐私数据处理"、"GDPR 合规"、"数据匿名化"、"数据脱敏审计"时使用此技能。
metadata:
  version: 1.2.0
  builtin: true
---

# 数据脱敏 (Data Desensitize)

## 核心任务

对文档/日志/代码中的敏感信息进行智能识别和替换，生成可安全分享的脱敏版本，同时保留文档的可读性和上下文关系。

## 合规框架映射

### GDPR（欧盟通用数据保护条例）
- **Article 4(1)** — 个人身份信息(PII)定义：姓名、身份证、邮箱、IP、位置数据
- **Article 25** — 数据保护设计(Privacy by Design)：默认最小化收集和脱敏
- **Article 32** — 安全处理：脱敏作为技术措施
- **Recital 26** — 假名化：数据脱敏后不再与自然人关联

### 中国《个人信息保护法》(PIPL)
- **第28条** — 敏感个人信息：身份证、生物特征、金融账户、行踪轨迹
- **第51条** — 个人信息安全处理义务：去标识化技术措施
- **第55条** — 个人信息保护影响评估：脱敏作为风险缓解

### ISO/IEC 27001 / 27701
- **A.8.10** — 信息删除和资产处置：数据生命周期末端脱敏
- **A.7.4** — PII 去标识化和匿名化

### NIST SP 800-188
- **De-Identification** — 去标识化标准实践
- ** anonymization** — 不可逆脱敏 vs 可逆假名化

### OWASP Top 10 关联
- **A02:2021** — Cryptographic Failures：敏感数据明文传输/存储
- **A04:2021** — Insecure Design：缺少数据保护设计

### MITRE ATT&CK 映射

脱敏作为防御方措施，对应以下攻击技术的缓解：

| Tactic | Technique | 子技术 | 脱敏缓解场景 |
|--------|-----------|--------|-------------|
| Credential Access (TA0006) | **T1552** Unsecured Credentials | **T1552.001** Files | 日志/报告中凭证泄露防护 |
| Credential Access (TA0006) | **T1552** Unsecured Credentials | **T1552.004** Private Keys | 私钥从配置文件/报告脱敏 |
| Credential Access (TA0006) | **T1552** Unsecured Credentials | **T1552.007** Keys | API 密钥从容器/日志中脱敏 |
| Discovery (TA0007) | **T1580** Cloud Infrastructure Discovery | — | 抑制云资源信息暴露 |
| Reconnaissance (TA0043) | **T1592** Gather Victim Host Information | **T1592.002** Software | 软件版本信息从报告中脱敏 |
| Reconnaissance (TA0043) | **T1592** Gather Victim Host Information | **T1592.004** Client Configuration | 客户端配置信息保护 |
| Reconnaissance (TA0043) | **T1589** Gather Victim Identity Information | **T1589.001** Credentials | 凭证信息从社工面清除 |
| Collection (TA0009) | **T1560** Archive Collected Data | — | 压缩包中的敏感数据脱敏 |
| Exfiltration (TA0010) | **T1567** Exfiltration Over Web Service | **T1567.001** Exfil to Code Repository | 代码提交前脱敏检查 |
| Exfiltration (TA0010) | **T1041** Exfiltration Over C2 Channel | — | 日志中外传数据脱敏 |
| Defense Evasion (TA0005) | **T1078** Valid Accounts | **T1078.004** Cloud Accounts | 云账户信息从日志中脱敏 |
| Initial Access (TA0001) | **T1078** Valid Accounts | — | 账户信息保护降低初始访问风险 |

### ATT&CK Mitigations

| Mitigation | ID | 应用场景 |
|-----------|-----|--------|
| Data Loss Prevention | **M1057** | 对出站数据执行脱敏检查 |
| User Account Management | **M1026** | 账户信息从日志/报告中脱敏 |
| Credential Access Protection | **M1043** | 禁止明文存储/传输凭证 |
| Encrypt Sensitive Information | **M1041** | 对可逆脱敏映射表加密存储 |
| Network Segmentation | **M1030** | 脱敏数据与原始数据隔离存储 |
| Restrict File and Directory Permissions | **M1020** | 限制脱敏映射表访问权限 |

### OWASP Top 10 / CWE 映射

| OWASP 类别 | CWE | ATT&CK | 脱敏场景 |
|-----------|------|--------|---------|
| **A02 Cryptographic Failures** | CWE-311 | T1552.001 | 敏感数据明文传输/存储 — 脱敏作为缓解 |
| **A04 Insecure Design** | CWE-209 | T1589.001 | 缺少数据保护设计 — 默认脱敏 |
| **A01 Broken Access Control** | CWE-862 | T1078.004 | 脱敏映射表访问控制 |
| **A05 Security Misconfiguration** | CWE-312 | T1552.007 | 配置文件中的密钥明文存储 |
| **A07 Identification & Auth Failures** | CWE-522 | T1552.004 | 凭据保护不足 — 脱敏降低泄露风险 |
| **A09 Logging Failures** | CWE-778 | T1567.001 | 日志中记录敏感信息 — 脱敏净化日志 |

## 脱敏流程

```
1. 读取原始文档
2. 自动检测敏感信息（17+ 种类型，见下方）
3. 生成一致性替换（相同值 → 相同占位符）
4. 上下文感知过滤（排除版本号、端口号等误报）
5. 输出脱敏文档 + 映射表 + 审计报告
```

## 敏感信息类型

### 个人身份信息 (PII)

| 类型 | 标识符 | 检测模式 | 示例 |
|------|--------|---------|------|
| 公网 IP | `[PUBLIC_IP_N]` | IPv4/IPv6 正则 | 8.8.8.8 → [PUBLIC_IP_1] |
| 内网 IP | `[PRIVATE_IP_N]` | RFC 1918 范围 | 192.168.1.100 → [PRIVATE_IP_1] |
| 域名 | `[DOMAIN_N]` | FQDN 匹配 | example.com → [DOMAIN_1] |
| 邮箱 | `[EMAIL_N]` | RFC 5322 格式 | user@corp.com → [EMAIL_1] |
| 手机号(中) | `[PHONE_N]` | 1[3-9]XXXXXXXXX | 13800138000 → [PHONE_1] |
| 身份证(中) | `[IDCARD_N]` | 18位含校验位 | 110101199001011234 → [IDCARD_1] |
| SSN(美) | `[SSN_N]` | NNN-NN-NNNN | 123-45-6789 → [SSN_1] |
| 人名 | `[PERSON_N]` | NER + 上下文 | 张三 → [PERSON_1] |

### 金融信息

| 类型 | 标识符 | 检测模式 | 示例 |
|------|--------|---------|------|
| 银行卡 | `[BANKCARD_N]` | 13-19位 Luhn 校验 | 6222021234567890123 → [BANKCARD_1] |
| 信用卡 | `[CREDITCARD_N]` | Visa/MC/Amex 模式 | 4111 1111 1111 1111 → [CREDITCARD_1] |

### 凭据和密钥

| 类型 | 标识符 | 检测模式 | 示例 |
|------|--------|---------|------|
| API 密钥 | `[APIKEY_N]` | AWS/GCP/通用模式 | sk-xxx... → [APIKEY_1] |
| 密码/凭据 | `[CREDENTIAL_N]` | key=value 格式 | password=xxx → [CREDENTIAL_1] |
| JWT Token | `[JWT_N]` | eyJ... 模式 | eyJhbG... → [JWT_1] |
| 私钥 | `[PRIVATE_KEY_N]` | PEM 格式 | -----BEGIN RSA... → [PRIVATE_KEY_1] |
| 连接字符串 | `[CONNSTR_N]` | mongodb://... 等 | mongodb://user:pass@... → [CONNSTR_1] |

### 组织和资产

| 类型 | 标识符 | 检测模式 | 示例 |
|------|--------|---------|------|
| 组织名称 | `[ORG_N]` | NER + 自定义词表 | 某某公司 → [ORG_1] |
| 产品名称 | `[PRODUCT_N]` | 自定义词表 | 某某系统 → [PRODUCT_1] |
| 服务器名 | `[HOST_N]` | FQDN/主机名 | web-prod-01 → [HOST_1] |
| MAC 地址 | `[MAC_N]` | IEEE 802 格式 | 00:1B:44:11:3A:B7 → [MAC_1] |

详细定义见：[references/sensitive-types.md](references/sensitive-types.md)

## 脱敏规则

### 一致性原则
- **相同的敏感值必须映射到相同的占位符**
- 例：文档中多次出现 `192.168.1.100`，全部替换为 `[PRIVATE_IP_1]`

### 拓扑保留（可选）
- 同子网 IP 脱敏后仍保持同网段关系
- 例：`192.168.1.100` 和 `192.168.1.101` → `[PRIVATE_IP_1]` 和 `[PRIVATE_IP_2]`（暗示同网段）

### 弱口令保留（可选）
- 常见弱口令可保留用于安全分析
- 例：`123456`、`admin`、`password` 保持原样

### 上下文感知过滤
- `version: 1.0.0` 中的数字不识别为 IP
- `port: 8080` 不识别为敏感信息
- 代码中的变量名不识别为人名
- 正则表达式注释不识别为密钥

### 不可逆 vs 可逆脱敏
- **不可逆（默认）**：使用占位符替换，无法还原
- **可逆**：生成加密映射表，需要密钥才能还原（使用 AES-256-GCM）

## 脱敏策略矩阵

| 场景 | 策略 | 说明 |
|------|------|------|
| 安全报告分享 | 完全脱敏 + 占位符 | 对外发布，完全匿名化 |
| 日志分析外包 | IP/域名脱敏 + 时间保留 | 保留时序，去除身份 |
| 代码审计交付 | 凭据/密钥脱敏 | 保留代码逻辑，去除敏感配置 |
| 内部培训材料 | 全量脱敏 + 弱口令保留 | 教学+安全意识 |
| 渗透测试报告 | 全量脱敏 + 拓扑保留 | 保留攻击路径结构 |
| 取证数据移交 | 司法级脱敏 + 审计链 | 完整操作日志 |

## 输出格式

### 1. 脱敏文档
直接输出脱敏后的完整文档，保持原格式（Markdown/JSON/YAML/文本）。

### 2. 映射表（文档末尾注释或独立文件）
```
<!-- DESENSITIZE_MAPPINGS
[PUBLIC_IP_1] = 8.8.8.8
[DOMAIN_1] = example.com
[EMAIL_1] = admin@example.com
[APIKEY_1] = AKIAIOSFODNN7EXAMPLE
-->
```

### 3. 审计报告（可选）
```json
{
  "timestamp": "2026-06-14T10:00:00+08:00",
  "input_file": "incident-report.md",
  "input_size": 45230,
  "output_file": "incident-report.desensitized.md",
  "total_findings": 47,
  "by_type": {"PUBLIC_IP": 5, "PRIVATE_IP": 12, "EMAIL": 8, "PERSON": 15, "ORG": 7},
  "by_severity": {"high": 15, "medium": 25, "low": 7},
  "compliance": ["GDPR Art.25", "PIPL Art.51", "ISO 27001 A.8.10"],
  "reversible": false
}
```

## 使用方式

### 单文件脱敏
```bash
python3 scripts/desensitizer.py -f incident-report.md -o output.md
```

### 批量脱敏
```bash
python3 scripts/desensitizer.py -d /path/to/logs/ -o /path/to/output/
```

### 仅扫描（不脱敏）
```bash
python3 scripts/desensitizer.py -f config.yaml --scan-only
```

### 验证脱敏完整性
```bash
python3 scripts/verify_desensitize.py -o output.md --original input.md
```

### 指定脱敏类型
```
用户：只脱敏 IP 和域名，保留其他信息
```

### 并发批量处理
当用户要求并发/并行/快速批量处理时：
- 每个子代理处理一个文件
- 主代理汇总结果和全局映射表
- 确保跨文件的一致性映射

## Sigma 检测规则

### Sigma 规则 1：敏感数据明文传输检测
```yaml
title: Sensitive Data Transmitted in Plaintext
description: Detects potential PII or credentials in outbound traffic that should have been desensitized
status: experimental
author: sec-skills
logsource:
    product: proxy
    category: file_transfer
detection:
    selection_sensitive:
        - "[PRIVATE_IP_"
        - "[PUBLIC_IP_"
        - "[EMAIL_"
        - "[IDCARD_"
        - "[BANKCARD_"
    filter_desensitized:
        RequestContent|contains:
            - '[REDACTED'
            - '[PRIVATE_IP_'
            - '[EMAIL_'
    condition: selection_sensitive and not filter_desensitized
falsepositives:
    - Legitimate internal data transfers
level: high
tags:
    - attack.exfiltration
    - attack.t1567.001
    - attack.t1552.001
```

### Sigma 规则 2：日志中检测未脱敏凭证
```yaml
title: Unmasked Credentials in Application Logs
description: Detects plaintext credentials or API keys appearing in log files without desensitization
status: experimental
author: sec-skills
logsource:
    product: linux
    category: file_write
detection:
    selection_log:
        TargetFilename|endswith:
            - '.log'
            - '.json'
            - '.yaml'
    selection_cred:
        Content|contains:
            - 'password='
            - 'api_key='
            - 'secret='
            - 'AKIA'  # AWS key prefix
            - 'private_key'
    condition: selection_log and selection_cred
falsepositives:
    - Security tools logging hashed/encrypted values
level: high
tags:
    - attack.credential_access
    - attack.t1552.001
    - attack.t1552.007
```

## YARA 检测规则

```yara
rule Unmasked_API_Keys_in_Document
{
    meta:
        description = "Detects unmasked API keys in documents awaiting desensitization"
        author = "sec-skills"
    strings:
        $aws = /AKIA[0-9A-Z]{16}/
        $gcp = /AIza[0-9A-Za-z\-_]{35}/
        $github = /gh[pousr]_[A-Za-z0-9]{36}/
        $slack = /xox[baprs]-[0-9A-Za-z-]{10,}/
        $generic = /sk-[a-zA-Z0-9]{20,}/
    condition:
        1 of ($aws, $gcp, $github, $slack, $generic)
}

rule Unmasked_PII_Patterns
{
    meta:
        description = "Detects PII patterns that should be desensitized"
        author = "sec-skills"
    strings:
        $cn_id = /\b\d{17}[0-9Xx]\b/        // Chinese ID card
        $us_ssn = /\b\d{3}-\d{2}-\d{4}\b/    // US SSN
        $phone = /\b1[3-9]\d{9}\b/            // Chinese mobile
        $email = /[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/
    condition:
        2 of ($cn_id, $us_ssn, $phone, $email)
}
```

## CVE 参考表

| CVE | 漏洞 | 脱敏关联 |
|-----|------|--------|
| CVE-2021-43798 | Grafana 目录遍历 | 未脱敏配置导致插件接口泄露 |
| CVE-2020-3452 | Cisco ASA 目录遍历 | 配置文件中的凭证未脱敏被读取 |
| CVE-2019-12384 | Jackson 反序列化 | 日志中序列化对象包含未脱敏 PII |
| CVE-2021-44228 | Log4Shell JNDI 注入 | 日志注入利用未脱敏的上下文数据 |
| CVE-2023-22515 | Confluence 权限提升 | 未脱敏的管理员凭证被利用 |

## IOC 采集指引

| IOC 类型 | 提取方法 | 脱敏处理 | 后续用途 |
|---------|---------|--------|--------|
| IP 地址 | 日志解析 + 正则提取 | 替换为 `[PRIVATE_IP_N]`/`[PUBLIC_IP_N]` | 网络拓扑分析（保留拓扑关系） |
| 域名 | DNS 日志 + URL 提取 | 替换为 `[DOMAIN_N]` | 威胁情报比对（脱敏前后都可比对） |
| 邮箱 | 日志/文档提取 | 替换为 `[EMAIL_N]` | 钓鱼分析中受害者匿名化 |
| 凭证 | 配置文件/日志扫描 | 替换为 `[CREDENTIAL_N]` | 泄露检测（映射表安全存储） |
| API 密钥 | 正则匹配 + 格式检测 | 替换为 `[APIKEY_N]` | 密钥轮换验证 |
| 用户身份 | NER + 上下文提取 | 替换为 `[PERSON_N]` | 内部威胁分析（去标识化） |
| 系统名称 | 主机名/服务名提取 | 替换为 `[HOST_N]` | 资产管理匿名化 |
| 连接字符串 | URI 格式匹配 | 替换为 `[CONNSTR_N]` | 数据库安全审计 |

## 跨技能工作流

### 工作流 1：安全报告脱敏发布
```
linux-ir/windows-ir/macos-ir → 事件响应报告
  → data-desensitize (全量脱敏)
  → pdf-report/office-report (生成脱敏报告)
  → data-desensitize (二次验证脱敏完整性)
  → 对外发布
```

### 工作流 2：日志分析外包脱敏
```
traffic-analysis → 网络流量日志
  → data-desensitize (IP/域名/用户脱敏, 保留时序)
  → 第三方分析 (脱敏后数据安全交付)
  → data-desensitize (分析结果回映射, 可选)
```

### 工作流 3：代码审计脱敏交付
```
[code-audit] → 源代码 + 配置文件
  → data-desensitize (密钥/凭证/内部URL脱敏)
  → [pdf-analysis/office-malware-analyzer] (分析脱敏后的文档)
  → 外部安全评估交付
```

### 上游（提供数据给 data-desensitize）
- **linux-ir / windows-ir / macos-ir** — IR 采集的日志和取证数据需要脱敏后才能外发
- **phishing-analysis** — 钓鱼邮件分析报告分享前需脱敏
- **traffic-analysis** — 网络流量分析中的内部 IP 需脱敏

### 下游（消费脱敏后的数据）
- **pdf-report / office-report** — 生成脱敏后的正式报告
- **ttp-extractor** — 从脱敏报告中提取 TTP（不含受害者信息）
- **researching-vulnerabilities** — 漏洞报告公开前的脱敏处理

```
[IR 技能] → 采集日志 → [data-desensitize] → 脱敏数据 → [report 技能] → 正式报告
```

## 工作流程

1. **读取文档**：使用 Read 工具或 `desensitizer.py -f` 读取原始内容
2. **识别敏感信息**：按类型自动检测所有敏感数据（17+ 种）
3. **生成映射**：为每个唯一敏感值分配一致性占位符
4. **执行替换**：替换所有敏感信息
5. **验证完整性**：使用 `verify_desensitize.py` 验证无遗漏
6. **输出结果**：
   - 脱敏文档（`.desensitized` 后缀）
   - 映射表（JSON 格式，可选加密）
   - 审计报告（JSON 格式）

## 示例

见：[references/examples.md](references/examples.md)

## 注意事项

1. **不要过度脱敏**：版本号、端口号、普通数字不是敏感信息
2. **保持可读性**：脱敏后文档仍应易于理解
3. **处理边界情况**：URL 中的域名、日志中的混合格式
4. **大文件分块**：超大文件分块处理，保持映射一致性
5. **密钥安全**：可逆脱敏的映射表必须单独安全存储
6. **审计留痕**：记录脱敏操作的时间、操作者、文件摘要

## 附加资源

- [敏感类型详细定义](references/sensitive-types.md)
- [脱敏示例](references/examples.md)
- [报告格式](references/report-format.md)
