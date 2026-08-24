---
name: mail-attachment-downloader
description: 当用户要求"下载邮箱附件"、"获取邮箱中转站文件"、"下载 163 邮箱附件"、"下载 QQ 邮箱附件"、"分析邮箱分享链接"时使用此技能。
metadata:
  version: 1.3.0
  builtin: true
---

# 邮箱附件中转站下载技能

从邮箱文件中转站（163/QQ）提取真实下载链接并下载文件，支持文件哈希计算、元数据提取和自动化威胁分诊。

> 此技能通常作为其他分析技能的**上游依赖**，用于获取待分析的文件。作为邮件攻击链的入口点，下载的文件可能包含恶意载荷。

## MITRE ATT&CK 技术映射

### 战术与技术覆盖表

| 战术 | 技术 | 子技术 | 场景描述 |
|------|------|--------|---------|
| Initial Access (TA0001) | **T1566** Phishing | **T1566.001** Spearphishing Attachment | 钓鱼邮件通过中转站投递恶意附件（文档/可执行文件） |
| Initial Access (TA0001) | **T1566** Phishing | **T1566.002** Spearphishing Link | 邮件正文中包含附件下载链接，引导用户点击 |
| Initial Access (TA0001) | **T1566** Phishing | **T1566.004** Spearphishing Voice | 结合社工电话引导受害者打开邮件附件链接 |
| Execution (TA0002) | **T1203** Exploitation for Client Execution | — | 下载的附件利用客户端漏洞（Office/PDF/浏览器）自动执行 |
| Execution (TA0002) | **T1204** User Execution | **T1204.002** Malicious File | 用户手动下载并打开恶意附件文件 |
| Defense Evasion (TA0005) | **T1036** Masquerading | **T1036.008** Masquerade File Type | 附件伪装为正常文件类型（.pdf.exe → 显示为 PDF） |
| Defense Evasion (TA0005) | **T1027** Obfuscated Files | **T1027.002** Software Packing | 下载的恶意软件使用加壳/混淆技术规避检测 |
| Command and Control (TA0011) | **T1105** Ingress Tool Transfer | — | 从外部邮箱服务下载工具/载荷到受害者主机 |
| Resource Development (TA0042) | **T1588** Obtain Capabilities | **T1588.001** Malware | 攻击者通过邮件附件分发恶意软件载荷 |
| Collection (TA0009) | **T1560** Archive Collected Data | **T1560.002** Archive via Library | 附件下载后压缩包中包含恶意载荷 |
| Defense Evasion (TA0005) | **T1027** Obfuscated Files | **T1027.011** File System Storage Offsets | 下载的文件使用隐藏/偏移数据存储恶意代码 |

### ATT&CK Mitigations 对应

| Mitigation ID | 名称 | 应用场景 |
|---------------|------|---------|
| M1049 | Antivirus/Antimalware | 下载完成后自动扫描文件 |
| M1031 | Network Intrusion Prevention | 检测已知的恶意文件哈希 |
| M1021 | Restrict Web-Based Content | 限制从不可信邮箱域名下载文件 |
| M1017 | User Guidance | 培训用户不随意下载未知来源的邮件附件 |

## OWASP Top 10 / CWE 映射

| OWASP 类别 | CWE ID | 关联场景 |
|-----------|--------|---------|
| **A01** Broken Access Control | CWE-284 | 未经授权访问邮件附件链接 |
| **A04** Insecure Design | CWE-829 | 包含不可信来源的文件（从未知邮箱服务下载） |
| **A05** Security Misconfiguration | CWE-311 | 附件传输缺乏加密（HTTP 而非 HTTPS） |
| **A06** Vulnerable Components | CWE-1104 | 下载的文件包含漏洞利用代码或恶意依赖 |
| **A08** Software & Data Integrity | CWE-345 | 下载文件完整性验证不足（缺少哈希校验） |
| **A09** Security Logging | CWE-778 | 附件下载操作缺乏审计日志记录 |

## CVE 参考（邮件附件相关高危漏洞）

| CVE ID | 产品 | 影响 | CVSS | 附件场景 |
|--------|------|------|------|---------|
| CVE-2023-23397 | Microsoft Outlook | 特权提升 | 9.8 | 日历提醒附件触发 NTLM 泄露 |
| CVE-2023-36884 | Office/Windows HTML | RCE | 8.3 | 恶意邮件附件利用 Office 漏洞 |
| CVE-2022-30190 | MSDT (Follina) | RCE | 7.8 | 邮件附件中包含恶意 URL 触发 MSDT |
| CVE-2021-44228 | Apache Log4j | RCE | 10.0 | 邮件附件触发 Log4Shell 利用链 |
| CVE-2023-21716 | Microsoft Word | RCE | 7.8 | 恶意 Word 附件中的 RTF 格式利用 |

## Sigma 检测规则

### 规则 1: 邮箱附件下载后可疑进程创建

```yaml
title: 邮箱附件下载后可疑进程创建
id: 7a3c1e2f-8b5d-4c6a-9e0f-1a2b3c4d5e6f
status: experimental
description: 检测从邮箱附件中转站下载文件后，短时间内创建可疑子进程的行为
references:
    - https://attack.mitre.org/techniques/T1204/002/
    - https://attack.mitre.org/techniques/T1566/001/
tags:
    - attack.execution
    - attack.initial_access
    - attack.t1204.002
    - attack.t1566.001
logsource:
    product: windows
    category: process_creation
detection:
    suspicious_process:
        Image|endswith:
            - 'powershell.exe'
            - 'cmd.exe'
            - 'mshta.exe'
            - 'wscript.exe'
            - 'cscript.exe'
            - 'rundll32.exe'
    from_download_dir:
        CurrentDirectory|contains:
            - 'Downloads'
            - 'Temp'
            - 'mail_download'
    timeframe: 5m
    condition: suspicious_process and from_download_dir
falsepositives:
    - 正常软件安装后从下载目录运行
level: high
```

### 规则 2: 邮箱附件文件类型伪装检测

```yaml
title: 邮箱附件文件类型伪装检测
id: 8b4d2f3a-9c6e-4d7b-af1a-2b3c4d5e6f7a
status: experimental
description: 检测邮箱附件下载的文件实际类型与声明的 MIME 类型不一致（可执行文件伪装为文档）
references:
    - https://attack.mitre.org/techniques/T1036/008/
    - https://cwe.mitre.org/data/definitions/829.html
tags:
    - attack.defense_evasion
    - attack.t1036.008
logsource:
    product: linux
    category: file_event
detection:
    declared_document:
        ContentType|contains:
            - 'application/pdf'
            - 'application/msword'
            - 'application/vnd.openxmlformats'
    actual_executable:
        CommandLine|contains:
            - 'MZ'
            - 'PE32'
            - 'executable'
            - 'ELF'
    condition: declared_document and actual_executable
falsepositives:
    - 文件类型检测工具的误报
level: critical
```

## IOC 采集指引

从邮箱附件下载文件中可提取的 IOC 类型：

| IOC 类型 | 提取方法 | 用途 | 示例 |
|---------|---------|------|------|
| **MD5 哈希** | `hashlib.md5(file_data).hexdigest()` | 文件指纹查询威胁情报 | `d41d8cd98f00b204e9800998ecf8427e` |
| **SHA256 哈希** | `hashlib.sha256(file_data).hexdigest()` | 精确文件标识（VirusTotal） | `e3b0c44298fc1c14...` |
| **下载 URL** | 从 API 响应中提取 `downloadUrl` | C2 基础设施分析 | `https://fs.163.com/download/...` |
| **文件名** | 从 `Content-Disposition` 头解析 | 社工攻击模式分析 | `Invoice_2024.pdf.exe` |
| **邮箱域名** | 从分享链接 URL 解析 | 攻击者邮箱基础设施追踪 | `mail.163.com`, `mail.qq.com` |
| **嵌入 URL** | 下载后分析文件内容中的 URL | C2 地址提取 | 从文档宏/脚本中提取 |
| **文件真实类型** | 通过 magic bytes 检测 | 类型伪装检测 | `MZ` → PE 可执行文件 |

## 合规框架参考

| 标准 | 条款 | 关联说明 |
|------|------|---------|
| **ISO 27001** | A.8.7 恶意软件防范 | 邮箱附件作为攻击载体，需要下载控制和扫描 |
| **ISO 27001** | A.8.20 网络安全 | 邮件传输通道安全监控 |
| **NIST SP 800-83** | 恶意软件事件预防 | 邮件附件下载控制指南 |
| **NIST SP 800-61** | 计算机安全事件处理 | 附件相关安全事件的响应流程 |
| **GDPR** | Art. 32 | 邮件附件中的个人数据安全处理 |
| **PIPL** | 第51条 | 邮件传输中个人信息的安全保障 |
| **PCI DSS** | 5.2 | 针对恶意软件的防护（含邮件附件载体） |
| **GB/T 35273** | 个人信息安全规范 | 邮件附件中的个人信息保护 |

## 依赖要求

**Python 版本**: 3.8+

**内置脚本**:
| 脚本 | 用途 |
|------|------|
| mail_downloader.py | 邮箱中转站文件下载（主入口） |
| attachment_triage.py | 附件安全分诊脚本（类型检测+哈希+威胁情报查询） |

**必需依赖**:
| 库 | 安装 | 用途 |
|------|------|------|
| requests | `pip install requests` | HTTP 请求 |

## 支持的邮箱服务

| 服务商 | URL 模式 | 提取方式 |
|-------|---------|---------|
| 163 邮箱 | `mail.163.com/large-attachment-download/` | API: linkKey → downloadUrl |
| 163 大师 | `dashi.163.com/html/cloud-attachment-download` | API: key → downloadUrl |
| QQ 邮箱 (新版) | `wx.mail.qq.com/ftn/download` | JSON API: body.url |
| QQ 邮箱 (旧版) | `mail.qq.com/cgi-bin/ftnExs_download` | 页面解析: `var url = "..."` |

## 快速开始

```bash
cd <SKILL_DIR>

# 分析链接（不下载，仅获取真实 URL）
python scripts/mail_downloader.py "<URL>" --analyze

# 下载文件到指定目录
python scripts/mail_downloader.py "<URL>" -d ./downloads

# JSON 格式输出
python scripts/mail_downloader.py "<URL>" -o json

# 指定超时时间
python scripts/mail_downloader.py "<URL>" -t 60

# 下载后自动分诊（类型检测+哈希+威胁评估）
python scripts/attachment_triage.py ./downloads/suspicious_file.exe

# 批量分诊目录下所有文件
python scripts/attachment_triage.py ./downloads/ --batch
```

## 工作流程

### Phase 1: 链接识别

1. **URL 模式匹配**
   - 检测是否为已知邮箱中转站链接
   - 识别服务商（163/QQ）
   - 提取关键参数（linkKey, file, key）

### Phase 2: 真实链接获取

2. **163 邮箱处理**
   ```
   提取: file= 或 key= 参数
   API: POST https://mail.163.com/filehub/bg/dl/prepare
   请求: {"linkKey": "<提取的key>"}
   响应: data.downloadUrl
   ```

3. **QQ 邮箱处理**

   **wx.mail.qq.com (新版 JSON API)**:
   ```
   请求: GET 分享链接
   响应: JSON {"head":{"ret":0}, "body":{"url":"..."}}
   提取: body.url
   ```

   **mail.qq.com (旧版 HTML)**:
   ```
   访问: 分享页面 HTML
   提取: 正则 var\s+url\s*=\s*"([^"]+)"
   处理: 替换 \x26 → &
   ```

### Phase 3: 文件下载

4. **下载与验证**
   | 步骤 | 说明 |
   |------|------|
   | 流式下载 | 分块写入，支持大文件 |
   | 文件名提取 | 从 Content-Disposition 或 URL |
   | 哈希计算 | MD5 + SHA256 |
   | 元数据记录 | 大小、类型、路径、来源URL |

### Phase 4: 安全分诊

5. **自动化威胁评估**（使用 `attachment_triage.py`）
   - **Magic bytes 检测**: 识别文件真实类型（vs 声明的 MIME）
   - **文件类型伪装检测**: PE 伪装为 PDF/Office？
   - **哈希威胁查询**: MD5/SHA256 对比已知恶意软件数据库
   - **嵌入 URL 提取**: 扫描文件中的可疑链接
   - **风险评分**: 综合评估给出 Low/Medium/High/Critical

### Phase 5: 结果输出与转发

6. **返回信息**
   | 字段 | 说明 |
   |------|------|
   | success | 是否成功 |
   | provider | 服务商 (163/qq) |
   | download_url | 真实下载链接 |
   | filename | 文件名 |
   | size | 文件大小 |
   | md5 / sha256 | 文件哈希 |
   | path | 本地保存路径 |
   | file_type_real | 真实文件类型（magic bytes） |
   | risk_level | 风险评级 (Low/Medium/High/Critical) |
   | recommended_skill | 推荐的下游分析技能 |

## 命令行参数

### mail_downloader.py

```
mail_downloader.py <URL> [OPTIONS]

位置参数:
  url                   邮箱中转站分享链接

选项:
  -d, --save-dir DIR    保存目录（默认临时目录）
  -t, --timeout SEC     超时时间（默认 30 秒）
  -o, --output FORMAT   输出格式: text / json
  --analyze             仅分析链接，不下载文件
```

### attachment_triage.py

```
attachment_triage.py <FILE|DIR> [OPTIONS]

位置参数:
  file                  待分析的文件或目录路径

选项:
  --batch               批量分析目录下所有文件
  -o, --output FORMAT   输出格式: text / json
  --extract-urls        从文件中提取可疑 URL
  --check-hash          输出哈希用于威胁情报查询
```

## 输出格式

### 下载报告

```
============================================================
邮箱中转站文件下载报告
============================================================

【基本信息】
  原始链接: https://mail.163.com/large-attachment-download/...
  服务商: 163
  状态: ✓ 成功

【下载链接】
  真实下载 URL: https://fs.163.com/download/...

【文件信息】
  文件名: invoice.pdf
  大小: 1.25 MB
  类型: application/pdf
  MD5: d41d8cd98f00b204e9800998ecf8427e
  SHA256: e3b0c44298fc1c149afbf4c8996fb924...
  保存路径: /tmp/mail_download_xxx/invoice.pdf

============================================================
```

### 分诊报告

```
============================================================
邮箱附件安全分诊报告
============================================================

【文件基本信息】
  文件名: report.pdf.exe
  大小: 456 KB
  MD5: a1b2c3d4e5f6...
  SHA256: f1e2d3c4b5a6...

【类型分析】
  声称类型: application/pdf
  真实类型: PE32 executable (MS Windows)
  ⚠️ 类型伪装! 声称为 PDF 但实为可执行文件

【风险评估】
  风险等级: 🔴 CRITICAL
  原因:
    - 文件类型伪装 (T1036.008)
    - 文件名使用双扩展名
    - PE 文件包含网络通信功能

【IOC 提取】
  嵌入 URL: http://185.220.101.42/c2/beacon
  嵌入域名: malicious-c2.example.com

【推荐操作】
  → 调用 binary-reverse-engineering 进行深度逆向分析
  → 使用 SHA256 查询 VirusTotal
  → 提取 IOC 到 ttp-extractor 进行战术映射
============================================================
```

## 跨技能工作流

### 工作流 1: 钓鱼邮件附件分析链

```
phishing-analysis (钓鱼邮件分析)
  └─→ 发现邮箱附件链接
      └─→ mail-attachment-downloader (下载文件 + 安全分诊)
          ├─→ office-malware-analyzer (Office 文档分析)
          │    └─→ ttp-extractor (提取 ATT&CK 技术)
          │         └─→ pdf-report (生成报告)
          ├─→ pdf-analysis (PDF 文件分析)
          └─→ binary-reverse-engineering (可执行文件逆向)
               └─→ ttp-extractor (提取 ATT&CK 技术)
```

### 工作流 2: 大规模邮件附件威胁狩猎

```
eml-malware-analyzer (批量 EML 分析)
  └─→ 提取邮箱附件链接
      └─→ mail-attachment-downloader (批量下载 + 分诊)
          ├─→ 高风险文件 → binary-reverse-engineering
          ├─→ 中风险文件 → code-audit (源代码审查)
          └─→ 所有 IOC → ttp-extractor → pdf-report
```

### 工作流 3: 合规审计邮件附件传输

```
mail-attachment-downloader (下载 + 哈希记录)
  └─→ 记录所有下载操作的审计日志 (GDPR Art.32 / PIPL 第51条)
      └─→ pdf-report (生成合规报告)
```

## 误报排除指南

| 场景 | 判断依据 | 处理方式 |
|------|---------|---------|
| 公司内部文件共享 | 发件人为内部域名，文件类型匹配声明 | 标记为可信来源，跳过深度分析 |
| 已知软件安装包 | SHA256 匹配官方发布哈希 | 标记为已知良好，跳过分析 |
| 压缩包内多重打包 | 嵌套层级 ≤2 且无可执行文件 | 标记为低风险 |
| HTML 附件 | 正常的邮件签名或日历邀请 | 检查是否包含 JavaScript 后放行 |

## 与其他技能的关联

**下游技能**（依赖本技能下载文件后分析）：

| 技能 | 使用场景 | 触发条件 |
|------|---------|---------|
| `url-analysis` | 分析 URL 时发现邮箱中转站链接 | URL 匹配邮箱模式 |
| `phishing-analysis` | 分析钓鱼邮件中的附件链接 | 钓鱼邮件分析流程 |
| `eml-malware-analyzer` | 分析 EML 邮件中的附件链接 | EML 解析发现链接 |
| `binary-reverse-engineering` | 下载后分析可执行文件 | 文件类型为 PE/ELF |
| `office-malware-analyzer` | 下载后分析 Office 文档 | 文件类型为 Office |
| `pdf-analysis` | 下载后分析 PDF 文件 | 文件类型为 PDF |
| `ttp-extractor` | 从下载文件中提取 TTP | 发现 ATT&CK 技术 |
| `pdf-report` | 生成最终分析报告 | 分析完成 |

**典型调用链**：
```
phishing-analysis
    └─→ mail-attachment-downloader (下载 + 分诊)
        ├─→ office-malware-analyzer (分析 .docm)
        │    └─→ ttp-extractor → pdf-report
        └─→ binary-reverse-engineering (分析 .exe)
             └─→ ttp-extractor → pdf-report
```

## 安全注意事项

| 风险 | 缓解措施 |
|------|---------|
| 下载恶意文件 | 默认保存到临时目录，不自动执行 |
| 链接过期 | 返回明确错误信息 |
| 大文件 | 流式下载，可设置超时 |
| 网络异常 | 重试机制 + 详细错误信息 |
| 类型伪装 | attachment_triage.py 通过 magic bytes 检测真实类型 |
| C2 通信 | 提取嵌入 URL/域名用于威胁情报比对 |
| 二次投递 | 记录下载源 URL 用于追踪攻击链 |

## 使用示例

### 示例 1: 下载可疑钓鱼邮件附件

```bash
# 步骤 1: 分析链接（不下载）
$ python scripts/mail_downloader.py "https://mail.163.com/large-attachment-download/?file=abc123" --analyze
服务商: 163 邮箱
真实下载 URL: https://fs.163.com/download/abc123/Invoice.pdf
文件大小: 约 1.2 MB

# 步骤 2: 下载文件
$ python scripts/mail_downloader.py "https://mail.163.com/large-attachment-download/?file=abc123" -d ./quarantine

# 步骤 3: 安全分诊
$ python scripts/attachment_triage.py ./quarantine/Invoice.pdf --extract-urls --check-hash
```

### 示例 2: 自动化批量处理

```bash
# 批量下载并分诊（配合 eml-malware-analyzer 使用）
$ for url in $(cat suspicious_urls.txt); do
    python scripts/mail_downloader.py "$url" -d ./quarantine -o json >> download_log.json
  done
$ python scripts/attachment_triage.py ./quarantine/ --batch -o json > triage_report.json
```

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 📋 报告格式规范
