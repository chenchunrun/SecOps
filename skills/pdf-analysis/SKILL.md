---
name: pdf-analysis
description: PDF 恶意文件分析。当用户询问"分析 PDF 是否恶意"、"检测 PDF 安全性"、"PDF 威胁分析"、"检查 PDF 是否有病毒"、"PDF 安全检测"、"扫描 PDF"、"PDF 钓鱼检测"、"PDF 嵌入文件提取"、"PDF JavaScript 分析"时使用此技能。
metadata:
  version: 1.2.0
  builtin: true
---

# PDF 恶意分析

对可疑 PDF 文件进行全面安全分析：结构检测、JavaScript 提取、嵌入文件发现、钓鱼 URL 识别、二维码检测、CVE 关联匹配。

## MITRE ATT&CK 映射

| Tactic | Technique | 子技术 | PDF 相关场景 |
|--------|-----------|--------|-------------|
| Initial Access (TA0001) | **T1566** Phishing | **T1566.001** Spearphishing Attachment | 通过钓鱼邮件投递恶意 PDF 附件 |
| Initial Access (TA0001) | **T1566** Phishing | **T1566.002** Spearphishing Link | PDF 中嵌入钓鱼 URL 诱导点击 |
| Execution (TA0002) | **T1059** Command and Scripting Interpreter | **T1059.007** JavaScript | PDF 内嵌 JavaScript 在阅读器中执行 |
| Execution (TA0002) | **T1204** User Execution | **T1204.001** Malicious File | 用户被诱导打开恶意 PDF 文件 |
| Defense Evasion (TA0005) | **T1027** Obfuscated Files | **T1027.010** Command Obfuscation | JavaScript 混淆代码隐藏真实意图 |
| Defense Evasion (TA0005) | **T1036** Masquerading | **T1036.008** Masquerade File Type | 伪造 PDF 文件头隐藏真实文件类型 |
| Defense Evasion (TA0005) | **T1140** Deobfuscate/Decode | — | PDF 流多层解码还原隐藏载荷 |
| Defense Evasion (TA0005) | **T1027.002** Software Packing | — | PDF 嵌入加壳可执行文件 |
| Discovery (TA0007) | **T1082** System Information Discovery | — | JavaScript 探测阅读器版本和操作系统 |
| Collection (TA0009) | **T1560** Archive Collected Data | — | PDF 表单收集用户输入数据 |
| Command and Control (TA0011) | **T1105** Ingress Tool Transfer | — | PDF 通过 JavaScript 下载后续载荷 |
| Exfiltration (TA0010) | **T1567** Exfiltration Over Web Service | **T1567.001** Exfil to Code Repository | PDF 表单数据外传到外部服务器 |
| Exfiltration (TA0010) | **T1041** Exfiltration Over C2 Channel | — | JavaScript 建立信令通道外传数据 |
| Impact (TA0040) | **T1485** Data Destruction | — | 恶意 PDF 利用漏洞导致系统崩溃 |

### ATT&CK Mitigations

| Mitigation | ID | 应用场景 |
|-----------|-----|--------|
| Disable or Remove Feature | **M1042** | 禁用 PDF JavaScript 执行 |
| Execution Prevention | **M1038** | 使用应用白名单阻止异常 PDF 阅读器行为 |
| Network Segmentation | **M1030** | 隔离 PDF 分析环境网络 |
| Behavior Prevention on Endpoint | **M1040** | EDR 检测 PDF 进程异常行为 |
| User Training | **M1017** | 安全意识培训：不打开可疑 PDF |
| Restrict File and Directory Permissions | **M1020** | 限制 PDF 阅读器文件系统访问 |
| Update Software | **M1051** | 保持 PDF 阅读器补丁最新 |

## OWASP Top 10 / CWE 映射

| OWASP 类别 | CWE | ATT&CK | PDF 场景 |
|-----------|------|--------|---------|
| **A01 Broken Access Control** | CWE-862 | T1566.001 | PDF 阅读器权限提升利用 |
| **A03 Injection** | CWE-79 | T1059.007 | PDF JavaScript 注入阅读器上下文 |
| **A04 Insecure Design** | CWE-829 | T1204.001 | 包含不可信来源代码（嵌入第三方 JS） |
| **A05 Security Misconfiguration** | CWE-732 | T1027.010 | PDF 阅读器默认启用 JS 执行 |
| **A06 Vulnerable Components** | CWE-1035 | T1566.001 | PDF 阅读器已知漏洞利用 |
| **A08 Software/Data Integrity** | CWE-502 | T1140 | PDF 流反序列化利用 |
| **A09 Logging/Monitoring** | CWE-778 | T1567.001 | PDF 表单外传数据无审计日志 |
| **A10 SSRF** | CWE-918 | T1059.007 | JavaScript 发起内网请求 |

## 合规框架参考

| 标准 | 条款 | PDF 安全关联 |
|------|------|-------------|
| **ISO 27001** | A.8.7 恶意软件防范 | PDF 作为恶意软件载体，需文件类型控制 |
| **ISO 27001** | A.8.12 数据泄露预防 | PDF 表单数据外传检测 |
| **NIST SP 800-83** | 恶意软件事件预防 | 文档文件类型控制和沙箱分析 |
| **NIST SP 800-53** | SI-3 恶意代码防护 | 邮件网关 PDF 附件扫描 |
| **NIST SP 800-53** | SC-7 边界保护 | 隔离环境处理可疑 PDF |
| **GDPR** | Art. 32 安全处理 | PDF 文档中的 PII 数据保护 |
| **PIPL** | 第40条 跨境传输 | PDF 表单数据跨境外传合规 |
| **PCI DSS** | 5.2 恶意软件防护 | 含支付数据的 PDF 文件扫描 |

## 依赖要求

**Python 版本**: 3.8+

**内置脚本**:
- `pdf_scan.py` - 快速特征提取和威胁评分
- `pdf_extract.py` - 内容提取（文本/图像/嵌入文件/二维码）

**推荐安装**:
```bash
pip install PyMuPDF Pillow pyzbar  # 增强 pdf_extract.py
pip install pdfid pdf-parser       # Didier Stevens 工具
brew install qpdf poppler          # 深度分析工具（pdfinfo, pdftotext）
```

## 快速使用

```bash
# 快速扫描 - 威胁评分
python3 scripts/pdf_scan.py sample.pdf

# JSON 输出（适合管道/自动化）
python3 scripts/pdf_scan.py -j sample.pdf

# 提取全部内容
python3 scripts/pdf_extract.py sample.pdf

# 只提取图像和检测二维码
python3 scripts/pdf_extract.py sample.pdf --images --qr

# 提取嵌入文件
python3 scripts/pdf_extract.py sample.pdf --files

# 提取 JavaScript
python3 scripts/pdf_extract.py sample.pdf --js
```

## 威胁类型矩阵

| 威胁类型 | 攻击方式 | 关键指标 | 检测方法 |
|---------|----------|---------|---------|
| 🔴 漏洞利用型 | 利用 PDF Reader 漏洞 | JavaScript, /JS, /JavaScript, CVE 特征 | pdf_scan.py 特征扫描 |
| 🟠 钓鱼诱导型 | 诱导点击链接/扫码 | URL, /URI, /Launch, 二维码 | pdf_extract.py URL/QR 提取 |
| 🟡 恶意载荷型 | 嵌入可执行文件 | /EmbeddedFile, /EmbeddedF | pdf_extract.py --files |
| 🔵 信息窃取型 | 表单外传数据 | /AcroForm, /SubmitForm, 外部链接 | pdf_scan.py + pdf_extract.py |
| 🟣 躲避检测型 | 混淆/编码隐藏 | /FlateDecode 层叠, 十六进制编码 | pdf_scan.py 异常计数 |

## 分析工作流

### Phase 1: 快速扫描（30秒）
```bash
python3 scripts/pdf_scan.py sample.pdf
```
**输出内容：**
- 文件基本信息（大小、页数、PDF版本、创建者）
- 威胁指标列表（JS/嵌入文件/URL/表单/动作）
- 威胁评分（LOW/MEDIUM/HIGH/CRITICAL）
- 逐项风险评估

### Phase 2: 内容提取（按需）
```bash
python3 scripts/pdf_extract.py sample.pdf --text        # 提取文本
python3 scripts/pdf_extract.py sample.pdf --images --qr  # 提取图像+二维码
python3 scripts/pdf_extract.py sample.pdf --files        # 提取嵌入文件
python3 scripts/pdf_extract.py sample.pdf --js           # 提取 JavaScript
python3 scripts/pdf_extract.py sample.pdf --all          # 全部提取
```

### Phase 3: 深度分析
根据 Phase 1-2 发现，针对性深入：

| 发现 | 深度分析方法 |
|------|------------|
| JavaScript | 混淆解码 → 恶意行为判定 → CVE 匹配 |
| 嵌入文件 | 文件类型识别 → 调用对应分析技能 |
| URL | 提取所有 URL → 调用 `url-analysis` |
| 二维码 | 解码内容 → URL 安全分析 |
| 表单 | 检查提交目标 → 数据外传风险评估 |
| 异常流 | 多层解码 → 隐藏对象提取 |

### Phase 4: 关联分析
将提取到的 IOC 关联到威胁情报：

```
PDF 中提取的 URL
  → url-analysis（URL 安全分析）
  → domain-analysis（域名信誉）
  → ip-analysis（IP 分析）

嵌入的 Office 文件
  → office-malware-analyzer（宏分析）

嵌入的可执行文件
  → binary-reverse-engineering（逆向）
```

### Phase 5: 报告生成
按 `references/report-format.md` 格式生成完整分析报告。

## 高危嵌入文件类型

提取后需进一步分析，按危险程度排序：

| 危险等级 | 文件类型 | 后续处理 |
|---------|---------|---------|
| 🔴 高危 | `.exe`, `.dll`, `.scr` | → binary-reverse-engineering |
| 🔴 高危 | `.js`, `.vbs`, `.hta` | → 代码审计 |
| 🟠 中危 | `.docm`, `.xlsm` | → office-malware-analyzer |
| 🟠 中危 | `.bat`, `.ps1`, `.sh` | → 脚本审计 |
| 🟡 低危 | `.zip`, `.rar`, `.7z` | → 解压后逐项分析 |

## JavaScript 恶意检测要点

### 常见混淆模式
```javascript
// eval 堆叠（高危）
eval(unescape('%66%75%6e%63%74%69%6f%6e...'));

// String.fromCharCode（高危）
var s = String.fromCharCode(104,116,116,112,...);

// 正则执行（中危）
app.setTimeout("/*obfuscated*/", 1000);

// Collab.getIcon 数据隐藏（高危）
// 利用 PDF 注释对象隐藏 Shellcode
```

### CVE 关联特征

| CVE | 特征 | 检测模式 |
|-----|------|---------|
| CVE-2010-0188 | util.printf 栈溢出 | 检测 util.printf + 超长参数 |
| CVE-2013-0640 | U3D 解析漏洞 | 检测 /Type /3D |
| CVE-2018-4990 | JSON JBIG2 漏洞 | 检测 /JBIG2Decode |
| CVE-2021-44711 | 字体解析漏洞 | 检测异常字体对象 |
| CVE-2023-21674 | 内存损坏 | 检测畸形 XFA 结构 |

详见 [references/javascript-cve.md](references/javascript-cve.md)

## Sigma 检测规则

### Sigma 规则 1：恶意 PDF JavaScript 执行检测
```yaml
title: Suspicious PDF Reader JavaScript Execution
description: Detects PDF reader process executing JavaScript or spawning child processes
status: experimental
author: sec-skills
logsource:
    product: windows
    category: process_creation
detection:
    selection_pdf:
        ParentImage|endswith:
            - '\\AcroRd32.exe'
            - '\\Acrobat.exe'
            - '\\FoxitReader.exe'
            - '\\SumatraPDF.exe'
    selection_suspicious:
        Image|endswith:
            - '\\powershell.exe'
            - '\\\\cmd.exe'
            - '\\mshta.exe'
            - '\\wscript.exe'
            - '\\cscript.exe'
    condition: selection_pdf and selection_suspicious
falsepositives:
    - Legitimate PDF with embedded tools (rare)
level: high
tags:
    - attack.execution
    - attack.t1059.007
    - attack.t1204.001
    - attack.t1566.001
```

### Sigma 规则 2：PDF 阅读器异常网络连接检测
```yaml
title: PDF Reader Making Unusual Network Connections
description: Detects PDF reader processes establishing external network connections
status: experimental
author: sec-skills
logsource:
    product: windows
    category: network_connection
detection:
    selection_pdf:
        Image|endswith:
            - '\\AcroRd32.exe'
            - '\\Acrobat.exe'
            - '\\FoxitReader.exe'
    filter legitimate:
        DestinationHostname|endswith:
            - '.adobe.com'
            - '.foxit.com'
    condition: selection_pdf and not filter legitimate
falsepositives:
    - PDF with legitimate cloud sync features
    - PDF digital signature validation (AIA fetching)
level: medium
tags:
    - attack.exfiltration
    - attack.t1567.001
    - attack.command_and_control
    - attack.t1105
```

## YARA 检测规则

```yara
rule PDF_Embedded_Shellcode
{
    meta:
        description = "Detects shellcode patterns embedded in PDF streams"
        author = "sec-skills"
    strings:
        $pdf = "%PDF-"
        $nop_sled = /(\x90){16,}/
        $unicode_shellcode = /(%u[0-9A-Fa-f]{4}){20,}/
        $heap_spray = /(\\x0c\\x0c\\x0c\\x0c){10,}/
    condition:
        $pdf at 0 and ($nop_sled or $unicode_shellcode or $heap_spray)
}

rule PDF_Suspicious_JS_Patterns
{
    meta:
        description = "Detects suspicious JavaScript patterns in PDF"
        author = "sec-skills"
    strings:
        $pdf = "%PDF-"
        $eval = "eval(" nocase
        $unescape = "unescape(" nocase
        $fromcharcode = "String.fromCharCode(" nocase
        $export = "exportDataObject" nocase
        $launch = "app.launchURL" nocase
    condition:
        $pdf at 0 and 2 of ($eval, $unescape, $fromcharcode, $export, $launch)
}
```

## IOC 采集指引

| IOC 类型 | 提取方法 | 示例格式 | 后续处理 |
|---------|---------|---------|--------|
| URL/域名 | `pdf_extract.py --text` + 正则提取 | `http://malicious.com/payload` | → url-analysis / domain-analysis |
| IP 地址 | 文本提取 + 正则 `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b` | `192.168.1.1` | → ip-analysis |
| JavaScript Hash | `pdf_scan.py -j` → SHA256 of JS content | `a1b2c3...` | → 威胁情报比对 |
| 嵌入文件 Hash | `pdf_extract.py --files` → SHA256 | `d4e5f6...` | → VT 查询 / 逆向分析 |
| C2 User-Agent | JS 分析中提取 HTTP UA 字符串 | `Mozilla/5.0...` | → NIDS 规则 |
| PDF 对象 Hash | 对可疑对象内容计算 MD5 | `e5f6a7...` | → 恶意特征库比对 |
| 嵌入邮箱 | 文本提取 + 正则 `[\w.]+@[\w.]+` | `spam@mal.com` | → email-osint |
| 二维码 URL | `pdf_extract.py --qr` 解码 | `http://qr-malicious.com` | → url-analysis |

## 跨技能工作流

### 工作流 1：钓鱼邮件 PDF 附件分析
```
phishing-analysis → mail-attachment-downloader → pdf-analysis
  → 提取 URL → url-analysis → domain-analysis → ip-analysis
  → 提取嵌入文件 → office-malware-analyzer / binary-reverse-engineering
  → 提取 IOC → ttp-extractor
  → 生成报告 → pdf-report → data-desensitize
```

### 工作流 2：PDF 漏洞利用分析
```
pdf-analysis (检测到 JS + CVE 特征)
  → CVE 匹配 → researching-vulnerabilities
  → Shellcode 提取 → binary-reverse-engineering
  → C2 地址 → ip-analysis / domain-analysis
  → 技术映射 → ttp-extractor
  → 告警规则 → Sigma 规则部署到 SIEM
```

### 工作流 3：企业 PDF 文档安全审计
```
asset-discovery → 发现 PDF 文档资产
  → pdf-analysis (批量扫描)
  → 敏感数据检测 → data-desensitize
  → 嵌入内容提取 → code-audit (JS 安全审计)
  → 生成报告 → pdf-report
```

## 与其他技能的协同

### 上游（调用 pdf-analysis 的技能）
- **phishing-analysis** — 钓鱼邮件中的 PDF 附件分析
- **mail-attachment-downloader** — 下载邮件附件后传递给 PDF 分析
- **asset-discovery** — 资产发现中的 PDF 文档安全检查
- **email-osint** — 邮箱情报中发现的 PDF 附件

### 下游（pdf-analysis 调用的技能）
- **url-analysis** — 分析 PDF 中的 URL
- **domain-analysis** — 分析 PDF 中的域名
- **ip-analysis** — 分析 PDF 中的 IP 地址
- **office-malware-analyzer** — 分析嵌入的 Office 文件
- **binary-reverse-engineering** — 分析嵌入的可执行文件 / Shellcode
- **ttp-extractor** — 从 PDF 攻击中提取 TTP
- **pdf-report** — 生成 PDF 格式的分析报告
- **data-desensitize** — 报告分享前脱敏
- **researching-vulnerabilities** — CVE 关联查询

```
[phishing-analysis / mail-attachment-downloader / asset-discovery / email-osint]
    ↓ PDF 文件
[pdf-analysis]
    ↓ URL/域名/IP    → [url-analysis / domain-analysis / ip-analysis]
    ↓ 嵌入文件       → [office-malware-analyzer / binary-reverse-engineering]
    ↓ CVE 关联       → [researching-vulnerabilities]
    ↓ 技术/程序      → [ttp-extractor]
    ↓ 报告           → [pdf-report → data-desensitize]
```

## 工具速查

| 任务 | 命令 | 耗时 |
|------|------|------|
| 快速扫描 | `python3 pdf_scan.py sample.pdf` | ~1s |
| JSON 输出 | `python3 pdf_scan.py -j sample.pdf` | ~1s |
| 提取全部 | `python3 pdf_extract.py sample.pdf` | ~5s |
| 提取嵌入文件 | `python3 pdf_extract.py sample.pdf --files` | ~3s |
| 提取图像 | `python3 pdf_extract.py sample.pdf --images` | ~3s |
| 检测二维码 | `python3 pdf_extract.py sample.pdf --images --qr` | ~5s |
| 文件信息 | `pdfinfo sample.pdf` | <1s |
| 对象统计 | `pdfid.py sample.pdf` | <1s |
| 对象解析 | `pdf-parser.py -o N sample.pdf` | ~2s |
| JavaScript | `pdf-parser.py -s javascript sample.pdf` | ~2s |
| 流解码 | `pdf-parser.py -f sample.pdf` | ~2s |

## 处置指南

| 威胁等级 | 建议处置 |
|---------|---------|
| CRITICAL | 立即隔离，禁止打开，提取 IOC 上报 |
| HIGH | 在沙箱中分析，提取载荷，关联情报 |
| MEDIUM | 深度检查特定指标，验证可疑项 |
| LOW | 记录扫描结果，标记为已检查 |

详见 [references/handling-guide.md](references/handling-guide.md)

## 参考文件

- **[references/report-format.md](references/report-format.md)** — 📋 报告格式规范（必读）
- [references/structure-analysis.md](references/structure-analysis.md) — PDF 结构分析
- [references/javascript-cve.md](references/javascript-cve.md) — JavaScript 与 CVE
- [references/phishing-detection.md](references/phishing-detection.md) — 钓鱼检测
- [references/handling-guide.md](references/handling-guide.md) — 处置指南
- [references/malware-signatures.md](references/malware-signatures.md) — 恶意特征库
