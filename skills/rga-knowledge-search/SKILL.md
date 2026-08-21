---
name: rga-knowledge-search
description: 在本地知识库中搜索文档内容，从 rga 缓存读取已提取的文本。支持 PDF、Office 文档、电子书、压缩包等格式。当用户询问内部文档、历史报告、本地资料时使用。触发词包括"知识库"、"本地文档"、"<KNOWLEDGE></KNOWLEDGE>"、"之前的报告"，或类似"安全报告里说了什么"的问题。
metadata:
  version: 1.3.0
  builtin: true
---

# RGA 本地知识库搜索

## 关于 RGA

**rga (ripgrep-all)** 是 ripgrep 的扩展，支持在多种文件格式中进行正则搜索：

- **PDF**: 通过 poppler (pdftotext) 提取文本
- **Office 文档**: DOCX/XLSX/PPTX 通过 pandoc 转换
- **电子书**: EPUB 通过 pandoc 转换
- **压缩包**: ZIP/TAR/GZ 自动递归解压搜索
- **图片**: JPG/PNG 通过 tesseract OCR（需安装）
- **数据库**: SQLite 直接查询

**缓存机制**: rga 首次搜索时提取文本并缓存到 SQLite，后续搜索直接使用缓存，速度接近纯文本搜索。

## 知识库路径

从上下文 `<KNOWLEDGE>` 标签获取路径，默认: `~/Documents`

## 工作流

```
rga 搜索 → 定位文件 → cache_reader 读缓存 → 分析回答
                              ↓ (无缓存时)
                        doc_viewer 兜底读取
```

### 第一步：搜索

```bash
rga -l "关键词" <知识库路径>           # 列出匹配文件
rga -C 3 "关键词" <知识库路径>          # 带上下文
rga -t pdf "关键词" <知识库路径>        # 按类型过滤
```

### 第二步：读取内容

**优先：从缓存读取**（毫秒级，与搜索结果一致）

```bash
python scripts/cache_reader.py /path/to/document.pdf
python scripts/cache_reader.py /path/to/document.pdf --head 50
```

**兜底：直接解析文件**（缓存不存在时）

```bash
python scripts/doc_viewer.py /path/to/document.pdf
python scripts/doc_viewer.py /path/to/document.docx
python scripts/doc_viewer.py /path/to/archive.zip --target readme.txt
```

### 第三步：分析与引用

整理内容并回答用户问题。**必须标注知识来源**以避免幻觉：

```
根据 [文件名](路径:行号) 的记录，...

来源：
- 文件路径:行号 - 关键信息摘要
```

**引用规范**：
- 每个事实性陈述必须关联到具体文档
- 使用 `文件名:行号` 格式便于溯源
- 无法从文档确认的信息需明确标注"文档未提及"
- 禁止编造文档中不存在的内容

正式报告格式见 [references/report-format.md](references/report-format.md)。

---

## 安全情报搜索映射

知识库搜索在安全分析中扮演关键角色——本地存储的威胁情报报告、漏洞分析、IR 报告和合规文档都是重要的参考来源。以下是按安全场景组织的搜索模式。

### MITRE ATT&CK 搜索映射

搜索本地威胁情报时，按 ATT&CK 战术和技术 ID 进行精确检索：

| ATT&CK 战术 | 搜索关键词示例 | 典型文档类型 |
|-------------|--------------|-------------|
| TA0001 Initial Access | `T1566` `T1078` `鱼叉式钓鱼` `有效凭据` | 威胁报告, IR 报告 |
| TA0002 Execution | `T1059` `T1053` `计划任务` `PowerShell` | 恶意软件分析 |
| TA0004 Privilege Escalation | `T1068` `T1548` `令牌窃取` `UAC绕过` | 渗透测试报告 |
| TA0006 Credential Access | `T1110` `T1056` `Mimikatz` `凭据转储` | IR 报告, 取证报告 |
| TA0007 Discovery | `T1046` `T1087` `网络扫描` `账户发现` | 红队报告 |
| TA0008 Lateral Movement | `T1021` `T1570` `PsExec` `WMI` | IR 报告 |
| TA0010 Exfiltration | `T1041` `T1567` `数据外传` `C2信道` | 取证报告 |
| TA0040 Impact | `T1486` `T1490` `勒索软件` `数据销毁` | 勒索软件分析 |

**搜索策略**：
```bash
# 按 ATT&CK 技术 ID 精确搜索
rga "T1566\.[0-9]+" <知识库路径>

# 按战术名称模糊搜索
rga -i "lateral.movement\|横向移动" <知识库路径>

# 同时搜索多个技术 ID
rga "T1059\|T1078\|T1110" <知识库路径>
```

### OWASP 安全搜索映射

搜索应用安全相关文档时的关键词映射：

| OWASP 类别 | 搜索关键词 | 典型场景 |
|-----------|----------|---------|
| A01 Broken Access Control | `越权` `IDOR` `垂直权限` `水平权限` | 代码审计报告 |
| A02 Cryptographic Failures | `弱加密` `硬编码密钥` `MD5` `DES` | 安全评估报告 |
| A03 Injection | `SQL注入` `XSS` `命令注入` `CRLF` | 渗透测试报告 |
| A04 Insecure Design | `缺失校验` `无速率限制` `批量赋值` | 架构评审 |
| A05 Security Misconfiguration | `默认配置` `调试模式` `目录遍历` | 基线核查 |
| A06 Vulnerable Components | `CVE-202` `已知漏洞` `过时版本` | SCA 报告 |
| A07 Auth Failures | `弱密码` `会话固定` `无MFA` | 安全评估 |
| A08 Software/Data Integrity | `未签名更新` `反序列化` `不完整校验` | 代码审计 |
| A09 Logging Failures | `缺失审计日志` `日志注入` `无监控` | 合规检查 |
| A10 SSRF | `SSRF` `内网请求` `URL校验` | 渗透测试 |

### CVE 与漏洞搜索

```bash
# 按 CVE 编号精确搜索
rga "CVE-202[0-9]-[0-9]+" <知识库路径>

# 按漏洞类型搜索
rga -i "RCE\|远程代码执行\|命令执行" <知识库路径>
rga -i "SQL.injection\|注入漏洞" <知识库路径>

# 按 CVSS 严重度搜索
rga "CVSS.*[34]\.\|严重\|critical\|high" <知识库路径>
```

### IOC 与威胁狩猎搜索

```bash
# IP 地址模式搜索
rga "\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b" <知识库路径>

# 域名 / Hash 搜索
rga "[a-f0-9]{32,64}" <知识库路径>  # MD5/SHA256
rga "\[domain\]\|C2.*server\|恶意域名" <知识库路径>

# Sigma 规则参考
rga "sigma\|detection.*selection\|logsource" <知识库路径>
```

---

## 跨技能生态工作流

知识库搜索不是孤岛——它为多个安全技能提供情报支撑：

### 作为上游（feeds_into）

| 下游技能 | 提供内容 | 集成方式 |
|---------|---------|---------|
| **ttp-extractor** | 从报告中提取 ATT&CK 技术描述 | 搜索报告全文 → 提取 T-ID → 生成映射 |
| **pdf-report** | 历史报告模板、格式参考、上下文引用 | 搜索相似案例 → 引用历史发现 |
| **researching-vulnerabilities** | 本地漏洞数据库、CVE 详情 | 搜索 CVE 编号 → 提取影响范围和修复建议 |

### 作为下游（depends_on）

| 上游技能 | 使用场景 |
|---------|---------|
| **researching-vulnerabilities** | 漏洞研究产出存入知识库，后续可搜索 |
| **redteam-recon-nation** | APT 分析报告归档后，通过知识库检索 |

### 典型联合工作流

```
事件响应场景:
  auth-log-analysis 检测异常 → rga-knowledge-search 搜索历史相似事件 → ttp-extractor 提取 TTP → pdf-report 生成报告

漏洞管理场景:
  researching-vulnerabilities 发现新 CVE → 归档到知识库 → rga-knowledge-search 后续检索 → code-audit 关联代码审计

红队评估场景:
  redteam-recon-nation 产出情报 → 归档 → rga-knowledge-search 搜索历史评估 → pdf-report 生成对比报告
```

---

## 搜索优化技巧

### 性能优化

```bash
# 先更新缓存（首次或文件变更后）
rga --rg-ignore --no-messages "warmup" <知识库路径> 2>/dev/null

# 限制搜索文件类型提高速度
rga -t pdf -t docx "关键词" <知识库路径>

# 排除大型文件
rga --max-filesize 10M "关键词" <知识库路径>
```

### 精确搜索

```bash
# 全词匹配（避免子串匹配）
rga "\bAPT28\b" <知识库路径>

# 短语搜索
rga "lateral movement" <知识库路径>

# 排除噪声
rga "T1059" --glob "!*.log" <知识库路径>
```

### 结果导航

```bash
# 只看文件名（快速定位）
rga -l "关键词" <知识库路径> | head -20

# 带上下文（理解语境）
rga -C 5 "关键词" <知识库路径>

# JSON 输出（程序化处理）
rga --json "关键词" <知识库路径> | jq '.[].data.matches.text'
```

---

## 命令速查

### 搜索

| 场景 | 命令 |
|------|------|
| 列出文件 | `rga -l "关键词" <路径>` |
| 带上下文 | `rga -C 3 "关键词" <路径>` |
| 仅 PDF | `rga -t pdf "关键词" <路径>` |
| 忽略大小写 | `rga -i "关键词" <路径>` |
| 正则搜索 | `rga "pattern.*" <路径>` |

### 读取（优先 cache_reader）

| 操作 | 命令 |
|------|------|
| 读取内容 | `python scripts/cache_reader.py file.pdf` |
| 取消限制 | `python scripts/cache_reader.py file.pdf --no-limit` |
| 文件信息 | `python scripts/cache_reader.py --info file.pdf` |
| 列出缓存 | `python scripts/cache_reader.py --list` |

**滑动分页**（长文档导航）:

| 操作 | 命令 |
|------|------|
| 按页读取 | `python scripts/cache_reader.py file.pdf --page 1` |
| 定位关键词 | `python scripts/cache_reader.py file.pdf --around "keyword"` |
| 第 N 处匹配 | `python scripts/cache_reader.py file.pdf --around "keyword" --occur 3` |
| 从偏移读取 | `python scripts/cache_reader.py file.pdf --offset 50000` |
| 从行号读取 | `python scripts/cache_reader.py file.pdf --line 100` |
| 缩进模式 | `python scripts/cache_reader.py file.py --indent 100` |

### 读取（兜底 doc_viewer）

| 格式 | 命令 |
|------|------|
| PDF | `python scripts/doc_viewer.py file.pdf` |
| Word | `python scripts/doc_viewer.py file.docx` |
| Excel | `python scripts/doc_viewer.py file.xlsx` |
| 压缩包 | `python scripts/doc_viewer.py file.zip` |
| 取消限制 | `python scripts/doc_viewer.py file.pdf --no-limit` |

## 缓存位置

| 系统 | 路径 |
|------|------|
| Linux | `~/.cache/ripgrep-all/cache.sqlite3` |
| macOS | `~/Library/Caches/ripgrep-all/cache.sqlite3` |
| Windows | `%LOCALAPPDATA%/ripgrep-all/cache/cache.sqlite3` |

## 依赖

**系统**: `ripgrep-all`, `poppler`, `pandoc`

**Python (cache_reader)**: `pip install zstandard`

**Python (doc_viewer)**: `pip install pdfplumber python-docx openpyxl python-pptx ebooklib`

---

## 合规与标准参考

知识库搜索在合规审计中的典型应用：

| 标准 | 搜索场景 | 关键词示例 |
|------|---------|----------|
| GDPR | 数据保护影响评估报告 | `DPIA` `个人数据` `数据主体` |
| PIPL | 个人信息处理活动记录 | `个人信息` `敏感信息` `数据处理者` |
| ISO 27001 | 风险评估报告、SoA | `SoA` `风险评估` `控制措施` ` Annex A` |
| PCI DSS | 合规扫描报告 | `PCI` `持卡人数据` `SEG` `ASV扫描` |
| NIST CSF | 安全事件报告 | `Identify` `Protect` `Detect` `Respond` `Recover` |

## 使用示例

### 示例 1：搜索历史 IR 报告中的 ATT&CK 技术

```bash
# 用户问：之前报告里有没有涉及横向移动的分析？
rga -l "T1021\|T1570\|lateral.movement\|横向移动" ~/Documents

# 定位到具体报告后，读取相关章节
python scripts/cache_reader.py ~/Documents/IR-2025-06.pdf --around "横向移动"
```

### 示例 2：搜索特定 CVE 的漏洞分析

```bash
# 用户问：知识库里有没有 CVE-2025-1234 的分析？
rga "CVE-2025-1234" ~/Documents

# 找到分析报告后，读取完整内容
python scripts/cache_reader.py ~/Documents/vuln-analysis.pdf --no-limit
```

### 示例 3：合规审计报告检索

```bash
# 用户问：最近的安全评估报告覆盖了哪些 OWASP 类别？
rga -i "A0[1-9]\|A10\|OWASP" ~/Documents --type pdf

# 汇总后输出覆盖矩阵
```
