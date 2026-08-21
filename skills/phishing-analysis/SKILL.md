---
name: phishing-analysis
description: 对可疑邮件进行全面钓鱼威胁分析，包括邮件头验证、规避技术检测、IOC 提取、二维码/附件分析和组织归因。当用户要求分析邮件、检测社会工程攻击、检查邮件安全性或进行威胁狩猎时使用此技能。
metadata:
  version: 2.1.0
  builtin: true
---

# 钓鱼邮件分析技能

## 🔴 强制执行要求（必读）

> **分析邮件前必须执行以下步骤，缺一不可！**

### 步骤 1：执行 analyze_email.py（必需）

```bash
python scripts/analyze_email.py suspicious.eml --save-attachments -o result.json
```

> **🔴 必须使用 `--save-attachments`！** 该参数会自动保存附件到磁盘、用正文中检测到的密码解压加密压缩包、对提取出的文件生成 `recommended_skills`（含磁盘路径）。不加此参数 = 不分析附件内容。

**为什么必须执行**：

- 自动提取邮件头、正文、附件、URL、IOC
- 检测规避技术（零字体、追踪ID）
- **自动保存附件到磁盘并解压压缩包**（含加密压缩包自动破解）
- **提取压缩包内文件并生成完整的下游分析推荐**
- 输出 `recommended_skills` 指导后续分析（含 `saved_path` 文件路径）

**错误示例**（不要这样做）：

```
❌ 直接用 cat/Read 读取 .eml 文件然后人工分析 — 必须用脚本
❌ 跳过脚本直接输出结论
❌ 不加 --save-attachments（= 不分析附件内容）
❌ 自己用 PowerShell/shell/Python 手动解码 base64、解压 ZIP — 必须用脚本
❌ 用 System.IO.Compression 或 Expand-Archive 解压（不支持密码保护 ZIP，会报错）
❌ ZIP 解压失败就说"文件损坏" — 可能是工具不支持加密格式，换用脚本
❌ 发现加密压缩包但不解压，仅凭元数据/哈希就下结论
❌ 说"建议不要解压附件" — 你是安全分析师，必须在安全环境中提取并分析
```

> **🔴 关于附件提取的绝对规则**：`analyze_email.py --save-attachments` 会自动处理 base64 解码、附件保存、密码检测、加密 ZIP 解压的完整流程。**禁止自己手动实现任何这些步骤**。脚本使用专门的加密 ZIP 库（pyzipper/zipfile），能正确处理密码保护的压缩包。PowerShell 的 .NET ZIP 库不支持密码保护 ZIP，会导致误报"文件损坏"。

### 步骤 2：按 recommended_skills 调用技能（必需）

`analyze_email.py` 输出的 `recommended_skills` 必须全部执行：

```json
{
  "recommended_skills": [
    {
      "skill": "domain-analysis",
      "priority": "high",
      "targets": ["example.com"]
    },
    { "skill": "url-analysis", "priority": "high", "targets": ["https://..."] },
    { "skill": "ip-analysis", "priority": "medium", "targets": ["1.2.3.4"] }
  ]
}
```

**执行要求**：

- `priority: high` → **必须执行**
- `priority: medium` → 建议执行
- 不得忽略任何 high 优先级的推荐

### 步骤 3：调用 domain-analysis 获取域名年龄（必需）

> ⚠️ **域名年龄是钓鱼判定的核心指标！**

```bash
python /path/to/domain-analysis/scripts/domain_analyze.py <发件人域名>
```

**为什么必须执行**：

- 域名年龄 < 30 天 = 高风险钓鱼指标
- WHOIS 信息揭示注册商、隐私保护等特征
- 即使 SPF/DKIM 通过，新域名仍然高度可疑

**域名年龄风险评分**：
| 域名年龄 | 风险分数 | 说明 |
|---------|---------|------|
| < 7 天 | +30 | 🔴 极高风险 |
| < 30 天 | +20 | 🔴 高风险 |
| < 90 天 | +10 | 🟡 中风险 |
| > 90 天 | +0 | 🟢 相对可信 |

### 步骤 4：执行 Phase 2 评分（必需）

必须按照下方 **35 项评分标准** 逐项检查，不得跳过！

---

## 分析工作流概览

| Phase | 名称               | 必需    | 说明                       |
| ----- | ------------------ | ------- | -------------------------- |
| 1     | **信息提取+附件保存** | ✅ 必需 | `analyze_email.py --save-attachments` |
| 1.5   | **调用推荐技能**   | ✅ 必需 | 按 recommended_skills 执行 |
| 2     | **风险评分**       | ✅ 必需 | 35 项标准逐项检查          |
| 3     | **发件人域名分析** | ✅ 必需 | 调用 domain-analysis       |
| 4     | **附件内容分析**   | ✅ 必需 | 有附件时必须提取并分析内容 |
| 5     | 组织归因           | 条件    | 风险 ≥50 时执行            |
| 6     | **报告生成**       | ✅ 必需 | 12 章完整报告              |

> **🔴 关键**：Phase 1、1.5、2、3、4（有附件时）、6 为必需步骤，不得跳过！

---

## 依赖要求

**Python 版本**: 3.8+

**核心依赖**: 无（仅使用标准库）

**可选库**:
| 库 | 安装 | 用途 |
|----|------|------|
| pyzbar/qreader | `pip install pyzbar` | 二维码解析 |
| pyzipper/py7zr | `pip install pyzipper py7zr` | 加密压缩包 |

## ⚠️ 分析注意事项

1. **样本代表性判断**

   - 用户提供的可能只是一封邮件，谨慎判断是否为定向攻击（鱼叉式钓鱼）
   - 询问用户：是否有多人收到？是否针对特定部门/职位？
   - 单一样本难以判断攻击规模和意图

2. **定向 vs 批量钓鱼**
   | 特征 | 定向钓鱼 (Spearphishing) | 批量钓鱼 |
   |------|--------------------------|----------|
   | 收件人 | 特定个人/小群体 | 大量随机 |
   | 内容 | 高度定制、含个人信息 | 通用模板 |
   | 发件人 | 伪装熟人/合作伙伴 | 伪装知名品牌 |
   | 威胁等级 | 通常更高 | 中等 |
   | 归因难度 | 较高（APT可能性） | 较低（黑产为主） |

3. **信息完整性**

   - 确认邮件头是否完整（转发可能丢失原始头部）
   - 附件是否已被安全网关处理/删除
   - 链接是否已被重写（如 Safelinks）

4. **上下文很重要**
   - 收件人的职位和权限级别
   - 组织近期是否有相关业务（如财税申报期）
   - 是否为已知的红队演练

## 快速使用

> **注意**：脚本现在支持在任何目录执行，无需切换到技能目录。推荐使用绝对路径。

```bash
# 方式 1: 使用绝对路径（推荐）
python /path/to/skills/phishing-analysis/scripts/analyze_email.py suspicious.eml --save-attachments

# 方式 2: 在技能目录内使用相对路径
cd /path/to/skills/phishing-analysis
python scripts/analyze_email.py suspicious.eml --save-attachments

# 规避技术检测
python scripts/evasion_detector.py suspicious.eml

# 提取 IOC
python scripts/extract_iocs.py email.eml --format json --defang
```

## 分析工作流

### Phase 1: 信息提取 + 附件保存

```bash
python scripts/analyze_email.py suspicious.eml --save-attachments -o result.json
```

输出：邮件头、正文、附件列表（含磁盘路径）、URL、IOC、规避技术检测结果、压缩包解压结果

> **🔴 必须加 `--save-attachments`**，否则附件不会保存到磁盘，后续无法分析附件内容。

### Phase 2: 风险评分（人工判断）

根据提取结果，按以下标准计分：

| 检测项              | 分值 | 检查方法                      |
| ------------------- | ---- | ----------------------------- |
| 伪装政府/金融机构   | +35  | 检查主题/发件人/正文          |
| **域名年龄 < 7天**  | +30  | whois 查询                    |
| 二维码钓鱼          | +30  | `qr_analyzer.py` 检测         |
| 零字体/隐藏元素     | +25  | evasion_techniques.techniques |
| 恶意附件            | +25  | 附件扩展名 + 后续分析         |
| **动态DNS服务**     | +25  | 检查域名后缀                  |
| 滥用合法服务        | +20  | 发件人域名检查                |
| 钓鱼URL             | +20  | `url_analyzer.py` 检测        |
| **域名年龄 7-30天** | +20  | whois 查询                    |
| **品牌仿冒/同形字** | +20  | `homograph_detector.py`       |
| Message-ID不匹配    | +15  | from_domain vs Message-ID域名 |
| **SPF/DMARC 宽松**  | +15  | DNS 记录检查                  |
| **无ICP备案(.cn)**  | +15  | `cybersec_cloud_mcp_intel_icp_lookup`            |
| 正文极短            | +15  | text_length < 50              |
| 含追踪ID            | +10  | evasion_techniques.tracking   |
| 紧迫性用语          | +10  | 正文关键词匹配                |

### Phase 3: 发件人域名深度分析

**核心原则**：发件人域名的安全配置和年龄是判断钓鱼邮件的关键指标。

#### 3.1 DNS 安全配置检测

```bash
# SPF 记录检查
dig TXT example.com | grep "v=spf1"

# DMARC 记录检查
dig TXT _dmarc.example.com

# DKIM selector 探测（常见 selector）
dig TXT default._domainkey.example.com
dig TXT selector1._domainkey.example.com
dig TXT google._domainkey.example.com
```

| 配置项    | 安全配置        | 风险配置             | 评分 |
| --------- | --------------- | -------------------- | ---- |
| **SPF**   | `-all` (硬失败) | `~all` / `+all` / 无 | +15  |
| **DMARC** | `p=reject`      | `p=none` / 无        | +15  |
| **DKIM**  | 有效签名        | 无签名               | +10  |

> ⚠️ **重要**：邮件头中的 SPF/DKIM/DMARC 验证结果 ≠ 发件人域名的实际配置。
> 钓鱼者可能使用自己配置完善的域名发送邮件，验证会通过但仍是恶意的。

#### 3.2 域名年龄分析

```bash
whois example.com | grep -i "creation\|created"
```

| 域名年龄 | 风险等级 | 评分 |
| -------- | -------- | ---- |
| < 7 天   | 🔴 极高  | +30  |
| 7-30 天  | 🔴 高    | +20  |
| 30-90 天 | 🟡 中    | +10  |
| > 90 天  | 🟢 低    | +0   |

> 新注册域名 + 伪装知名品牌 = 高置信度钓鱼

#### 3.3 动态 DNS 服务检测

**高风险动态 DNS 域名**（C2/钓鱼常用）：

| 服务        | 风险    | 常见滥用          |
| ----------- | ------- | ----------------- |
| duckdns.org | 🔴 极高 | AsyncRAT, RemCos  |
| ydns.eu     | 🔴 高   | Xworm, AgentTesla |
| linkpc.net  | 🔴 高   | NjRAT             |
| ddns.net    | 🔴 高   | 多种 RAT          |
| no-ip.org   | 🔴 高   | 僵尸网络          |
| hopto.org   | 🟡 中   | RAT               |

检测规则：发件人域名或邮件中 URL 使用动态 DNS 服务 → **+25 分**

#### 3.4 ICP 备案查询（中国域名）

```
MCP 调用: cybersec_cloud_mcp_intel_icp_lookup
参数: 注册域名（非子域名）
```

**提取注册域名规则**：

- `mail.example.com` → 查询 `example.com`
- `sub.example.com.cn` → 查询 `example.com.cn`

| 备案状态    | 评估                   |
| ----------- | ---------------------- |
| ✅ 企业备案 | 可信度较高（但不绝对） |
| ✅ 个人备案 | 需关注是否仿冒         |
| ❌ 无备案   | 风险较高 +15           |

#### 3.5 品牌仿冒检测

使用 `homograph_detector.py` 检测：

```bash
python scripts/homograph_detector.py "发件人域名" --brand-check
```

检测维度：

- **同形字攻击**：`аpple.com` (西里尔字母 а)
- **打字错误**：`micros0ft.com`, `paypa1.com`
- **子域名滥用**：`microsoft.com.attacker.xyz`
- **添加后缀**：`apple-support.com`

### Phase 4: 附件内容分析（有附件时必需）

> **🔴 有附件就必须分析附件内容！不分析附件内容就无法判断邮件是否有害。**
>
> 附件分析 = 提取附件到磁盘 + 解压压缩包 + 分析内部文件。仅看文件名/哈希/元数据 ≠ 附件分析。
>
> **禁止说"建议不要解压附件"** — 你是安全分析师，必须在分析环境中提取并检查附件内容。

如果 Phase 1 已使用 `--save-attachments`，附件已自动保存和解压。检查输出中的 `extracted_files` 和 `recommended_skills`，按类型继续分析：

```
附件已提取到磁盘（Phase 1 自动完成）
├─ 图片 → python scripts/qr_analyzer.py <saved_path>
├─ 压缩包内文件 → 检查 extracted_files[] 中的每个文件
│   ├─ .eml → 递归: python scripts/analyze_email.py <path> --save-attachments
│   ├─ .exe/.dll/.scr/.bat/.js/.vbs/.hta → 调用 binary-reverse-engineering
│   ├─ .doc/.docx/.docm/.xls/.xlsx/.xlsm → 调用 office-malware-analyzer
│   ├─ .pdf → 调用 pdf-analysis
│   └─ .zip/.rar/.7z → 递归解压: python scripts/archive_analyzer.py <path> -p <pwd> -d <dir>
├─ Office → 调用 office-malware-analyzer 技能
├─ PDF → 调用 pdf-analysis 技能
├─ 可执行 → 调用 binary-reverse-engineering 技能

发现 URL？
├─ python scripts/url_analyzer.py "URL"
├─ python scripts/homograph_detector.py "domain"
├─ 调用 url-analysis / domain-analysis 技能
```

#### 加密压缩包处理

Phase 1 的 `--save-attachments` 已自动完成以下流程：
1. 检测正文中的密码（`passwords_in_body`）
2. 用检测到的密码尝试解压加密压缩包
3. 对提取出的文件计算哈希、检测类型
4. 在 `recommended_skills` 中生成下游分析推荐（含 `saved_path`）

**如果自动解压失败**（密码不匹配、格式不支持等），手动解压：

```bash
python scripts/archive_analyzer.py file.zip --password "密码" --extract-dir ./output
```

#### 解压后文件分析路径

| 解压出的文件类型 | 下一步操作 | 推荐 skill |
|-----------------|-----------|------------|
| `.eml` | 递归调用 `analyze_email.py --save-attachments` | `phishing-analysis` |
| `.doc/.docx/.docm/.xls/.xlsx/.xlsm` | 宏分析 | `office-malware-analyzer` |
| `.pdf` | PDF 结构分析 | `pdf-analysis` |
| `.exe/.dll/.scr/.bat/.ps1/.vbs/.js/.hta` | 逆向分析 | `binary-reverse-engineering` |
| `.zip/.rar/.7z` | 递归解压 | `phishing-analysis` |

> `recommended_skills` 中的 `saved_path` 字段直接指向磁盘文件路径，可作为下游 skill 的输入参数。

### Phase 5: 组织归因

根据 `threat-actor-attribution.md` 匹配特征：

1. 诱饵主题 → 财税(银狐) / 招聘(Lazarus) / IT工具(FIN7)
2. 载荷格式 → CHM/MSI(银狐) / 漏洞文档(Lazarus)
3. 投递渠道 → 微信(银狐) / LinkedIn(Lazarus) / SEO(FIN7)
4. 技术手段 → 白加黑/RAT家族/C2特征

### Phase 6: 报告生成

按 `report-format.md` 输出12章报告：

```
1.标题+评级 → 2.基本信息 → 3.高风险指标 → 4.邮件头
    ↓
5.正文分析 → 6.发件人域名分析 → 7.载荷分析 → 8.IOC
    ↓
9.ATT&CK → 10.攻击链 → 11.组织归因 → 12.结论
```

**新增：发件人域名分析章节**

- DNS 安全配置评估
- 域名年龄和备案信息
- 品牌仿冒检测结果

## 脚本列表

| 脚本                    | 用途                           |
| ----------------------- | ------------------------------ |
| `analyze_email.py`      | 综合邮件分析                   |
| `parse_headers.py`      | 邮件头解析                     |
| `evasion_detector.py`   | 规避技术检测（零字体、追踪ID） |
| `extract_iocs.py`       | IOC 提取                       |
| `url_analyzer.py`       | URL 分析                       |
| `homograph_detector.py` | IDN 同形字攻击检测             |
| `qr_analyzer.py`        | 二维码钓鱼检测                 |
| `archive_analyzer.py`   | 压缩包分析                     |

## 关联技能调用

完成邮件分析后，根据发现的 IOC 调用对应技能：

| 发现的 IOC                    | 调用技能                     | 优先级 |
| ----------------------------- | ---------------------------- | ------ |
| 可执行附件 (.exe/.dll/.scr)   | `binary-reverse-engineering` | P0     |
| Office 附件 (.doc/.docm/.xls) | `office-malware-analyzer`    | P0     |
| PDF 附件                      | `pdf-analysis`               | P1     |
| URL                           | `url-analysis`               | P1     |
| **邮箱中转站链接 (163/QQ)**   | `mail-attachment-downloader` | P1     |
| 可疑域名                      | `domain-analysis`            | P2     |
| 外部 IP                       | `ip-analysis`                | P2     |
| 中国域名 (.cn)                | MCP: ICP 备案查询            | P2     |

**执行流程：**

```
邮件分析完成 → 检查附件 → 调用对应技能 → 检查 URL → 调用 url-analysis → 输出综合报告
                            ↓
              邮箱中转站链接 → mail-attachment-downloader → 下载后分析
```

## 快速命令

```bash
# 解析邮件头
python scripts/parse_headers.py < email.eml

# 分析 URL
python scripts/url_analyzer.py "https://suspicious-link.com"

# 检测同形字攻击
python scripts/homograph_detector.py "suspicious-domain.com"

# 分析二维码
python scripts/qr_analyzer.py qrcode.png
python scripts/qr_analyzer.py email.eml

# 分析压缩包
python scripts/archive_analyzer.py suspicious.zip

# 解压加密压缩包
python scripts/archive_analyzer.py encrypted.zip -p "password" -d ./extracted

# 检测邮件正文中的密码
python scripts/archive_analyzer.py dummy --check-password "密码是123456"

# 完整链路：邮件分析 + 自动保存附件 + 解压 + 推荐
python scripts/analyze_email.py suspicious.eml --save-attachments

# 指定附件保存目录
python scripts/analyze_email.py suspicious.eml --output-dir ./attachments
```

## 红队邮件识别

红队钓鱼模拟通常具有：

- 追踪像素或唯一标识符
- 指向内部钓鱼平台的链接（KnowBe4, Cofense, GoPhish）
- URL中的特定活动标签

区分方法：

- 检查链接基础设施的域名归属
- 确认是否为已知安全意识培训平台

## 最佳实践

1. **绝不点击链接或打开附件** - 在可疑钓鱼邮件中
2. **使用沙箱环境** - 进行动态分析
3. **记录 URL 和 IP** - 用于威胁情报共享
4. **验证Punycode** - 对任何国际化域名进行解码检查

## 报告输出规范

分析完成后 **必须** 按照 `references/report-format.md` 格式输出报告。

### 威胁评级

| 等级     | 分数  | 标记 |
| -------- | ----- | ---- |
| Critical | ≥80   | 🔴   |
| High     | 50-79 | 🟠   |
| Medium   | 30-49 | 🟡   |
| Low      | <30   | 🟢   |

### 必含章节（12个）

1. 标题+威胁评级
2. 邮件基本信息
3. 高风险指标（评分表）
4. 邮件头分析
5. 正文分析
6. **载荷分析**（有附件时必需）
7. IOC 提取
8. MITRE ATT&CK 映射
9. 攻击链分析
10. **组织归因**（参考 `threat-actor-attribution.md`）
11. 分析存在的问题
12. 结论

## ATT&CK 战术覆盖表

钓鱼分析在 ATT&CK 框架中覆盖以下战术层：

| 战术 | 技术 ID | 技术名称 | 检测方法 |
|------|---------|---------|---------|
| Reconnaissance | T1589.004 | Gather Victim Host Info | 发件人指纹分析、X-Mailer 头检测 |
| Reconnaissance | T1590.002 | Gather Victim Domain Info | 目标域名侦察、DNS 配置探测 |
| Resource Development | T1583.001 | Acquire Infrastructure: Domains | 钓鱼域名注册检测、新域名告警 |
| Resource Development | T1584.001 | Compromise Infrastructure: Domains | 被盗用合法域名发信 |
| Resource Development | T1587.001 | Develop Capabilities: Malware | 宏文档/EXE 载荷开发特征 |
| Initial Access | T1566.001 | Spearphishing Attachment | 附件分析、宏检测 |
| Initial Access | T1566.002 | Spearphishing Link | URL 分析、钓鱼页面检测 |
| Initial Access | T1566.003 | Spearphishing via Service | 社交平台钓鱼检测 |
| Initial Access | T1566.004 | Spearphishing Voice | 语音钓鱼话术识别 |
| Initial Access | T1566.005 | Spearphishing SMS | 短信钓鱼模式检测 |
| Execution | T1204.001 | User Execution: Link | 用户点击链接行为 |
| Execution | T1204.002 | User Execution: File | 用户执行恶意附件 |
| Credential Access | T1552.001 | Credentials In Files | 钓鱼页面收集凭证 |
| Defense Evasion | T1027.002 | Software Packing | 附件混淆/加壳检测 |
| Defense Evasion | T1036.005 | Match Legitimate Name | 伪装合法文件名 |
| Command and Control | T1071.001 | Web Protocols | C2 通信检测 |
| Exfiltration | T1567.002 | Exfiltration to Cloud Storage | 数据外传至云存储 |

### ATT&CK Mitigations

| Mitigation ID | 名称 | 钓鱼防御应用 |
|--------------|------|-------------|
| M1017 | User Training | 安全意识培训、钓鱼模拟演练 |
| M1031 | Network Intrusion Prevention | URL 过滤、邮件网关沙箱 |
| M1021 | Restrict Web-Based Content | 外部链接重写、SafeLinks |
| M1041 | Encrypt Sensitive Information | TLS 加密、防止 SSL 剥离 |
| M1054 | Software Configuration | SPF/DKIM/DMARC 配置 |
| M1047 | Audit Account Permissions | 最小权限原则、MFA 强制 |

---

## OWASP Top 10 + CWE 映射（钓鱼分析视角）

钓鱼攻击与 OWASP Top 10 应用安全风险及 CWE 的映射关系：

| OWASP 类别 | CWE ID | 漏洞名称 | 钓鱼场景 | ATT&CK 映射 |
|-----------|--------|---------|---------|------------|
| A01:2021 Broken Access Control | CWE-287 | Improper Authentication | 钓鱼页面收割凭证导致越权访问 | T1552.001 |
| A01:2021 Broken Access Control | CWE-639 | Authorization Bypass | OAuth 钓鱼获取授权码绕过 | T1566.002 |
| A03:2021 Injection | CWE-79 | XSS | 钓鱼邮件中嵌入 XSS 载荷 | T1059.007 |
| A04:2021 Insecure Design | CWE-602 | Client-Side Enforcement | 钓鱼页面绕过前端验证 | T1566.002 |
| A05:2021 Security Misconfiguration | CWE-16 | Configuration | SPF/DKIM/DMARC 配置缺陷 | T1584.001 |
| A06:2021 Vulnerable Components | CWE-1035 | Outdated Components | 邮件客户端漏洞被钓鱼利用 | T1204.002 |
| A07:2021 Auth Failures | CWE-307 | Excessive Auth Attempts | 暴力破解伪装成合法登录 | T1110 |
| A07:2021 Auth Failures | CWE-521 | Weak Password Requirements | 弱密码策略导致凭证易被爆破 | T1552 |
| A08:2021 Software/Data Integrity | CWE-345 | Insufficient Verification | 附件签名验证缺失 | T1204.002 |
| A09:2021 Logging Failures | CWE-778 | Insufficient Logging | 钓鱼点击未被记录、审计盲区 | T1070 |
| A10:2021 SSRF | CWE-918 | SSRF | 钓鱼链接触发服务端请求 | T1190 |

---

## Sigma 检测规则

### Sigma 规则 1: 钓鱼邮件附件检测

```yaml
title: Suspicious Phishing Email with Malicious Attachment Patterns
id: b3c4d5e6-7f89-0123-abcd-ef2345678901
status: experimental
description: >
    Detects phishing emails with high-risk attachment types combined with
    urgency/authority social engineering patterns.
references:
    - https://attack.mitre.org/techniques/T1566/001/
    - https://attack.mitre.org/techniques/T1204/002/
author: SecSkill Evolution
date: 2026/06/24
logsource:
    product: gateway
    service: email
detection:
    selection_attachment:
        attachment|endswith:
            - '.xlsm'
            - '.docm'
            - '.lnk'
            - '.iso'
            - '.img'
            - '.hta'
            - '.js'
            - '.vbs'
    selection_keywords:
        subject|contains:
            - 'urgent'
            - 'account suspended'
            - 'verify'
            - 'invoice'
            - '紧急'
            - '账户异常'
            - '验证'
            - '发票'
    selection_new_domain:
        sender_domain_age: '<7d'
    condition: selection_attachment and (selection_keywords or selection_new_domain)
falsepositives:
    - Legitimate business communications with macros
level: high
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.t1204.002
    - attack.t1656
```

### Sigma 规则 2: 凭证收割钓鱼页面访问检测

```yaml
title: Potential Credential Phishing via Suspicious Login Form
id: c4d5e6f7-8a90-1234-abcd-ef3456789012
status: experimental
description: >
    Detects users navigating to newly registered domains with login form
    patterns, indicating potential credential phishing.
references:
    - https://attack.mitre.org/techniques/T1566/002/
    - https://attack.mitre.org/techniques/T1552/001/
author: SecSkill Evolution
date: 2026/06/24
logsource:
    product: proxy
    service: web
detection:
    selection_new_domain:
        url_domain_age: '<30d'
    selection_login_pattern:
        url|contains:
            - 'login'
            - 'signin'
            - 'account'
            - 'verify'
            - 'secure'
            - 'update'
    selection_typosquatting:
        url_domain|contains:
            - 'login-'
            - 'secure-'
            - 'verify-'
            - 'account-'
    selection_dynamic_dns:
        url_domain|endswith:
            - '.duckdns.org'
            - '.ydns.eu'
            - '.linkpc.net'
            - '.ddns.net'
            - '.no-ip.org'
    condition: (selection_new_domain or selection_typosquatting or selection_dynamic_dns) and selection_login_pattern
falsepositives:
    - Legitimate services with similar URL patterns
    - New legitimate service launches
level: high
tags:
    - attack.initial_access
    - attack.t1566.002
    - attack.credential_access
    - attack.t1552.001
```

---

## YARA 规则

### YARA 规则 1: 钓鱼邮件宏文档检测

```yara
rule Phishing_Malicious_Office_Document {
    meta:
        description = "Detects phishing Office documents with macro execution patterns"
        author = "SecSkill Evolution"
        date = "2026-06-24"
        reference = "ATT&CK T1566.001, T1204.002"
    strings:
        $ole_header = { D0 CF 11 E0 A1 B1 1A E1 }
        $vba_autoopen = "AutoOpen" ascii nocase
        $vba_documentopen = "Document_Open" ascii nocase
        $vba_workbookopen = "Workbook_Open" ascii nocase
        $powershell = "powershell" ascii nocase
        $cmd_exec = "cmd.exe" ascii nocase
        $wscript = "WScript.Shell" ascii nocase
        $download1 = "MSXML2.XMLHTTP" ascii nocase
        $download2 = "WinHttp.WinHttpRequest" ascii nocase
        $shell_pattern = "/c " ascii
        $encoded_ps = "-enc " ascii nocase
        $base64_flag = "base64" ascii nocase
    condition:
        $ole_header at 0 and (
            any of ($vba_*) and
            (1 of ($powershell, $cmd_exec, $wscript)) and
            (1 of ($download*, $shell_pattern, $encoded_ps, $base64_flag))
        )
}
```

### YARA 规则 2: 钓鱼 Kit 页面特征检测

```yara
rule Phishing_Kit_Landing_Page {
    meta:
        description = "Detects phishing kit landing pages with credential harvesting forms"
        author = "SecSkill Evolution"
        date = "2026-06-24"
        reference = "ATT&CK T1566.002, T1552.001"
    strings:
        $form_password = "type=\"password\"" ascii nocase
        $form_email = "type=\"email\"" ascii nocase
        $form_action = "action=" ascii nocase
        $post_method = "method=\"post\"" ascii nocase
        $brand_office = "office365" ascii nocase
        $brand_outlook = "outlook" ascii nocase
        $brand_google = "google" ascii nocase
        $brand_microsoft = "microsoft" ascii nocase
        $brand_apple = "apple" ascii nocase
        $brand_amazon = "amazon" ascii nocase
        $harvest_php = "$POST[" ascii
        $harvest_get = "$GET[" ascii
        $harvest_request = "$_REQUEST[" ascii
        $redirect_js = "window.location" ascii
        $obfuscated_eval = "eval(atob(" ascii
    condition:
        ($form_password and $form_action) and
        (1 of ($brand_*)) and
        (1 of ($harvest_*, $redirect_js))
}
```

---

## CVE 参考表

钓鱼攻击中高频利用的 CVE 及其检测方法：

| CVE ID | 漏洞名称 | CVSS | ATT&CK | 钓鱼场景 |
|--------|---------|------|--------|--------|
| CVE-2023-23397 | Outlook Elevation of Privilege | 9.8 | T1566.001 | 零点击 Outlook 预览窗格 RCE、提醒弹窗绕过 |
| CVE-2023-36884 | Office/Windows HTML RCE | 8.3 | T1566.001 | 恶意 Office 文档通过 HTML 协议远程加载执行 |
| CVE-2022-30190 | Follina (MSDT RCE) | 7.8 | T1566.001 | Word 文档通过 ms-msdt: 协议执行任意代码 |
| CVE-2022-41040 | Exchange Server EoP (ProxyNotShell) | 8.8 | T1566.002 | 钓鱼链接指向存在该漏洞的 Exchange 服务器 |
| CVE-2021-40444 | MSHTML RCE | 8.8 | T1566.001 | Word 文档加载恶意 ActiveX 控件下载执行 |
| CVE-2021-26855 | Exchange ProxyLogon SSRF | 9.8 | T1566.002 | 钓鱼邮件配合 Exchange SSRF 实现账号接管 |
| CVE-2020-0674 | IE Scripting Engine RCE | 8.8 | T1566.002 | 钓鱼页面利用 IE 漏洞远程执行代码 |

---

## 合规标准参考表

| 标准 | 相关章节 | 钓鱼分析要求 |
|------|---------|-------------|
| ISO/IEC 27001 | A.6.3 | 安全意识培训、反钓鱼测试 |
| ISO/IEC 27035 | 4.3.1 | 安全事件检测与告警、邮件威胁分类 |
| NIST SP 800-61 | 3.2 | 钓鱼事件分类、应急响应流程 |
| NIST SP 800-177 | Section 4 | 可信邮件认证 (SPF/DKIM/DMARC) 部署指南 |
| NIST SP 800-53 | SI-4 | 入侵检测系统配置、邮件网关监控 |
| 等保2.0 第八章 | 8.1.3 | 入侵防范、恶意代码检测、邮件过滤 |
| 等保2.0 第九章 | 9.1.4 | 安全审计、邮件日志留存与分析 |
| GDPR | Art.32(1)(b) | 安全措施、数据泄露检测与通知 |
| GDPR | Art.33 | 72 小时内报告数据泄露 (钓鱼导致) |
| PIPL | 第55条 | 个人信息处理安全评估、钓鱼事件应急 |
| PCI DSS | 12.6 | 安全意识计划 (含钓鱼防范培训) |
| SOC 2 | CC7.3 | 安全事件检测、钓鱼响应有效性 |

---

## 跨技能生态工作流

| 场景 | 上游技能 → 本技能 → 下游技能 | 数据流 |
|------|-------------------------------|--------|
| 邮件威胁狩猎 | email-osint → **phishing-analysis** → domain-analysis | 邮箱情报 → 邮件分析 → 域名深度调查 |
| 附件攻击链 | mail-attachment-downloader → **phishing-analysis** → office-malware-analyzer | 附件下载 → 邮件分析 → 宏文档逆向 |
| 钓鱼URL追踪 | url-analysis → **phishing-analysis** → ip-analysis | URL 分析 → 钓鱼判定 → C2 基础设施 |
| 钓鱼演练 | redteam-intrusion-social → **phishing-analysis** → pdf-report | 红队钓鱼 → 检测分析 → 演练报告 |
| 凭证泄露检测 | auth-log-analysis → **phishing-analysis** → ttp-extractor | 异常登录 → 钓鱼归因 → TTP 提取 |

---

## 附加资源

### 参考文档

- **`references/report-format.md`** - 📋 **报告格式规范（必读）**
- **`references/threat-actor-attribution.md`** - 🎯 **组织归因指南（必读）**
- **`references/analysis-phases.md`** - 分析阶段详解
- **`references/evasion-techniques.md`** - 规避技术检测
- **`references/quishing.md`** - 二维码钓鱼专题
- **`references/archive-analysis.md`** - 压缩包分析专题
- **`references/header-fields.md`** - 邮件头字段参考
- **`references/indicators.md`** - 钓鱼指标检查清单
- **`references/threat-intel-sources.md`** - 威胁情报源
- **`references/common-attacks.md`** - 常见攻击套路速查

### 配置文件

- **`config/detection_rules.toml`** - 检测规则配置

---

## AI 建议

发现邮箱地址时，可建议用户使用 `email-osint` 技能进行深入调查。

---

## 🔴 分析完成检查清单（强制执行）

> **生成报告前必须确认以下所有步骤已完成！**

### 必需步骤验证

- [ ] **Phase 1 已执行** - 运行了 `analyze_email.py --save-attachments`
- [ ] **附件已提取分析** - 有附件时，`extracted_files` 非空，或已手动提取
- [ ] **recommended_skills 已处理** - 所有 `priority: high` 的推荐都已执行
- [ ] **domain-analysis 已调用** - 获取了发件人域名的 WHOIS 和年龄信息
- [ ] **Phase 2 评分已完成** - 按 35 项标准逐项评分
- [ ] **威胁情报已查询** - 调用了 `cybersec_cloud_mcp_risk_insight` MCP 工具
- [ ] **DNS 历史已查询** - 调用了 `cybersec_cloud_mcp_dns_history` MCP 工具

### 常见错误（不要这样做）

| 错误行为                        | 正确做法                               |
| ------------------------------- | -------------------------------------- |
| ❌ 只用 cat/Read 读邮件就下结论  | ✅ 必须先执行 analyze_email.py         |
| ❌ 不加 `--save-attachments`    | ✅ 必须加，否则附件不会保存和解压      |
| ❌ 自己用 PowerShell 解压 ZIP   | ✅ 必须用脚本，PS 不支持加密 ZIP       |
| ❌ 解压失败就说"文件损坏"       | ✅ 工具不对，用脚本重试                |
| ❌ 有附件但不提取分析内容       | ✅ 必须提取附件到磁盘并分析内部文件    |
| ❌ 只看附件哈希/文件名就下结论  | ✅ 必须解压压缩包，检查内部实际内容    |
| ❌ 说"建议不要解压附件"         | ✅ 你是安全分析师，必须提取并分析      |
| ❌ 加密压缩包有密码但不解压     | ✅ 用检测到的密码解压，分析内部文件    |
| ❌ 忽略 recommended_skills 输出 | ✅ 按优先级执行所有推荐的技能          |
| ❌ 不查域名年龄就判断钓鱼       | ✅ 必须调用 domain-analysis 获取 WHOIS |
| ❌ 跳过 Phase 2 的 35 项评分    | ✅ 逐项检查并计算总分                  |
| ❌ SPF fail 就判定钓鱼          | ✅ 综合评估，SPF fail 只是其中一项     |
| ❌ 威胁情报无标记就判安全       | ✅ 新域名即使无标记也是高风险          |

### 报告完整性验证

最终报告必须包含以下关键信息：

1. ✅ **威胁评级** - 基于 Phase 2 评分计算（Critical/High/Medium/Low）
2. ✅ **域名年龄** - 来自 domain-analysis，不能是"未知"
3. ✅ **WHOIS 信息** - 注册日期、注册商
4. ✅ **风险评分表** - 35 项标准的逐项得分
5. ✅ **IOC 清单** - 域名、IP、URL、哈希
6. ✅ **处置建议** - 基于风险等级的具体行动

### 判定逻辑提醒

```
钓鱼判定 ≠ 单一指标

正确的判定逻辑：
┌─────────────────────────────────────────────┐
│ 域名年龄 < 30天？ ─────────────→ +20~30 分  │
│ SPF/DKIM 失败？  ─────────────→ +10~15 分  │
│ 品牌仿冒/同形字？ ────────────→ +20 分     │
│ 威胁情报标记？   ─────────────→ +25~40 分  │
│ 规避技术检测？   ─────────────→ +10~25 分  │
│ ...（共 35 项）                             │
├─────────────────────────────────────────────┤
│ 总分 ≥80 → Critical                         │
│ 总分 50-79 → High                           │
│ 总分 30-49 → Medium                         │
│ 总分 <30 → Low                              │
└─────────────────────────────────────────────┘

错误的判定逻辑：
❌ "SPF fail → 钓鱼"
❌ "威胁情报没标记 → 安全"
❌ "DKIM 通过 → 合法"
```
