---
name: pdf-report
description: 生成专业的 PDF 报告文档，支持封面页、多级标题、表格、图片、页眉页脚等功能。当用户需要将分析结果、报告内容输出为 PDF 格式时使用此技能。
metadata:
  version: 1.2.0
  builtin: true
  attck_version: v16.1
  owasp_version: "2025"
---

# PDF Report - PDF 报告生成

## Overview

基于 reportlab 库的 PDF 报告生成工具，提供专业的文档排版功能，支持中文字体、封面页、多级标题、表格、图片等元素。适用于生成安全分析报告、威胁情报报告、业务分析报告等场景。

## 核心功能

| 功能 | 说明 |
|------|------|
| 封面页 | 带背景图、标题、副标题、作者、日期信息 |
| 多级标题 | 支持 1-4 级标题，自动样式 |
| 正文段落 | 首行缩进、1.5 倍行距、两端对齐 |
| 表格 | 自动换行、交替行背景色、表头高亮 |
| 图片 | 自动缩放、居中、带说明文字 |
| 页眉页脚 | 页眉文本、页码（从正文开始计数） |
| 中文支持 | 自动加载中文字体 |

## 工作流程

### 阶段 1: 初始化

```python
import sys
sys.path.append('<SKILL_DIR>/scripts')
from pdf_template import PDFTemplate

# 创建 PDF 模板管理器实例（默认中文）
manager = PDFTemplate(language='zh')

# 或创建英文报告
# manager = PDFTemplate(language='en')
```

**语言支持**:

| 参数 | 效果 |
|------|------|
| `language='zh'` | 中文（默认）：作者、表、图、第 N 页 |
| `language='en'` | 英文：Author、Table、Figure、Page N |

**说明**: 初始化时会自动下载中文字体和默认封面背景图（如果不存在）。

### 阶段 2: 配置文档

```python
# 设置页眉文本
manager.header_text = "威胁分析报告"

# 可选：使用自定义封面背景图
# manager.set_cover_background("custom_background.jpg")
```

### 阶段 3: 添加封面页

```python
from datetime import datetime

manager.add_cover_page(
    title="威胁分析报告",
    subtitle="针对可疑 IP 的深度分析",
    author="安全分析团队",
    date=datetime.now().strftime("%Y年%m月%d日"),
    organization="安全运营中心"  # 可选
)
```

### 阶段 4: 添加正文内容

#### 标题

```python
# 一级标题
manager.add_title("一、执行摘要", level=1)

# 二级标题
manager.add_title("1.1 分析背景", level=2)

# 三级标题
manager.add_title("1.1.1 事件概述", level=3)

# 四级标题
manager.add_title("1.1.1.1 详细说明", level=4)
```

#### 正文段落

```python
# 带首行缩进的段落（默认）
manager.add_content("本次分析针对企业内网发现的可疑 IP 地址进行深度威胁研判。")

# 不带首行缩进的段落
manager.add_content("分析时间：2024-01-15", first_line_indent=False)
```

#### 表格

```python
# 准备表格数据（第一行为表头）
table_data = [
    ["指标", "结果", "风险等级"],
    ["多源标记恶意", "是", "高"],
    ["恶意样本关联", "5 个", "中"],
    ["近期活跃", "是", "高"]
]

# 添加表格（行数, 列数, 数据, 说明文字）
manager.add_table(4, 3, table_data, caption="威胁指标评估结果")
```

**表格自动编号**: 表格说明会自动编号为 "表<1>", "表<2>" 等。

#### 图片

```python
# 添加图片（默认宽度 14cm，高度按比例自动计算）
manager.add_image("screenshot.png", caption="攻击流量截图")

# 指定宽度
manager.add_image("diagram.png", width=10, caption="攻击路径示意图")

# 指定宽度和高度
manager.add_image("chart.png", width=12, height=8, caption="威胁趋势图")
```

**图片自动编号**: 图片说明会自动编号为 "图<1>", "图<2>" 等。

#### 其他元素

```python
# 添加分页符
manager.add_page_break()

# 添加空白间距（单位：点）
manager.add_spacer(24)
```

### 阶段 5: 保存文档

```python
# 保存 PDF 文档
filepath = manager.save_document("威胁分析报告.pdf")
print(f"PDF 已保存: {filepath}")

# 获取文档信息
info = manager.get_document_info()
print(f"元素数: {info['total_elements']}")
print(f"表格数: {info['table_count']}")
print(f"图片数: {info['image_count']}")
```

## 完整示例

```python
import sys
from datetime import datetime

sys.path.append('<SKILL_DIR>/scripts')
from pdf_template import PDFTemplate

def generate_threat_report():
    """生成威胁分析报告"""

    # 1. 初始化
    manager = PDFTemplate()
    manager.header_text = "IP 威胁分析报告"

    # 2. 封面
    manager.add_cover_page(
        title="IP 威胁分析报告",
        subtitle="45.33.32.156 深度分析",
        author="安全分析团队",
        date=datetime.now().strftime("%Y年%m月%d日"),
        organization="安全运营中心"
    )

    # 3. 执行摘要
    manager.add_title("一、执行摘要", level=1)
    manager.add_content("本报告对可疑 IP 地址 45.33.32.156 进行了全面的威胁情报分析。")
    manager.add_content("分析结果表明该 IP 具有高度威胁风险，建议立即采取封锁措施。")

    # 4. 基础信息
    manager.add_title("二、基础信息", level=1)
    manager.add_content("IP 地址: 45.33.32.156", first_line_indent=False)
    manager.add_content("IP 类型: 公网地址", first_line_indent=False)
    manager.add_content("地理位置: 美国 / 加利福尼亚州", first_line_indent=False)
    manager.add_content("ASN: AS63949 (Linode, LLC)", first_line_indent=False)

    # 5. 威胁情报
    manager.add_title("三、威胁情报", level=1)

    intel_data = [
        ["来源", "标签", "首次发现", "最后活跃"],
        ["VirusTotal", "scanner", "2023-05-12", "2024-12-20"],
        ["AbuseIPDB", "malware", "2023-06-01", "2024-12-19"],
        ["ThreatFox", "C2", "2024-01-10", "2024-12-18"]
    ]
    manager.add_table(4, 4, intel_data, caption="多源威胁情报汇总")

    # 6. 风险评估
    manager.add_title("四、风险评估", level=1)

    risk_data = [
        ["指标", "结果", "分值"],
        ["多源标记恶意", "是", "+40"],
        ["C2 标签", "是", "+30"],
        ["恶意样本关联", "5 个", "+15"],
        ["近期活跃", "是", "+10"],
        ["总分", "", "95"]
    ]
    manager.add_table(6, 3, risk_data, caption="风险评分明细")

    # 7. 结论
    manager.add_title("五、结论与建议", level=1)
    manager.add_content("基于以上分析，该 IP 地址风险等级为 Critical，强烈建议采取以下措施：")
    manager.add_content("1. 立即在防火墙封锁该 IP 地址", first_line_indent=False)
    manager.add_content("2. 检查内网是否有主机与该 IP 通信", first_line_indent=False)
    manager.add_content("3. 将该 IP 加入威胁情报监控列表", first_line_indent=False)

    # 8. 保存
    filepath = manager.save_document("ip_threat_report.pdf")
    return filepath

if __name__ == "__main__":
    generate_threat_report()
```

## 依赖要求

### 必需依赖

| 依赖 | 用途 | 安装命令 |
|------|------|----------|
| reportlab | PDF 生成核心库 | `pip install reportlab` |
| Pillow | 图片处理 | `pip install Pillow` |
| PyPDF2 | PDF 合并（用于添加最后一页） | `pip install PyPDF2` |

### 安装命令

```bash
pip install reportlab Pillow PyPDF2
```

### 环境检查

```bash
python -c "import reportlab; print('reportlab OK')"
python -c "from PIL import Image; print('Pillow OK')"
python -c "from PyPDF2 import PdfReader; print('PyPDF2 OK')"
```

## API 参考

### PDFTemplate 类

| 方法 | 参数 | 说明 |
|------|------|------|
| `add_cover_page()` | title, subtitle, author, date, organization, additional_info | 添加封面页 |
| `add_title()` | text, level (1-4) | 添加标题 |
| `add_content()` | text, first_line_indent (bool) | 添加正文段落 |
| `add_table()` | rows, cols, data, caption | 添加表格 |
| `add_image()` | image_path, width, height, caption | 添加图片 |
| `add_page_break()` | 无 | 添加分页符 |
| `add_spacer()` | height (默认 12) | 添加空白间距 |
| `set_cover_background()` | background_image_path | 设置封面背景图 |
| `save_document()` | filename | 保存 PDF 文档 |
| `get_document_info()` | 无 | 获取文档统计信息 |

### 属性

| 属性 | 类型 | 说明 |
|------|------|------|
| `header_text` | str | 页眉文本 |
| `story` | list | 文档内容元素列表 |

## 注意事项

1. **中文字体**: 优先使用嵌入式 TTF 字体（SourceHanSansCN），确保在微信等第三方预览器中也能正确显示中文。首次运行会自动下载字体文件，需要网络连接。若下载失败则降级为 CID 字体（依赖阅读器本地字体）
2. **封面背景**: 默认使用在线背景图，可通过 `set_cover_background()` 设置本地图片
3. **图片格式**: 支持 PNG、JPEG、GIF 等常见格式
4. **表格宽度**: 表格会自动适应页面宽度，列宽按比例分配
5. **页码**: 页码从正文页开始计数，封面页不显示页码

## 安全报告技术框架映射

### MITRE ATT&CK 报告集成

生成的 PDF 报告应包含 ATT&CK 技术引用，以标准化威胁描述：

| ATT&CK 元素 | 报告中的位置 | 格式示例 |
|------------|------------|--------|
| **Tactic** | 执行摘要、结论 | `Credential Access` |
| **Technique ID** | 威胁情报章节 | `T1110.001 (Brute Force: Password Guessing)` |
| **Sub-technique** | 详细分析章节 | `T1110.004 (Credential Stuffing)` |
| **Detection** | 检测与响应章节 | Sigma 规则引用、日志源建议 |
| **Mitigation** | 建议章节 | 对应 ATT&CK Mitigation ID |

报告模板中的 ATT&CK 映射表格式：
```python
attck_table = [
    ["ATT&CK ID", "战术", "技术", "检测状态"],
    ["T1110.001", "Credential Access", "Password Guessing", "已检测"],
    ["T1110.004", "Credential Access", "Credential Stuffing", "已检测"],
    ["T1078", "Defense Evasion", "Valid Accounts", "部分覆盖"],
]
manager.add_table(4, 4, attck_table, caption="ATT&CK 技术映射表")
```

### OWASP 2025 报告维度

安全评估类报告应包含 OWASP 维度分析：

| OWASP 类别 | 报告章节 | 说明 |
|-----------|---------|------|
| A01: Broken Access Control | 访问控制评估 | 权限模型分析结果 |
| A07: Authentication Failures | 认证安全评估 | 登录安全分析结果 |
| A09: Logging & Monitoring | 日志审计 | SIEM 覆盖度评估 |

### Sigma 规则引用

报告中引用 Sigma 检测规则，提供可操作的检测建议：
```python
sigma_ref = (
    "检测规则: Sigma rule auth_credential_stuffing (ATT&CK T1110.004)\n"
    "SIEM 集成: Splunk / Elastic Security / Microsoft Sentinel"
)
manager.add_content(sigma_ref, first_line_indent=False)
```

### YARA 规则引用

报告中引用 YARA 规则，提供恶意样本检测建议：
```python
yara_ref = (
    "YARA 规则: WebShell_Generic_Windows (ATT&CK T1505.003)\n"
    "YARA 规则: Windows_Backdoor_Features (ATT&CK T1547)\n"
    "部署位置: EDR / 文件服务器 / Web 服务器"
)
manager.add_content(yara_ref, first_line_indent=False)
```

### CVE 参考表

安全报告应在威胁情报章节包含相关 CVE 引用：

| CVE ID | 受影响系统 | CVSS | 报告建议位置 |
|--------|-----------|------|-------------|
| CVE-2024-3094 | XZ Utils 后门 | 10.0 | 供应链风险评估报告 |
| CVE-2024-21413 | Outlook RCE | 9.8 | 钓鱼邮件分析报告 |
| CVE-2023-23397 | Outlook 提权 | 9.8 | 钓鱼邮件分析报告 |
| CVE-2021-34527 | PrintNightmare | 8.8 | Windows IR 报告 |
| CVE-2020-1472 | Zerologon | 10.0 | 域渗透 IR 报告 |
| CVE-2019-0708 | BlueKeep | 9.8 | RDP 暴露面评估报告 |
| CVE-2021-30860 | FORCEDENTRY | 9.8 | 移动设备 IR 报告 |
| CVE-2023-20198 | Cisco IOS XE | 10.0 | 网络设备评估报告 |

### IOC 标准格式

报告中 IOC 应遵循标准格式化规范：

| IOC 类型 | 报告格式 | 示例 |
|---------|---------|------|
| IP 地址 | 方括号转义 | `45.33[.]32[.]156` |
| URL | 防点击格式 | `hxxp://example[.]com/path` |
| 域名 | 方括号转义 | `evil[.]example[.]com` |
| 哈希 | 完整展示 | `a1b2c3d4e5f6...` |
| 邮箱 | 方括号转义 | `attacker[.]user[@]evil[.]com` |

## 合规与标准参考

| 标准/框架 | 报告章节要求 | 说明 |
|-----------|------------|------|
| **GDPR** | 数据事件报告 | 个人数据泄露事件 72 小时报告要求 |
| **PIPL** | 个人信息保护 | 数据处理活动记录 |
| **ISO 27001** | ISMS 审计报告 | A.16 事件管理 |
| **PCI DSS** | 合规审计报告 | Req 10: 日志监控 |
| **NIST CSF** | 风险评估报告 | Detect/Respond/Recover |

## 跨技能报告模板

不同安全场景推荐使用对应的报告模板：

| 场景 | 上游技能 | 报告重点 | ATT&CK 覆盖 |
|------|---------|---------|------------|
| **IP 威胁分析** | `ip-analysis` | 情报汇总、信誉评分 | T1078 |
| **钓鱼邮件分析** | `phishing-analysis` | 邮件头、URL、附件 | T1566 |
| **认证日志分析** | `auth-log-analysis` | 暴力破解、不可能旅行 | T1110, T1078 |
| **恶意软件分析** | `binary-reverse-engineering` | 行为分析、IOCs | T1059, T1218 |
| **应急响应** | `linux-ir` / `windows-ir` | 时间线、影响范围 | 多战术 |
| **代码审计** | `code-audit` | 漏洞清单、修复建议 | OWASP 2025 |
| **URL/域名分析** | `url-analysis` / `domain-analysis` | DNS、SSL、信誉 | T1566.002 |

## 报告质量检查清单

### 内容完整性
- [ ] 封面信息完整（标题、作者、日期、机构）
- [ ] 执行摘要包含关键发现和风险等级
- [ ] 正文章节结构清晰、逻辑连贯
- [ ] ATT&CK 技术映射表（安全报告）
- [ ] OWASP 维度分析（应用安全报告）
- [ ] IOC 列表使用标准转义格式

### 格式规范
- [ ] 表格和图片有编号说明文字
- [ ] 页眉文本已设置
- [ ] 页码从正文开始
- [ ] 文件名包含日期和主题
- [ ] 敏感信息已脱敏处理

### 安全合规
- [ ] IOC 转义（防误点）
- [ ] 敏感数据脱敏（GDPR/PIPL）
- [ ] 报告分级标识（公开/内部/机密）
- [ ] 附录包含检测规则（Sigma/YARA）

## 相关参考

- [references/report-format.md](references/report-format.md) - 报告格式规范（结构、排版、样式）

## 关联技能

| 关系 | 技能 | 说明 |
|------|------|------|
| **数据来源** | `ip-analysis` | IP 分析结果 → 威胁报告 |
| **数据来源** | `phishing-analysis` | 钓鱼分析 → 钓鱼报告 |
| **数据来源** | `auth-log-analysis` | 认证日志分析 → 登录安全报告 |
| **数据来源** | `linux-ir` / `windows-ir` | IR 取证 → 事件响应报告 |
| **数据来源** | `code-audit` | 代码审计 → 漏洞报告 |
| **数据来源** | `url-analysis` / `domain-analysis` | URL 分析 → 威胁报告 |
| **输出格式** | `office-report` | Office 格式替代输出 |

## AI 建议

- 生成报告前，先用 `ttp-extractor` 从分析结果中归纳 ATT&CK 技术映射
- IOC 列表建议同时输出 STIX 2.1 格式，方便威胁情报共享
- 大规模事件报告可分章节由不同分析技能填充
