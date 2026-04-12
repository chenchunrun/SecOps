---
name: pdf-report
description: 生成专业的 PDF 报告文档，支持封面页、多级标题、表格、图片、页眉页脚等功能。当用户需要将分析结果、报告内容输出为 PDF 格式时使用此技能。
metadata:
  version: 1.0.0
  builtin: true
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

## 相关参考

- [references/report-format.md](references/report-format.md) - 报告格式规范
