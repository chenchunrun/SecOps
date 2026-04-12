---
name: pdf-analysis
description: 当用户询问"分析 PDF 是否恶意"、"检测 PDF 安全性"、"PDF 威胁分析"、"检查 PDF 是否有病毒"、"PDF 安全检测"、"扫描 PDF"时使用此技能。
metadata:
  version: 1.0.0
  builtin: true
---

# PDF 恶意分析

## 依赖要求

**Python 版本**: 3.8+

**内置脚本**:
- `pdf_scan.py` - 快速特征提取
- `pdf_extract.py` - 内容提取

**推荐安装**:
```bash
pip install PyMuPDF Pillow pyzbar  # 增强 pdf_extract.py
brew install qpdf poppler          # 深度分析工具
pip install pdfid pdf-parser       # Didier Stevens 工具
```

## 快速使用

```bash
# 快速扫描
python3 scripts/pdf_scan.py sample.pdf

# JSON 输出
python3 scripts/pdf_scan.py -j sample.pdf

# 提取全部内容
python3 scripts/pdf_extract.py sample.pdf

# 只提取图像和检测二维码
python3 scripts/pdf_extract.py sample.pdf --images --qr
```

## 威胁类型

| 类型 | 攻击方式 | 关注点 |
|------|----------|--------|
| 漏洞利用型 | 利用 PDF Reader 漏洞 | JavaScript、CVE 特征 |
| 钓鱼诱导型 | 诱导点击链接/扫码 | 文本、URL、二维码 |
| 恶意载荷型 | 嵌入可执行文件 | EmbeddedFile、附件 |
| 信息窃取型 | 外传数据 | 外部链接、表单 |

## 分析工作流

### Phase 1: 快速扫描
```bash
python3 scripts/pdf_scan.py sample.pdf
```
输出：威胁指标（JS/嵌入文件/URL）

### Phase 2: 内容提取
```bash
python3 scripts/pdf_extract.py sample.pdf --text    # 文本
python3 scripts/pdf_extract.py sample.pdf --images --qr  # 图像+二维码
python3 scripts/pdf_extract.py sample.pdf --files   # 嵌入文件
```

### Phase 3: 深度分析
- JavaScript → 分析脚本内容
- 嵌入文件 → 调用对应技能
- URL → 调用 `url-analysis`

### Phase 4: 报告生成
按 `references/report-format.md` 输出报告

## 高危嵌入文件类型

提取后需进一步分析：
- 可执行文件: `.exe`, `.dll`, `.scr`, `.bat`, `.ps1`
- 脚本文件: `.js`, `.vbs`, `.hta`
- Office 宏文档: `.docm`, `.xlsm`
- 压缩包: `.zip`, `.rar`, `.7z`

## 关联技能调用

| 提取到的 IOC | 调用技能 |
|-------------|---------|
| URL | `url-analysis` |
| 二维码中的 URL | `url-analysis` |
| 嵌入 Office 文件 | `office-malware-analyzer` |
| 嵌入可执行文件 | `binary-reverse-engineering` |
| 外部域名 | `domain-analysis` |

## 工具速查

| 任务 | 命令 |
|------|------|
| 快速扫描 | `python3 pdf_scan.py sample.pdf` |
| 提取全部 | `python3 pdf_extract.py sample.pdf` |
| 提取嵌入文件 | `python3 pdf_extract.py sample.pdf --files` |
| 提取图像 | `python3 pdf_extract.py sample.pdf --images` |
| 检测二维码 | `python3 pdf_extract.py sample.pdf --images --qr` |
| 文件信息 | `pdfinfo sample.pdf` |
| 对象统计 | `pdfid.py sample.pdf` |
| 对象解析 | `pdf-parser.py -o N sample.pdf` |
| JavaScript | `pdf-parser.py -s javascript sample.pdf` |

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 📋 报告格式规范（必读）
- [references/structure-analysis.md](references/structure-analysis.md) - PDF 结构分析
- [references/javascript-cve.md](references/javascript-cve.md) - JavaScript 与 CVE
- [references/phishing-detection.md](references/phishing-detection.md) - 钓鱼检测
- [references/handling-guide.md](references/handling-guide.md) - 处置指南
- [references/malware-signatures.md](references/malware-signatures.md) - 恶意特征库
