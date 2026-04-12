---
name: rga-knowledge-search
description: 在本地知识库中搜索文档内容，从 rga 缓存读取已提取的文本。支持 PDF、Office 文档、电子书、压缩包等格式。当用户询问内部文档、历史报告、本地资料时使用。触发词包括"知识库"、"本地文档"、"<KNOWLEDGE></KNOWLEDGE>"、"之前的报告"，或类似"安全报告里说了什么"的问题。
metadata:
  version: 1.2.1
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

## 命令速查

### 搜索

| 场景       | 命令                         |
| ---------- | ---------------------------- |
| 列出文件   | `rga -l "关键词" <路径>`     |
| 带上下文   | `rga -C 3 "关键词" <路径>`   |
| 仅 PDF     | `rga -t pdf "关键词" <路径>` |
| 忽略大小写 | `rga -i "关键词" <路径>`     |
| 正则搜索   | `rga "pattern.*" <路径>`     |

### 读取（优先）

| 操作       | 命令                                               |
| ---------- | -------------------------------------------------- |
| 读取内容   | `python scripts/cache_reader.py file.pdf`          |
| 取消限制   | `python scripts/cache_reader.py file.pdf --no-limit` |
| 文件信息   | `python scripts/cache_reader.py --info file.pdf`  |
| 列出缓存   | `python scripts/cache_reader.py --list`           |

**滑动分页**（长文档导航）:

| 操作        | 命令                                                                   |
| ----------- | ---------------------------------------------------------------------- |
| 按页读取    | `python scripts/cache_reader.py file.pdf --page 1`                     |
| 定位关键词  | `python scripts/cache_reader.py file.pdf --around "keyword"`           |
| 第 N 处匹配 | `python scripts/cache_reader.py file.pdf --around "keyword" --occur 3` |
| 从偏移读取  | `python scripts/cache_reader.py file.pdf --offset 50000`               |
| 从行号读取  | `python scripts/cache_reader.py file.pdf --line 100`                   |
| 缩进模式    | `python scripts/cache_reader.py file.py --indent 100`                  |

**格式化选项**:

| 操作         | 命令                                                |
| ------------ | --------------------------------------------------- |
| 显示行号     | `python scripts/cache_reader.py file.pdf -n`        |
| 原始输出     | `python scripts/cache_reader.py file.pdf --raw`     |
| 行号+分页    | `python scripts/cache_reader.py file.pdf -n --page 2` |

**说明**:
- 默认限制 50000 字符（约 12500 tokens）防止超出上下文窗口
- 默认截断超过 500 字符的行，制表符转换为 4 空格
- `--indent` 模式按缩进级别提取代码块，适合查看函数/类定义
- `-n` 显示行号，格式与 `cat -n` 一致（右对齐 6 位 + tab + 内容）

### 读取（兜底）

| 格式     | 命令                                               |
| -------- | -------------------------------------------------- |
| PDF      | `python scripts/doc_viewer.py file.pdf`            |
| Word     | `python scripts/doc_viewer.py file.docx`           |
| Excel    | `python scripts/doc_viewer.py file.xlsx`           |
| 压缩包   | `python scripts/doc_viewer.py file.zip`            |
| 取消限制 | `python scripts/doc_viewer.py file.pdf --no-limit` |

**注意**: 同样默认限制 50000 字符

## 缓存位置

| 系统    | 路径                                             |
| ------- | ------------------------------------------------ |
| Linux   | `~/.cache/ripgrep-all/cache.sqlite3`             |
| macOS   | `~/Library/Caches/ripgrep-all/cache.sqlite3`     |
| Windows | `%LOCALAPPDATA%/ripgrep-all/cache/cache.sqlite3` |

## 依赖

**系统**: `ripgrep-all`, `poppler`, `pandoc`

**Python (cache_reader)**: `pip install zstandard`

**Python (doc_viewer)**: `pip install pdfplumber python-docx openpyxl python-pptx ebooklib`
