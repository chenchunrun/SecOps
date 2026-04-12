# PDF 结构分析详解

## 对象统计

```bash
# 使用 pdfid.py
pdfid.py sample.pdf

# 或使用内置脚本
python3 pdf_scan.py -j sample.pdf | jq '.object_counts'
```

## 危险对象类型

| 对象 | 说明 |
|------|------|
| `/JavaScript` | 嵌入脚本，可触发漏洞 |
| `/JS` | JavaScript 引用 |
| `/Launch` | 启动外部程序 |
| `/EmbeddedFile` | 嵌入文件（可能是恶意软件） |
| `/OpenAction` | 打开时自动执行 |
| `/AA` | 附加动作 |
| `/AcroForm` | 交互式表单（可提交数据） |
| `/XFA` | XML 表单（历史漏洞多） |
| `/RichMedia` | 富媒体（Flash 等） |
| `/URI` | 外部链接 |

## 流解压与分析

```bash
# 解压所有流
qpdf --qdf --object-streams=disable sample.pdf uncompressed.pdf

# 查看特定对象
pdf-parser.py -o 10 sample.pdf

# 解码 FlateDecode 流
pdf-parser.py -o 10 -f sample.pdf
```

**可疑流特征**:
- 多层嵌套压缩（FlateDecode + ASCIIHexDecode + ...）
- 异常大的流（可能嵌入恶意载荷）
- 无法解压的流（可能是畸形数据触发漏洞）

## OpenAction 类型

| 动作 | 正常用途 | 恶意用途 |
|------|----------|----------|
| `/GoTo` | 跳转到页面 | 通常安全 |
| `/GoToR` | 打开其他 PDF | 可能加载恶意 PDF |
| `/GoToE` | 打开嵌入文档 | 可能执行嵌入恶意文件 |
| `/Launch` | 启动程序 | 执行恶意软件 |
| `/URI` | 打开 URL | 可能是钓鱼链接 |
| `/JavaScript` | 执行脚本 | 触发漏洞 |
| `/SubmitForm` | 提交表单 | 可能外传数据 |
