# PDF JavaScript 分析与 CVE 检测

## JavaScript 提取

```bash
# 使用 pdf-parser 提取 JavaScript
pdf-parser.py -s javascript sample.pdf

# 或从内置脚本输出
python3 pdf_scan.py -j sample.pdf | jq '.javascript'
```

## 危险 JavaScript 模式

| 模式 | 说明 |
|------|------|
| `eval()` | 动态执行代码 |
| `unescape()` | 解码混淆代码 |
| `String.fromCharCode()` | 字符编码混淆 |
| `this.exportDataObject` | 导出嵌入文件 |
| `app.launchURL` | 打开 URL |
| `util.printf` 长格式串 | CVE-2008-2992 |
| `Collab.collectEmailInfo` | CVE-2007-5659 |
| `spell.customDictionaryOpen` | CVE-2009-1493 |
| 超长字符串 (>1000字符) | 可能是 shellcode |
| 大量 %u 编码 | Unicode shellcode |

## 已知 CVE 特征

| CVE | 漏洞 | 检测特征 |
|-----|------|----------|
| CVE-2008-2992 | util.printf 溢出 | `util.printf` + 长格式串 |
| CVE-2009-0927 | getIcon 溢出 | `Collab.getIcon` |
| CVE-2009-1493 | customDictionaryOpen | `spell.customDictionaryOpen` |
| CVE-2010-0188 | JBIG2 解码溢出 | `/JBIG2Decode` + 畸形数据 |
| CVE-2010-2883 | CoolType SING 溢出 | `SING` 表 + `uniqueName` |
| CVE-2011-2462 | U3D 内存损坏 | `/U3D` 流 |
| CVE-2013-0640 | XFA TIFF 溢出 | `/XFA` + TIFF 图像 |
| CVE-2013-2729 | XFA 整数溢出 | `/XFA` + 畸形数据 |

## 通用漏洞利用特征

```bash
# 检查 shellcode 特征
strings sample.pdf | grep -E '%u[0-9A-Fa-f]{4}' | head

# 检查堆喷射
strings sample.pdf | grep -E '(0x[0-9A-Fa-f]{2}){100,}'

# 检查 NOP sled
xxd sample.pdf | grep -E '(90 ){10,}'
```

**可疑特征**:
- 大量重复的 NOP (0x90) 或等效指令
- 大量 `%u` 编码的 Unicode
- 超长字符串（可能是堆喷射）
- 畸形的对象结构
