---
name: mail-attachment-downloader
description: 当用户要求"下载邮箱附件"、"获取邮箱中转站文件"、"下载 163 邮箱附件"、"下载 QQ 邮箱附件"、"分析邮箱分享链接"时使用此技能。
metadata:
  version: 1.1.0
  builtin: true
---

# 邮箱附件中转站下载技能

从邮箱文件中转站（163/QQ）提取真实下载链接并下载文件，支持文件哈希计算和元数据提取。

> 此技能通常作为其他分析技能的**上游依赖**，用于获取待分析的文件

## 依赖要求

**Python 版本**: 3.8+

**内置脚本**:
| 脚本 | 用途 |
|------|------|
| mail_downloader.py | 邮箱中转站文件下载（主入口） |

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
```

## 工作流程

### Phase 1: 链接识别

1. **URL 模式匹配**
   - 检测是否为已知邮箱中转站链接
   - 识别服务商（163/QQ）
   - 提取关键参数

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
   | 元数据记录 | 大小、类型、路径 |

### Phase 4: 结果输出

5. **返回信息**
   | 字段 | 说明 |
   |------|------|
   | success | 是否成功 |
   | provider | 服务商 (163/qq) |
   | download_url | 真实下载链接 |
   | filename | 文件名 |
   | size | 文件大小 |
   | md5 / sha256 | 文件哈希 |
   | path | 本地保存路径 |

## 命令行参数

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

## 输出格式

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

## 与其他技能的关联

**下游技能**（依赖本技能下载文件后分析）：

| 技能 | 使用场景 |
|------|---------|
| `url-analysis` | 分析 URL 时发现邮箱中转站链接 |
| `phishing-analysis` | 分析钓鱼邮件中的附件链接 |
| `eml-malware-analyzer` | 分析 EML 邮件中的附件链接 |
| `binary-reverse-engineering` | 下载后分析可执行文件 |
| `office-malware-analyzer` | 下载后分析 Office 文档 |
| `pdf-analysis` | 下载后分析 PDF 文件 |

**典型调用链**：
```
phishing-analysis
    └─→ 发现邮箱附件链接
        └─→ mail-attachment-downloader (下载文件)
            └─→ office-malware-analyzer (分析 .docm)
            └─→ binary-reverse-engineering (分析 .exe)
```

## 安全注意事项

| 风险 | 缓解措施 |
|------|---------|
| 下载恶意文件 | 默认保存到临时目录，不自动执行 |
| 链接过期 | 返回明确错误信息 |
| 大文件 | 流式下载，可设置超时 |
| 网络异常 | 重试机制 + 详细错误信息 |

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 📋 报告格式规范
