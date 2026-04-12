# 邮箱附件下载报告格式规范

## 报告结构（5个章节）

| # | 章节 | 必含 | 内容要点 |
|---|------|------|----------|
| 1 | 链接信息 | ✅ | 原始链接/服务商/状态 |
| 2 | 下载链接 | 条件 | 真实下载 URL |
| 3 | 文件信息 | 条件 | 文件名/大小/类型/哈希 |
| 4 | 后续分析 | 条件 | 推荐的分析技能 |
| 5 | 错误信息 | 条件 | 失败原因 |

---

## 文件类型与后续技能映射

| 文件后缀 | MIME 类型 | 推荐技能 |
|---------|----------|---------|
| .exe/.dll/.scr | application/x-msdownload | binary-reverse-engineering |
| .js/.vbs/.hta | text/javascript, application/x-vbs | binary-reverse-engineering |
| .docm/.xlsm/.pptm | application/vnd.ms-word.document.macroEnabled | office-malware-analyzer |
| .doc/.xls/.ppt | application/msword | office-malware-analyzer |
| .pdf | application/pdf | pdf-analysis |
| .zip/.rar/.7z | application/zip | 解压后按类型分析 |
| .eml/.msg | message/rfc822 | eml-malware-analyzer |

---

## 报告模板

### 成功下载

```markdown
# 📧 邮箱附件下载报告

**下载时间**: YYYY-MM-DD HH:MM
**状态**: ✅ 成功

---

## 1. 链接信息

| 字段 | 值 |
|------|-----|
| 原始链接 | https://mail.163.com/large-attachment-download/... |
| 服务商 | 163 邮箱 |
| linkKey | abc123def456... |

---

## 2. 下载链接

| 字段 | 值 |
|------|-----|
| 真实下载 URL | https://fs.163.com/download/... |

---

## 3. 文件信息

| 字段 | 值 |
|------|-----|
| 文件名 | invoice.exe |
| 大小 | 1.25 MB |
| 类型 | application/x-msdownload |
| MD5 | d41d8cd98f00b204e9800998ecf8427e |
| SHA256 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| 保存路径 | /tmp/mail_download_xxx/invoice.exe |

---

## 4. 后续分析建议

| 文件类型 | 推荐技能 | 命令 |
|---------|---------|------|
| 可执行文件 (.exe) | binary-reverse-engineering | 调用技能分析 |

**风险提示**:
- ⚠️ 可执行文件，请勿直接运行
- 建议先进行威胁情报查询（MD5/SHA256）
```

### 下载失败

```markdown
# 📧 邮箱附件下载报告

**下载时间**: YYYY-MM-DD HH:MM
**状态**: ❌ 失败

---

## 1. 链接信息

| 字段 | 值 |
|------|-----|
| 原始链接 | https://mail.163.com/large-attachment-download/... |
| 服务商 | 163 邮箱 |

---

## 2. 错误信息

| 字段 | 值 |
|------|-----|
| 错误类型 | 链接过期 |
| 错误详情 | API 返回: {"code": 404, "msg": "文件不存在"} |

---

## 3. 处置建议

1. 确认链接是否仍有效
2. 检查是否需要登录邮箱账号
3. 联系发送方重新分享
```

---

## JSON 输出格式

```json
{
  "success": true,
  "url": "https://mail.163.com/large-attachment-download/...",
  "provider": "163",
  "download_url": "https://fs.163.com/download/...",
  "filename": "invoice.exe",
  "size": 1310720,
  "content_type": "application/x-msdownload",
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "path": "/tmp/mail_download_xxx/invoice.exe",
  "error": ""
}
```
