# 密码保护压缩包分析专题

密码保护的压缩包是规避安全扫描的常用技术（MITRE ATT&CK T1027.002）。

## 为什么攻击者使用密码保护附件

- 邮件安全网关无法解压分析内容
- 杀毒软件无法扫描加密文件
- 沙箱环境无法自动执行
- 用户手动输入密码增加参与度
- 绕过DLP（数据防泄漏）系统

## 典型恶意投递模式

```
邮件正文: "密码是123456" 或 "解压密码见附件说明"
附件: document.zip (密码保护)
内含: malware.exe 或 payload.js
```

## 可疑特征

| 特征 | 说明 |
|------|------|
| 密码保护ZIP/RAR/7z | 规避安全扫描 |
| 邮件正文提供解压密码 | 典型恶意投递 |
| 压缩包内含.exe/.scr/.bat | 可执行载荷 |
| 压缩包内含.js/.vbs/.hta | 脚本载荷 |
| 压缩包内含嵌套压缩包 | 多层规避 |
| 双扩展名文件 | document.pdf.exe |
| 文件名为数字 | 如764.exe，可能自动生成 |

## 分析步骤

1. 识别附件是否为压缩格式（ZIP/RAR/7z/TAR.GZ）
2. 检查是否密码保护（尝试列出内容）
3. 搜索邮件正文中的密码模式
4. 如可解压，列出内容（不执行）
5. 检查内部文件扩展名和类型
6. 计算内部文件哈希

## 密码检测正则模式

```
中文: 密码[是为:：]?\s*[\w\d]+
中文: 解压[密码码][是为:：]?\s*[\w\d]+
英文: password[:\s]+[\w\d]+
英文: pwd[:\s]+[\w\d]+
```

## ZIP文件结构分析（无需解压）

```bash
# 列出ZIP内容（即使加密也可查看文件名）
unzip -l suspicious.zip

# 检查是否加密
unzip -t suspicious.zip 2>&1 | grep -i "password\|encrypt"

# 使用Python查看
python -c "import zipfile; print(zipfile.ZipFile('file.zip').namelist())"
```

## 使用脚本

```bash
# 分析压缩包
python scripts/archive_analyzer.py suspicious.zip
python scripts/archive_analyzer.py attachment.rar --format json

# 检测邮件正文中的密码
python scripts/archive_analyzer.py dummy --check-password "密码是123456"

# 查看支持的后端
python scripts/archive_analyzer.py --status
```

## 支持的格式

| 格式 | 基础支持 | 完整支持 |
|------|----------|----------|
| ZIP | zipfile (stdlib) | pyzipper (AES) |
| 7z | 头部检测 | py7zr |
| RAR | 头部检测 | rarfile |

## 密码解压与文件提取

### CLI 用法

```bash
# 使用密码解压 ZIP（自动选择目录）
python scripts/archive_analyzer.py encrypted.zip -p "password123"

# 指定提取目录
python scripts/archive_analyzer.py encrypted.zip -p "pwd" -d ./output

# 分析 + 解压（合并输出）
python scripts/archive_analyzer.py encrypted.zip -p "pwd" -d ./output --format json

# 邮件分析全链路（自动检测密码 → 保存附件 → 解压 → 推荐下游 skill）
python scripts/analyze_email.py suspicious.eml --save-attachments --format json

# 指定附件保存目录
python scripts/analyze_email.py suspicious.eml --output-dir ./attachments
```

### 输出字段说明

#### archive_analyzer.py 提取输出

```json
{
  "extraction": {
    "archive_path": "/path/to/file.zip",
    "extract_dir": "/path/to/file_extracted/",
    "password_used": true,
    "extracted_files": [
      {
        "path": "/path/to/file_extracted/document.eml",
        "original_name": "document.eml",
        "filename": "document.eml",
        "size": 12345,
        "extension": ".eml",
        "file_type": "unknown",
        "md5": "...",
        "sha256": "..."
      }
    ],
    "errors": []
  }
}
```

#### analyze_email.py `--save-attachments` 输出新增字段

```json
{
  "attachments": [
    {
      "filename": "encrypted.zip",
      "saved_path": "/path/to/attachments_email/encrypted.zip",
      "archive_encrypted": true,
      "extracted_files": [
        {
          "path": "/path/to/attachments_email/encrypted_contents/inner.eml",
          "filename": "inner.eml",
          "file_type": "unknown",
          "sha256": "..."
        }
      ],
      "extraction_password": "123456",
      "extraction_errors": []
    }
  ],
  "recommended_skills": [
    {
      "skill": "phishing-analysis",
      "reason": "已提取邮件需要递归分析: inner.eml",
      "targets": ["inner.eml"],
      "saved_path": "/path/to/.../inner.eml",
      "priority": "high"
    }
  ]
}
```

### 安全措施

| 防护项 | 说明 |
|--------|------|
| 路径穿越 (Zip Slip) | 文件名清理 + `resolve().relative_to()` 校验 |
| 解压炸弹 (Zip Bomb) | 单文件 500MB 上限，总量 2GB 上限 |
| 符号链接攻击 | ZIP/RAR/7z 均检测并拒绝符号链接条目 |
| 压缩比异常 | 单文件压缩比 > 50:1 记录警告 |
| 磁盘空间 | 提取前检查至少 100MB 可用空间 |
| 临时文件 | `try/finally` 确保清理 |
| 密码编码 | ZIP 密码尝试 utf-8 → gbk → latin-1 |
| 密码数量 | 候选密码限制最多 10 个 |

### 向后兼容

| 调用方式 | 行为 |
|---------|------|
| `archive_analyzer.py file.zip`（无新参数） | 与原来完全一致：只做元数据分析 |
| `analyze_email.py email.eml`（无新参数） | 与原来完全一致：不保存附件 |
| `analyze_email.py email.eml --save-attachments` | **新**：落盘 + 自动解压 + 推荐 |
| `archive_analyzer.py file.zip -p X -d ./out` | **新**：密码解压 + 文件列表输出 |
