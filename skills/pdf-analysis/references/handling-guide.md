# PDF 威胁处置指南

## 风险评分矩阵

| 发现 | 分数 | 说明 |
|------|------|------|
| `/JavaScript` 存在 | +25 | 脚本可能触发漏洞 |
| JavaScript 包含 `eval/unescape` | +35 | 混淆的恶意代码 |
| `/Launch` 动作 | +40 | 可启动外部程序 |
| `/EmbeddedFile` 是可执行文件 | +40 | 嵌入恶意软件 |
| 检测到 CVE 特征 | +50 | 已知漏洞利用 |
| URL 指向可执行文件 | +30 | 下载恶意软件 |
| 钓鱼话术 + 可疑 URL | +25 | 钓鱼诱导 |
| 空白/可疑 Creator | +10 | 来源不明 |
| 密码保护 | +15 | 可能隐藏恶意内容 |

---

## 处置方案

### 🟢 低风险 (0-20分) - 正常使用

**判断**: 未发现恶意特征，来源可信

**处置**:
- 可以正常打开使用
- 如有外部链接，点击前确认 URL 合法性
- 如有表单，确认提交目标可信

---

### 🟡 中风险 (21-40分) - 谨慎处理

**判断**: 存在可疑特征，但未确认恶意

**处置**:

1. **验证来源**
   - 联系发件人确认是否本人发送
   - 检查邮件头确认发件源

2. **安全打开**
   ```bash
   # macOS: 用预览打开（比 Adobe Reader 更安全）
   open -a Preview sample.pdf

   # 或转换为图片查看
   pdftoppm sample.pdf output -png
   open output-1.png
   ```

3. **如需编辑**
   - 使用 LibreOffice 或在线 PDF 工具
   - 避免使用 Adobe Reader 打开含 JavaScript 的 PDF

---

### 🟠 高风险 (41-70分) - 沙箱分析

**判断**: 高度可疑，可能是恶意文件

**处置**:

1. **立即隔离**
   ```bash
   # 移动到隔离目录
   mkdir -p ~/quarantine
   mv sample.pdf ~/quarantine/
   chmod 000 ~/quarantine/sample.pdf
   ```

2. **沙箱分析**
   ```bash
   # 上传到在线沙箱
   # - VirusTotal: https://www.virustotal.com
   # - Hybrid Analysis: https://hybrid-analysis.com
   # - ANY.RUN: https://any.run

   # 或本地 Docker 沙箱
   docker run --rm -v $(pwd):/data remnux/remnux-distro pdfid.py /data/sample.pdf
   ```

3. **提取 IOC 并查询**
   ```bash
   # 提取 URL/域名
   python3 pdf_scan.py -j sample.pdf | jq '.urls.all[]'

   # 查询威胁情报
   # - VirusTotal API
   # - AbuseIPDB
   # - URLhaus
   ```

4. **通知安全团队**
   - 提交工单/告警
   - 附上分析报告和 IOC

---

### 🔴 严重风险 (71+分) - 确认恶意

**判断**: 确认为恶意文件

**处置**:

1. **立即隔离并取证**
   ```bash
   # 计算哈希（取证证据）
   shasum -a 256 sample.pdf > sample.pdf.sha256

   # 压缩加密保存（密码: infected）
   zip -e -P infected malware_sample.zip sample.pdf

   # 移动到隔离区
   mv malware_sample.zip ~/quarantine/
   ```

2. **阻断传播**
   - 邮件网关加黑发件人/域名
   - 防火墙阻断 IOC 中的 IP/域名
   - EDR 添加文件哈希到黑名单

3. **威胁狩猎**
   ```bash
   # 搜索同源文件
   # 在邮件日志中搜索相同发件人
   # 在文件服务器搜索相同哈希

   # 检查是否有用户已打开
   # 查看 EDR/SIEM 告警
   ```

4. **事件响应**
   - 如有用户已打开：启动事件响应流程
   - 检查该主机是否有后续恶意行为
   - 必要时隔离受感染主机

5. **情报共享**
   ```bash
   # 提交样本到威胁情报平台
   # - VirusTotal
   # - MalwareBazaar
   # - 内部威胁情报平台

   # 生成 IOC 报告供团队使用
   ```

6. **复盘与加固**
   - 分析投递渠道，加强防护
   - 更新检测规则
   - 安全意识培训（如有用户中招）

---

## 特定威胁类型处置

### 钓鱼型 PDF

```bash
# 1. 提取所有 URL
python3 pdf_scan.py -j sample.pdf | jq '.urls'

# 2. 检查 URL 是否已知恶意
# 提交到 VirusTotal/URLhaus

# 3. 如用户已点击
# - 检查浏览器历史
# - 检查是否输入了凭据
# - 必要时重置密码
```

### 漏洞利用型 PDF

```bash
# 1. 确认 CVE
python3 pdf_scan.py -j sample.pdf | jq '.cve_detected'

# 2. 检查 PDF Reader 版本
# - 确认是否受影响
# - 紧急更新到最新版本

# 3. 如用户已打开
# - 立即隔离主机
# - 全盘杀毒扫描
# - 检查是否有后门
```

### 恶意载荷型 PDF

```bash
# 1. 提取嵌入文件（安全环境）
python3 pdf_extract.py sample.pdf --files

# 2. 分析提取的文件
file extracted/files/*
shasum -a 256 extracted/files/*

# 3. 上传到 VirusTotal 确认
# 4. 如是已知恶意软件，按对应处置流程
```

---

## 分析报告模板

```markdown
## PDF 安全分析报告

**文件**: [文件名]
**SHA256**: [哈希值]
**分析时间**: [时间]

### 基本信息
- 大小: X bytes
- PDF 版本: 1.x
- 创建工具: [Creator]
- 加密: 是/否

### 威胁评估
**风险等级**: 🔴/🟠/🟡/🟢
**威胁类型**: [漏洞利用/钓鱼诱导/恶意载荷/无]

### 发现的问题
1. [问题描述]
2. [问题描述]

### 详细分析
[分析过程和发现]

### IOC
- URL: [...]
- 域名: [...]
- 文件哈希: [...]

### 结论与建议
[最终判断和处置建议]
```
