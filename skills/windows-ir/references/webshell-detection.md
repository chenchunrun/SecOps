# Webshell 检测参考文档

> **本文档定位**：对 SKILL.md Phase 5 的补充说明，阐述检测原理、评级标准和应急响应流程。
> **实际检测操作**：请使用 `scripts/find_web_dirs.py` 和 `scripts/webshell_check.py` 自动化脚本，不要手动执行本文档的示例命令。

---

## 使用说明

### 自动化检测流程

```powershell
# 定义技能目录
$SKILL_DIR = "$HOME\.cybersec\skills\windows-ir"

# 第一步：自动发现 Web 目录
python "$SKILL_DIR\scripts\find_web_dirs.py"

# 第二步：深度扫描 Webshell
python "$SKILL_DIR\scripts\webshell_check.py" --deep
```

### 脚本功能说明

| 脚本 | 功能 | 输出 |
|------|------|------|
| `find_web_dirs.py` | 5层机制自动发现 IIS/Apache/Nginx/Tomcat/PHPStudy 等 Web 目录 | 生成 `config/web_paths.txt` |
| `webshell_check.py` | 8层检测引擎扫描可疑文件，进程行为监控，IIS 日志关联 | 控制台彩色输出 + 可选 JSON 报告 |

---

## 目录

1. [威胁评级标准](#1-威胁评级标准)
2. [8层检测设计原理](#2-8层检测设计原理)
3. [检测报告模板](#3-检测报告模板)
4. [误报处理指南](#4-误报处理指南)
5. [应急响应流程](#5-应急响应流程)

---

## 1. 威胁评级标准

### 1.1 评级分类

| 等级 | 判定条件 | 风险描述 | 响应时效 |
|------|---------|---------|---------|
| **严重** | 工具指纹匹配 + IIS日志确认访问 | 确认入侵，可能已失陷 | 立即处置 |
| **高危** | 得分 ≥ 80 或 3+ 可疑特征组合 | 高度疑似后门 | 2小时内 |
| **中危** | 得分 50-79 | 需人工分析代码逻辑 | 24小时内 |
| **低危** | 得分 < 50 | 可能为合法功能 | 3天内验证 |
| **信息** | 仅时间异常 | 需核对变更记录 | 记录备查 |

### 1.2 评分计算

```
总分 = Σ(触发特征的权重)

if 工具指纹匹配:
    威胁等级 = 严重
elif 总分 ≥ 80:
    威胁等级 = 高危
elif 总分 50-79:
    威胁等级 = 中危
else:
    威胁等级 = 低危
```

**特征权重示例**：
- 工具指纹（菜刀/蚁剑/冰蝎/哥斯拉）: 100（直接定级严重）
- eval + base64 编码混淆: 30
- Socket + eval 反向Shell: 35
- ProcessStartInfo 命令执行: 25
- IIS 日志异常访问: 25
- w3wp.exe 异常子进程: 35

---

## 2. 8层检测设计原理

### 2.1 设计理念

**为什么需要 8 层检测？**

单一特征检测容易产生误报（如合法代码编辑器也包含 eval），多维度关联分析可提高准确率：
- **静态特征**（层 1-6）：文件内容、命名、属性
- **动态行为**（层 7-8）：访问日志、进程活动

### 2.2 8层检测架构

| 层级 | 检测维度 | 检测内容 | 示例特征 | 权重 |
|------|---------|---------|---------|------|
| **1. 工具指纹** | 静态代码 | 已知 Webshell 工具特征码 | `z0=Request`（菜刀）<br>`antSword`（蚁剑） | 100 |
| **2. 高危函数** | 静态代码 | eval/Execute/Runtime.exec 等 | `eval(base64_decode(...))` | 30 |
| **3. 文件名异常** | 文件系统 | shell.php / 1.aspx / cmd.asp | `upload_shell.php` | 20 |
| **4. 时间异常** | 文件系统 | 凌晨 2-5 点创建 + 可疑函数 | 2026-01-10 03:15 创建 | 15 |
| **5. 权限异常** | 文件系统 | 可写 + 可执行权限 | Everyone Full Control | 10 |
| **6. 大小异常** | 文件系统 | < 5KB 但包含高危函数 | 2KB 文件包含 eval | 10 |
| **7. 日志关联** | 行为分析 | IIS 访问记录 + 异常 User-Agent | User-Agent: Behinder/3.0 | 25 |
| **8. 进程行为** | 行为分析 | w3wp.exe → cmd.exe 子进程 | 父子进程异常关系 | 35 |

### 2.3 核心检测技术

#### 工具指纹识别（层 1）

主流 Webshell 工具特征：

| 工具 | 版本 | 关键特征 | 通信加密 |
|------|------|---------|---------|
| **中国菜刀** | 2011-2016 | `z0=Request` / `<%eval request` | 明文 |
| **蚁剑** | 2.x-4.x | `@ini_set("display_errors","0")` / `antSword` | AES 可选 |
| **冰蝎** | 3.x-4.x | `@session_start();@set_time_limit(0);` | AES-128 |
| **哥斯拉** | 3.x-4.x | `$pass='pass';$md5=md5($pass)` | AES/XOR |
| **Weevely** | 3.x | `$kh="[32位十六进制]";$kf="[32位十六进制]"` | RC4 |

#### 高危函数模式（层 2）

按语言分类的命令执行特征：

**ASP/ASPX**:
- `eval()` - 动态代码执行
- `Execute()` - VBScript 执行
- `System.Diagnostics.Process` - 进程启动
- `ProcessStartInfo` - 命令执行
- `Server.CreateObject("WScript")` - COM 对象

**PHP**:
- `eval()` - 变量执行
- `system/exec/passthru/shell_exec` - 系统命令
- `base64_decode() + eval()` - 编码混淆
- `assert()` - 断言执行
- `preg_replace(/.../e)` - 正则执行（旧版）

**JSP**:
- `Runtime.getRuntime().exec()` - Java 命令执行
- `ProcessBuilder` - 进程构建
- `ClassLoader.loadClass()` - 动态类加载

#### 行为关联检测（层 7-8）

**IIS 日志可疑模式**:
- POST 请求 + 200 响应 + 异常 User-Agent（Python-urllib, Behinder, antSword）
- 同一 IP 短时间（1分钟）内 > 20 次访问同一脚本
- 请求体积异常（POST body > 10KB）
- 响应时间过长（time-taken > 5000ms）

**进程行为可疑模式**:
- `w3wp.exe` → `cmd.exe /c [命令]`
- `w3wp.exe` → `powershell.exe -enc [BASE64]`
- 执行侦察命令：`whoami`, `net user`, `ipconfig`

---

## 3. 检测报告模板

### 3.1 脚本输出格式

```
=== Windows Webshell Detection Tool ===
Scan mode: Deep
Time range: Last 30 days

[Process Check] Detecting w3wp.exe suspicious child processes...
  [+] No suspicious child processes found

Scan directories:
  - E:\phpstudy\phpstudy_pro\www
  - E:\tomcat\apache-tomcat-9.0.2\webapps

[SCAN] E:\phpstudy\phpstudy_pro\www
  Found 67 web script files (depth: 5)
  [Critical] upload/conn.aspx (Score: 100)
    - Tool Signature: Behinder 3.0 (@session_start + AES encryption)
    - IIS Log: 192.168.1.100 访问 120 次
    - User-Agent: Mozilla/5.0 (compatible; Behinder/3.0)
  [High] admin/shell.php (Score: 85)
    - Functions: eval + base64_decode
    - Filename: shell.php (suspicious keyword)
    - Created: 2026-01-10 03:22 (凌晨异常)
  [Low] include/cache.php (Score: 25)
    - Functions: exec (可能为合法缓存清理功能)

========================================
Detection Results Summary
========================================
Total files scanned: 67
Suspicious files found: 3

Classification by threat level:
  Critical: 1
  High:     1
  Medium:   0
  Low:      1
  Info:     0
```

### 3.2 IOC 汇总格式

```markdown
## 入侵指标 (Indicators of Compromise)

### 文件 IOC
| 文件路径 | SHA256 | 创建时间 | 工具类型 | 威胁等级 |
|---------|--------|---------|---------|---------|
| E:\phpstudy\www\upload\conn.aspx | a1b2c3d4e5f6... | 2026-01-10 02:35 | 冰蝎 3.0 | 严重 |
| E:\phpstudy\www\admin\shell.php | b2c3d4e5f6a1... | 2026-01-10 03:22 | 自定义 | 高危 |

### 网络 IOC
| 攻击者IP | 访问目标 | 访问次数 | 首次访问 | 最后访问 |
|---------|---------|---------|---------|---------|
| 192.168.1.100 | conn.aspx | 120 | 2026-01-10 03:15 | 2026-01-12 14:30 |
| 10.0.0.50 | shell.php | 35 | 2026-01-11 08:20 | 2026-01-11 16:45 |

### 进程 IOC
| 父进程 | 子进程 | 命令行 | 执行时间 |
|-------|-------|-------|---------|
| w3wp.exe (1234) | cmd.exe | cmd /c whoami | 2026-01-10 03:16:22 |
| w3wp.exe (1234) | powershell.exe | powershell -enc ... | 2026-01-10 03:18:45 |
```

### 3.3 ATT&CK 映射

| 战术 (Tactic) | 技术 (Technique) | 子技术 | 证据 |
|--------------|-----------------|--------|------|
| **初始访问** | T1190 - Exploit Public-Facing Application | - | 上传点漏洞利用 |
| **执行** | T1059 - Command and Scripting Interpreter | .003 - Windows Command Shell | IIS 日志显示命令执行 |
| **持久化** | T1505 - Server Software Component | .003 - Web Shell | conn.aspx, shell.php |
| **发现** | T1083 - File and Directory Discovery | - | 执行 dir/whoami |
| **命令与控制** | T1071 - Application Layer Protocol | .001 - Web Protocols | HTTP POST 加密通信 |

---

## 4. 误报处理指南

### 4.1 常见误报场景

| 场景 | 触发特征 | 识别方法 | 处理建议 |
|------|---------|---------|---------|
| **在线代码编辑器** | eval() + 编辑器 UI | 检查路径包含 /editor/ /ide/ | 核对是否为官方组件 |
| **CMS 核心文件** | WordPress/Drupal 包含 eval | 对比官方文件哈希 | 使用官方工具验证完整性 |
| **数据库管理工具** | PHPMyAdmin/Adminer 包含 exec | 检查是否为已知工具 | 确认版本和用途后放行 |
| **开发调试工具** | phpinfo(), var_dump() | 路径包含 docs/demo/test | 确认为测试文件后移出生产环境 |
| **备份文件** | backup/old_code.php.bak | 扩展名非标准可执行格式 | 移出 Web 目录或删除 |
| **模板缓存** | Smarty/Twig 编译文件 | 路径包含 /cache/ /temp/ | 排除缓存目录 |

### 4.2 验证流程

**发现可疑文件后的验证步骤**：

1. **查看文件哈希** → VirusTotal / 官方文件库对比
2. **阅读完整代码** → 理解上下文逻辑，确认是否为合法功能
3. **检查 IIS 日志** → 是否有外部访问记录
4. **联系开发团队** → 核对变更记录、工单、部署历史

### 4.3 白名单管理（未来功能）

计划支持配置 `config/whitelist.txt` 排除已知合法文件：

```
# SHA256 哈希白名单（每行一个）
a1b2c3d4e5f6...  # WordPress wp-includes/class-json.php
b2c3d4e5f6a1...  # PHPMyAdmin 5.1.0 setup.php
```

---

## 5. 应急响应流程

### 5.1 确认阶段

**快速验证检查清单**：
- [ ] 查看 IIS 日志确认文件被外部访问
- [ ] 检查文件创建时间是否异常（凌晨/非工作时间）
- [ ] 阅读代码确认包含明显恶意逻辑
- [ ] 询问开发团队是否为合法部署

### 5.2 隔离阶段

**重要原则**：不要直接删除，需保留证据！

**隔离步骤**：
1. **创建隔离目录** → `C:\Quarantine\20260112_153000`
2. **计算文件哈希** → 记录 SHA256 用于后续分析
3. **复制到隔离区** → 保留原始证据
4. **阻止 IIS 访问** → 使用 `icacls` 拒绝 IIS_IUSRS 读权限
5. **可选：停止应用池** → 根据业务影响决定

**参考命令**（具体操作见 `webshell_check.py` 生成的建议）：
```powershell
# 创建隔离目录并复制证据
$quarantineDir = "C:\Quarantine\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $quarantineDir -Force
Copy-Item "Webshell路径" -Destination $quarantineDir

# 阻止 IIS 访问（不删除文件）
icacls "Webshell路径" /deny "IIS_IUSRS:(R)"
```

### 5.3 溯源调查

**调查重点**：
1. **查找同目录其他可疑文件** → 按修改时间排序
2. **分析 IIS 日志找上传点** → 搜索 POST/PUT 到 upload 相关路径
3. **提取攻击时间线** → 根据攻击者 IP 筛选所有活动
4. **检查进程历史** → 查看是否有命令执行痕迹

### 5.4 修复加固

**识别入侵途径**：
- 文件上传漏洞（未验证扩展名/MIME 类型）
- CMS/第三方组件漏洞（FCKeditor, ThinkPHP 历史漏洞）
- 弱密码后台（管理员密码被爆破）
- SQL 注入写入文件（`INTO OUTFILE`）

**加固措施**：
1. **修复上传功能** → 白名单验证扩展名 + 文件头校验 + 重命名上传文件
2. **配置 IIS Request Filtering** → 阻止 .asa / .cer 等非标准扩展名
3. **上传目录禁止执行** → 设置 Handler 仅允许静态文件访问
4. **删除 Web 目录写入权限** → 移除 IIS_IUSRS 写权限
5. **启用实时防护** → Windows Defender / 第三方 EDR

### 5.5 持续监控

**建议措施**：
- 定期运行 `webshell_check.py` 扫描（建议每日凌晨 2 点）
- 启用完整 IIS 日志记录（包含 User-Agent, 请求耗时）
- 配置异常访问告警（单 IP 高频访问 / 异常 User-Agent）
