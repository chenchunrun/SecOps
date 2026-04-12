# macOS ATT&CK 技术详解

基于 MITRE ATT&CK macOS 矩阵的关键技术检测指南。

## 执行 (Execution)

### T1059.002 - AppleScript

**描述**: 使用 osascript 执行 AppleScript 代码

**恶意用途**:
- 显示假密码弹窗窃取凭据
- 执行系统命令
- 与 GUI 交互

**检测**:
```vql
SELECT Pid, CommandLine FROM pslist()
WHERE CommandLine =~ 'osascript.*-e|osascript.*display dialog'
```

**示例恶意命令**:
```bash
osascript -e 'display dialog "macOS needs to access System Settings" default answer "" with hidden answer'
```

---

### T1059.004 - Unix Shell

**描述**: 通过 bash/zsh/sh 执行命令

**恶意用途**:
- 下载执行远程脚本
- 反弹 Shell
- 命令混淆

**检测**:
```vql
SELECT Pid, CommandLine FROM pslist()
WHERE CommandLine =~ 'bash -[ci]|zsh -[ci]|sh -c.*curl|sh -c.*wget'
```

---

## 持久化 (Persistence)

### T1543.001 - Launch Agent

**描述**: 创建 LaunchAgent 在用户登录时自动执行

**位置**:
- `/Library/LaunchAgents/` (所有用户)
- `~/Library/LaunchAgents/` (当前用户)

**检测**:
```vql
SELECT FullPath, Mtime FROM glob(globs=[
  '/Library/LaunchAgents/*.plist',
  '/Users/*/Library/LaunchAgents/*.plist'
]) WHERE Mtime > now() - 604800
```

**可疑特征**:
- 以点开头 (隐藏)
- ProgramArguments 包含 curl/wget/python/osascript
- StartInterval < 60 秒

---

### T1543.004 - Launch Daemon

**描述**: 创建 LaunchDaemon 在系统启动时以 root 执行

**位置**:
- `/Library/LaunchDaemons/`
- `/System/Library/LaunchDaemons/`

**检测**: 类似 LaunchAgent，重点关注非 Apple 签名

---

### T1547.015 - Login Items

**描述**: 添加登录项在用户登录时自动启动

**位置**:
```
~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm
```

---

## 权限提升 (Privilege Escalation)

### T1548.004 - Elevated Execution with Prompt

**描述**: 通过 osascript 或 AuthorizationExecuteWithPrivileges 获取权限

**检测**:
```vql
SELECT Pid, CommandLine FROM pslist()
WHERE CommandLine =~ 'osascript.*administrator privileges|sudo.*-S'
```

---

## 防御规避 (Defense Evasion)

### T1553.001 - Gatekeeper Bypass

**描述**: 绕过 Gatekeeper 执行未签名应用

**技术**:
1. 移除 quarantine 属性: `xattr -d com.apple.quarantine`
2. 通过 Archive Utility 以外的工具解压
3. 使用命令行下载 (curl/wget 不设置 quarantine)

**检测**:
```vql
SELECT Pid, CommandLine FROM pslist()
WHERE CommandLine =~ 'xattr -d com.apple.quarantine|xattr -c'
```

---

### T1574.004 - Dylib Hijacking

**描述**: 通过 DYLD_INSERT_LIBRARIES 注入恶意动态库

**检测**:
```bash
ps eww -o pid,command | grep DYLD_INSERT_LIBRARIES
```

```vql
SELECT FullPath FROM glob(globs=['/tmp/*.dylib', '/Users/*/.*.dylib'])
```

**防护**: Hardened Runtime 和 Library Validation 可防止此攻击

---

### T1564.001 - Hidden Files and Directories

**描述**: 使用以点开头的文件名隐藏恶意文件

**检测**:
```vql
SELECT FullPath, Mtime FROM glob(globs=['/tmp/.*', '/Users/*/.*'])
WHERE NOT FullPath =~ '(DS_Store|Trash|zsh|bash)'
```

---

### T1562.001 - Disable or Modify Tools

**描述**: 禁用安全工具如 SIP

**检测**:
```bash
csrutil status
# 正常: System Integrity Protection status: enabled.
```

---

## 凭据访问 (Credential Access)

### T1555.001 - Keychain

**描述**: 从 macOS Keychain 窃取凭据

**工具**: `security` 命令

**检测**:
```vql
SELECT Pid, CommandLine FROM pslist()
WHERE CommandLine =~ 'security find-.*password|security dump-keychain|security export'
```

**恶意命令示例**:
```bash
security find-generic-password -a "account" -s "service" -w
security dump-keychain -d login.keychain
```

---

### T1555.003 - Credentials from Web Browsers

**描述**: 窃取浏览器保存的凭据

**目标文件**:
| 浏览器 | 凭据文件 |
|--------|----------|
| Chrome | `~/Library/Application Support/Google/Chrome/*/Login Data` |
| Firefox | `~/Library/Application Support/Firefox/Profiles/*/logins.json` |
| Safari | `~/Library/Safari/LocalStorage/*` |

---

## 发现 (Discovery)

### T1082 - System Information Discovery

**描述**: 收集系统信息用于环境识别

**常用命令**:
```bash
system_profiler SPSoftwareDataType
sw_vers
uname -a
```

**检测**:
```vql
SELECT Pid, CommandLine FROM pslist()
WHERE CommandLine =~ 'system_profiler|sw_vers|uname'
```

---

## 命令与控制 (C2)

### T1571 - Non-Standard Port

**描述**: 使用非标准端口进行 C2 通信

**常见 C2 端口**: 4444, 5555, 6666, 1337, 31337, 8443

**检测**:
```vql
SELECT Pid, Name, Laddr FROM netstat()
WHERE Status = 'LISTEN'
AND Laddr.Port IN (4444, 5555, 6666, 1337, 31337)
```

---

## TCC 相关攻击

### TCC 概述

TCC (Transparency, Consent, and Control) 控制应用对敏感数据的访问:
- 摄像头/麦克风
- 屏幕录制
- 完全磁盘访问
- 通讯录/日历/照片

### TCC 数据库位置
```
/Library/Application Support/com.apple.TCC/TCC.db (系统级)
~/Library/Application Support/com.apple.TCC/TCC.db (用户级)
```

### 2024 TCC 绕过 (CVE-2024-44131, CVE-2024-44133)

**检测 TCC 数据库变更**:
```vql
SELECT FullPath, Mtime FROM glob(globs='*/com.apple.TCC/TCC.db')
WHERE Mtime > now() - 604800
```

**检测可疑 TCC 权限**:
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, service, auth_value FROM access WHERE auth_value = 2;"
```

---

## 检测优先级

| 优先级 | 技术 | 原因 |
|--------|------|------|
| P0 | T1059.002 AppleScript | 2024 年最常见窃取技术 |
| P0 | T1543.001 Launch Agent | 最常见持久化方式 |
| P0 | T1555.001 Keychain | 凭据窃取核心目标 |
| P1 | T1553.001 Gatekeeper Bypass | 恶意软件落地 |
| P1 | T1574.004 Dylib Hijacking | 高级攻击技术 |
| P2 | T1564.001 Hidden Files | 隐藏恶意活动 |
| P2 | T1562.001 Disable Tools | 防护被禁用 |

---

## 参考链接

- [MITRE ATT&CK macOS Matrix](https://attack.mitre.org/matrices/enterprise/macos/)
- [Launch Agent T1543.001](https://attack.mitre.org/techniques/T1543/001/)
- [Gatekeeper Bypass T1553.001](https://attack.mitre.org/techniques/T1553/001/)
- [Dylib Hijacking T1574.004](https://attack.mitre.org/techniques/T1574/004/)
