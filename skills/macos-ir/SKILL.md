---
name: macos-ir
description: macOS 入侵检查与应急响应。当用户要求"macOS入侵检查"、"Mac应急响应"、"Mac后门检测"、"LaunchAgent检查"、"Mac持久化检测"、"Mac异常进程"时使用此技能。
metadata:
  version: 2.0.0
  builtin: true
---

# macOS 入侵检查与威胁狩猎

使用 Velociraptor 本地模式执行 VQL 查询，结合 MITRE ATT&CK 框架检测 macOS 系统入侵迹象。

## 依赖

```bash
# Velociraptor (ARM64)
mkdir -p ~/tools/velociraptor
curl -L -o ~/tools/velociraptor/velociraptor \
  https://github.com/Velocidex/velociraptor/releases/download/v0.73.3/velociraptor-v0.73.3-darwin-arm64
chmod +x ~/tools/velociraptor/velociraptor
xattr -d com.apple.quarantine ~/tools/velociraptor/velociraptor 2>/dev/null

# Intel Mac
curl -L -o ~/tools/velociraptor/velociraptor \
  https://github.com/Velocidex/velociraptor/releases/download/v0.73.3/velociraptor-v0.73.3-darwin-amd64
```

## 统一入口 (必读)

**所有检查通过 `ir.sh` 执行，AI 只需调用此脚本：**

```bash
# 推荐：摘要报告 (5秒，10项关键检查)
bash <SKILL_DIR>/scripts/ir.sh

# 快速扫描 (30秒，详细输出)
bash <SKILL_DIR>/scripts/ir.sh quick

# 完整检查 (2-3分钟，所有模块)
bash <SKILL_DIR>/scripts/ir.sh full

# 其他模式: persistence | network | signature | forensic
bash <SKILL_DIR>/scripts/ir.sh help
```

**执行顺序建议**：
1. 先运行 `ir.sh` 查看摘要
2. 发现问题再运行 `ir.sh full` 深入检查
3. 根据发现使用下方 VQL 手动查询取证

---

## 阶段 1: 进程狩猎

### 基础进程检查

```bash
# 所有进程
$VR query "SELECT Pid, Ppid, Name, Exe, CommandLine, Username FROM pslist()"

# 可疑进程（临时目录/隐藏名/可疑命令行）
$VR query "SELECT Pid, Name, Exe, CommandLine FROM pslist() WHERE Exe =~ '/tmp/|/private/tmp|/var/folders' OR Name =~ '^\\.' OR CommandLine =~ 'base64|curl.*\\|.*sh|wget.*\\|.*bash|osascript.*-e'"

# 非系统路径进程
$VR query "SELECT Pid, Name, Exe FROM pslist() WHERE NOT Exe =~ '^/System|^/usr/|^/Applications|^/Library'"
```

### 高级进程狩猎 (ATT&CK T1059)

```bash
# osascript 凭据窃取检测 (Cuckoo/Atomic/Banshee Stealer 特征)
$VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE CommandLine =~ 'osascript.*display dialog|osascript.*-e.*password|hidden answer'"

# Python/Ruby/Perl 可疑执行
$VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE (Name =~ 'python|ruby|perl') AND (CommandLine =~ 'http|socket|subprocess|exec|eval')"

# 编码命令检测
$VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE CommandLine =~ 'base64 -[dD]|openssl.*enc|xxd'"

# 反弹 Shell 特征
$VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE CommandLine =~ '/dev/tcp|nc -e|bash -i|zsh -i|0<&196'"
```

### Dylib 注入检测 (ATT&CK T1574.006)

```bash
# 检测 DYLD_INSERT_LIBRARIES 环境变量
ps eww -o pid,command | grep DYLD_INSERT

# 查找可疑 dylib 文件
$VR query "SELECT FullPath, Mtime, Size FROM glob(globs=['/tmp/*.dylib', '/private/tmp/*.dylib', '/Users/*/.*.dylib', '/var/folders/**/*.dylib'])"
```

---

## 阶段 2: 网络狩猎

### 基础网络检查

```bash
# 所有连接
$VR query "SELECT Pid, Name, Laddr, Raddr, Status FROM netstat()"

# 监听端口
$VR query "SELECT Pid, Name, Laddr FROM netstat() WHERE Status = 'LISTEN'"

# 外部连接（排除本地/苹果 CDN）
$VR query "SELECT Pid, Name, Raddr FROM netstat() WHERE Status = 'ESTABLISHED' AND NOT Raddr.IP =~ '^(127\\.|10\\.|192\\.168\\.|17\\.|172\\.16)'"
```

### 高级网络狩猎

```bash
# 高危端口监听 (C2/反弹Shell)
$VR query "SELECT Pid, Name, Laddr FROM netstat() WHERE Status = 'LISTEN' AND Laddr.Port IN (4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 1234, 12345)"

# 非标准端口外连
lsof -i -n -P 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1\|::1\|:443\|:80\|:22\|:53"

# DNS 隧道检测 (大量 DNS 查询)
$VR query "SELECT Pid, Name, Raddr FROM netstat() WHERE Raddr.Port = 53 AND Status = 'ESTABLISHED'"
```

---

## 阶段 3: 持久化狩猎 (ATT&CK TA0003)

### LaunchAgents / LaunchDaemons (T1543.001/T1543.004)

```bash
# 系统级
$VR query "SELECT FullPath, Mtime, Size FROM glob(globs=['/Library/LaunchAgents/*.plist', '/Library/LaunchDaemons/*.plist'])"

# 用户级
$VR query "SELECT FullPath, Mtime, Size FROM glob(globs='/Users/*/Library/LaunchAgents/*.plist')"

# 最近 7 天新增
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/Library/LaunchAgents/*.plist', '/Library/LaunchDaemons/*.plist', '/Users/*/Library/LaunchAgents/*.plist']) WHERE Mtime > now() - 604800"

# 隐藏的 LaunchAgent (以点开头)
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/Library/LaunchAgents/.*.plist', '/Library/LaunchDaemons/.*.plist', '/Users/*/Library/LaunchAgents/.*.plist'])"
```

### 高级持久化检测

```bash
# 可疑 plist 内容分析 (查找恶意特征)
for plist in /Library/Launch*/*.plist ~/Library/LaunchAgents/*.plist; do
  if plutil -p "$plist" 2>/dev/null | grep -qE 'curl|wget|python|osascript|base64|/tmp/'; then
    echo "[!] 可疑: $plist"
    plutil -p "$plist" | grep -E 'Program|Label|StartInterval'
  fi
done

# Overrides.plist 滥用检测 (高级持久化)
$VR query "SELECT FullPath, Mtime FROM glob(globs='/var/db/launchd.db/*/overrides.plist')"

# Login Items (T1547.015)
$VR query "SELECT FullPath, Mtime FROM glob(globs='/Users/*/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm')"
```

### 其他持久化机制

```bash
# Crontab
crontab -l 2>/dev/null
ls -la /var/at/tabs/ 2>/dev/null

# Periodic 脚本
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/etc/periodic/daily/*', '/etc/periodic/weekly/*', '/etc/periodic/monthly/*'])"

# 内核扩展 (T1547.006)
$VR query "SELECT FullPath, Mtime FROM glob(globs='/Library/Extensions/*.kext')"
kextstat | grep -v com.apple

# 系统扩展
systemextensionsctl list 2>/dev/null

# Authorization 插件 (T1547.002)
$VR query "SELECT FullPath FROM glob(globs='/Library/Security/SecurityAgentPlugins/*')"

# 登录/注销 Hooks
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/Users/*/Library/Preferences/com.apple.loginwindow.plist', '/Library/Preferences/com.apple.loginwindow.plist'])"
```

---

## 阶段 4: 凭据窃取检测 (ATT&CK TA0006)

### Keychain 访问 (T1555.001)

```bash
# 检测 security 命令滥用
$VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE CommandLine =~ 'security find-.*password|security dump-keychain'"

# Keychain 文件访问时间
$VR query "SELECT FullPath, Mtime FROM glob(globs='/Users/*/Library/Keychains/*')"
```

### 浏览器凭据 (T1555.003)

```bash
# Chrome 凭据
$VR query "SELECT FullPath, Mtime FROM glob(globs='/Users/*/Library/Application Support/Google/Chrome/*/Login Data')"

# Safari 凭据
$VR query "SELECT FullPath, Mtime FROM glob(globs='/Users/*/Library/Safari/LocalStorage/*')"

# Firefox 凭据
$VR query "SELECT FullPath, Mtime FROM glob(globs='/Users/*/Library/Application Support/Firefox/Profiles/*/logins.json')"
```

### osascript 钓鱼检测 (2024 Stealer 常用)

```bash
# 检测假密码弹窗
$VR query "SELECT Pid, CommandLine FROM pslist() WHERE CommandLine =~ 'display dialog.*password|System Preferences|System Settings'"

# 历史命令检查
grep -r "osascript.*password\|display dialog" ~/.zsh_history ~/.bash_history 2>/dev/null
```

---

## 阶段 5: 防御规避检测 (ATT&CK TA0005)

### TCC 绕过检测 (T1548)

```bash
# TCC 数据库检查
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/Library/Application Support/com.apple.TCC/TCC.db', '/Users/*/Library/Application Support/com.apple.TCC/TCC.db'])"

# 可疑 TCC 权限授予
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT client, service, auth_value FROM access WHERE auth_value = 2;" 2>/dev/null

# 检测 TCC 目录写入
$VR query "SELECT FullPath, Mtime FROM glob(globs='/Users/*/Library/Application Support/com.apple.TCC/*') WHERE Mtime > now() - 604800"
```

### Gatekeeper 绕过检测 (T1553.001)

```bash
# 检测 quarantine 属性移除
$VR query "SELECT Pid, CommandLine FROM pslist() WHERE CommandLine =~ 'xattr -d com.apple.quarantine|xattr -c'"

# 下载应用检查 quarantine
find ~/Downloads -name "*.app" -exec xattr -l {} \; 2>/dev/null | grep -L "com.apple.quarantine"
```

### SIP 状态检查

```bash
csrutil status
# 正常应为: System Integrity Protection status: enabled.
```

### 隐藏文件/进程 (T1564)

```bash
# 隐藏扩展属性文件
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/tmp/.*', '/private/tmp/.*', '/Users/*/.*']) WHERE NOT FullPath =~ '(DS_Store|Trash|CFUserTextEncoding|zsh|bash)'"

# 资源 Fork 隐藏
$VR query "SELECT FullPath FROM glob(globs='/Users/**/..namedfork/rsrc')"
```

---

## 阶段 6: 用户与文件检查

### 用户检查

```bash
# 所有用户
dscl . -list /Users UniqueID

# UID=0 异常用户
dscl . -list /Users UniqueID | awk '$2 == 0 && $1 != "root" {print "[!] 异常 root 用户: " $1}'

# 管理员组
dscl . -read /Groups/admin GroupMembership

# SSH authorized_keys
$VR query "SELECT FullPath, Mtime, Size FROM glob(globs='/Users/*/.ssh/authorized_keys')"

# 最近登录
last -20
```

### 文件系统检查

```bash
# /tmp 可疑文件
$VR query "SELECT FullPath, Size, Mtime FROM glob(globs='/tmp/**') WHERE Size > 0 AND (FullPath =~ '\\.(sh|py|pl|dylib|so|app)$' OR Mode =~ 'x') LIMIT 50"

# 最近修改的可执行文件
$VR query "SELECT FullPath, Mtime FROM glob(globs='/usr/local/bin/*') WHERE Mtime > now() - 604800"

# 可疑下载
$VR query "SELECT FullPath, Mtime FROM glob(globs='/Users/*/Downloads/*.{sh,command,pkg,dmg,app,scpt}') WHERE Mtime > now() - 604800"
```

---

## 阶段 7: 浏览器扩展检查

```bash
# Chrome 扩展
$VR query "SELECT FullPath FROM glob(globs='/Users/*/Library/Application Support/Google/Chrome/*/Extensions/*')"

# Safari 扩展
$VR query "SELECT FullPath FROM glob(globs='/Users/*/Library/Safari/Extensions/*')"
```

---

## 2024 年高危威胁检测

### Cuckoo / Atomic / Banshee Stealer 特征

```bash
# 特征: osascript 密码窃取 + pw.dat 文件
$VR query "SELECT FullPath FROM glob(globs=['/tmp/pw.dat', '/private/tmp/pw.dat', '/Users/*/pw.dat'])"
$VR query "SELECT Pid, CommandLine FROM pslist() WHERE CommandLine =~ 'hidden answer'"

# 特征: system_profiler 信息收集
$VR query "SELECT Pid, CommandLine FROM pslist() WHERE CommandLine =~ 'system_profiler'"
```

### DPRK/Lazarus 供应链攻击特征

```bash
# 可疑的开发者工具进程
$VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE (Name =~ 'node|npm|python') AND (CommandLine =~ 'crypto|wallet|defi')"

# Tauri 框架恶意应用 (扩展属性隐藏)
$VR query "SELECT FullPath FROM glob(globs='/Applications/*.app/Contents/Resources/*') WHERE FullPath =~ 'pdf'"
```

### XProtect 状态检查

```bash
# XProtect 版本
system_profiler SPInstallHistoryDataType | grep -A5 "XProtect"

# XProtect 签名更新时间
ls -la /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/
```

---

## 快速研判流程

### 第一层: 快速扫描 (~30秒)

```bash
VR=~/tools/velociraptor/velociraptor

# 1. 可疑进程
$VR query "SELECT Pid, Name, Exe, CommandLine FROM pslist() WHERE Exe =~ '/tmp/|/private/tmp' OR Name =~ '^\\.' OR CommandLine =~ 'osascript.*-e|base64|curl.*\\|.*sh' LIMIT 10"

# 2. 异常外连
lsof -i -n -P 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1\|::1\|:443\|:80" | head -10

# 3. 高危监听
$VR query "SELECT Pid, Name, Laddr FROM netstat() WHERE Status = 'LISTEN' AND Laddr.Port IN (4444, 5555, 6666, 1337)"

# 4. 最近 LaunchAgent
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/Library/LaunchAgents/*.plist', '/Users/*/Library/LaunchAgents/*.plist']) WHERE Mtime > now() - 604800"
```

### 第二层: 深度检查 (~2分钟)

```bash
# 5. TCC 数据库变更
$VR query "SELECT FullPath, Mtime FROM glob(globs='*/com.apple.TCC/TCC.db') WHERE Mtime > now() - 604800"

# 6. Keychain 访问
$VR query "SELECT Pid, CommandLine FROM pslist() WHERE CommandLine =~ 'security find-.*password'"

# 7. 可疑 dylib
$VR query "SELECT FullPath FROM glob(globs=['/tmp/*.dylib', '/Users/*/.*.dylib'])"

# 8. SSH Keys
$VR query "SELECT FullPath, Mtime FROM glob(globs='/Users/*/.ssh/authorized_keys')"
```

---

## ATT&CK 映射表

| 战术 | 技术 ID | 技术名称 | 检测查询 |
|------|---------|----------|----------|
| 执行 | T1059.002 | AppleScript | osascript 进程 |
| 执行 | T1059.004 | Unix Shell | bash/zsh -c 参数 |
| 持久化 | T1543.001 | Launch Agent | LaunchAgents 目录 |
| 持久化 | T1543.004 | Launch Daemon | LaunchDaemons 目录 |
| 持久化 | T1547.015 | Login Items | backgrounditems.btm |
| 权限提升 | T1548.004 | Elevated Execution | sudo/osascript 滥用 |
| 防御规避 | T1553.001 | Gatekeeper Bypass | xattr quarantine |
| 防御规避 | T1574.004 | Dylib Hijacking | DYLD_INSERT_LIBRARIES |
| 凭据访问 | T1555.001 | Keychain | security 命令 |
| 凭据访问 | T1555.003 | Browser Credentials | Login Data 文件 |

---

## 高危指标速查

| 检查项 | 高危特征 | ATT&CK | 说明 |
|--------|----------|--------|------|
| 进程路径 | /tmp/, /private/tmp, /var/folders | T1036 | 临时目录执行 |
| 进程名 | 以点开头 | T1564.001 | 隐藏进程 |
| 命令行 | osascript -e "display dialog.*password" | T1059.002 | 密码钓鱼 |
| 命令行 | curl\|sh, wget\|bash | T1059.004 | 远程执行 |
| 命令行 | base64 -d, openssl enc | T1140 | 解码执行 |
| 网络 | 4444/5555/1337 监听 | T1571 | 反弹 Shell |
| 文件 | .dylib 在 /tmp | T1574.006 | Dylib 注入 |
| 文件 | pw.dat | - | Stealer 特征 |
| 持久化 | 最近创建的 LaunchAgent | T1543.001 | 后门植入 |
| 安全 | SIP 已禁用 | T1562.001 | 防护被关闭 |

---

## 辅助脚本

VQL 本地模式部分插件不可用，以下脚本补充检测能力：

| 脚本 | 用途 | 补充能力 |
|------|------|----------|
| [scripts/quick_scan.sh](scripts/quick_scan.sh) | 一键快速扫描 | SIP/进程/网络/持久化综合检查 |
| [scripts/deep_persistence.sh](scripts/deep_persistence.sh) | 深度持久化分析 | plist 可疑特征检测 |
| [scripts/codesign_check.sh](scripts/codesign_check.sh) | 代码签名检查 | 未签名/无效签名/公证状态 |
| [scripts/network_analysis.sh](scripts/network_analysis.sh) | 网络深度分析 | 进程-连接关联/C2检测 |
| [scripts/forensic_artifacts.sh](scripts/forensic_artifacts.sh) | 取证数据采集 | Quarantine/统一日志/审计/EventTaps |
| [scripts/summary_scan.sh](scripts/summary_scan.sh) | **一键摘要报告** | 简洁单页报告，推荐首选 |

```bash
# 推荐使用顺序
./scripts/summary_scan.sh        # 1. 首选：一键摘要报告
./scripts/quick_scan.sh          # 2. 快速扫描（详细）
./scripts/quick_scan.sh --full   # 3. 完整扫描
./scripts/deep_persistence.sh    # 4. 持久化深度分析
./scripts/forensic_artifacts.sh  # 5. 取证数据采集
```

### VQL 取证查询 (补充)

```bash
# Quarantine 下载记录 (追踪恶意软件来源)
$VR query "SELECT LSQuarantineAgentName as Agent, LSQuarantineOriginURLString as URL, timestamp(epoch=LSQuarantineTimeStamp + 978307200) as Time FROM sqlite(file='$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2', query='SELECT * FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 20')"

# Shell 历史文件
$VR query "SELECT FullPath, Size, Mtime FROM glob(globs=['/Users/*/.zsh_history', '/Users/*/.bash_history'])"

# MRU 最近使用记录
$VR query "SELECT FullPath, Mtime FROM glob(globs='/Users/*/Library/Application Support/com.apple.sharedfilelist/*.sfl2')"
```

---

## 报告模板

详见 [references/report-format.md](references/report-format.md)

## 附加资源

- [references/attack-techniques.md](references/attack-techniques.md) - macOS ATT&CK 技术详解
- [references/2024-threats.md](references/2024-threats.md) - 2024 年 macOS 威胁情报
- [references/vql-advanced.md](references/vql-advanced.md) - 高级 VQL 狩猎查询
