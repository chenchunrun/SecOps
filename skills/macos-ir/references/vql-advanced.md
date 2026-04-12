# 高级 VQL 狩猎查询

## Velociraptor 本地模式说明

macOS 本地模式下部分插件不可用，需要使用系统命令补充:

| VQL 插件 | 状态 | 替代方案 |
|----------|------|----------|
| `pslist()` | 可用 | - |
| `netstat()` | 可用 | - |
| `glob()` | 可用 | - |
| `info()` | 可用 | - |
| `users()` | 不可用 | `dscl . -list /Users` |
| `crontab()` | 不可用 | `crontab -l` |
| `last()` | 不可用 | `last` 命令 |

---

## 进程狩猎查询

### 临时目录执行检测
```vql
SELECT Pid, Ppid, Name, Exe, CommandLine, Username
FROM pslist()
WHERE Exe =~ '/tmp/|/private/tmp|/var/folders|/Users/[^/]+/\\..*/'
```

### 隐藏进程检测
```vql
SELECT Pid, Name, Exe, CommandLine
FROM pslist()
WHERE Name =~ '^\\.' OR Exe =~ '/\\.[^/]+$'
```

### 可疑脚本解释器
```vql
SELECT Pid, Name, CommandLine
FROM pslist()
WHERE (Name =~ 'python|ruby|perl|bash|zsh|sh')
  AND (CommandLine =~ 'http://|https://|socket|subprocess|exec|eval|base64')
```

### osascript 凭据窃取 (2024 Stealer 特征)
```vql
SELECT Pid, Name, CommandLine
FROM pslist()
WHERE CommandLine =~ 'osascript.*display dialog|osascript.*-e.*password|hidden answer|System Preferences|System Settings'
```

### 反弹 Shell 检测
```vql
SELECT Pid, Name, CommandLine
FROM pslist()
WHERE CommandLine =~ '/dev/tcp|nc -[el]|bash -i|zsh -i|mkfifo|0<&196|python.*socket|ruby.*socket'
```

### 编码/解码命令
```vql
SELECT Pid, Name, CommandLine
FROM pslist()
WHERE CommandLine =~ 'base64 -[dD]|openssl.*enc|xxd -r|gzip -d.*\\|'
```

---

## 网络狩猎查询

### 高危端口监听
```vql
SELECT Pid, Name, Laddr
FROM netstat()
WHERE Status = 'LISTEN'
  AND Laddr.Port IN (4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 1234, 12345, 9001, 8443)
```

### 非常规外连
```vql
SELECT Pid, Name, Laddr, Raddr, Status
FROM netstat()
WHERE Status = 'ESTABLISHED'
  AND NOT Raddr.IP =~ '^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|17\\.)'
  AND NOT Raddr.Port IN (80, 443, 22, 53, 993, 587, 465)
```

### DNS 异常检测
```vql
SELECT Pid, Name, Raddr
FROM netstat()
WHERE Raddr.Port = 53
  AND Status = 'ESTABLISHED'
  AND NOT Raddr.IP =~ '^(8\\.8\\.|1\\.1\\.|9\\.9\\.)'
```

---

## 持久化狩猎查询

### LaunchAgents/Daemons 全量
```vql
SELECT FullPath, Mtime, Size
FROM glob(globs=[
  '/Library/LaunchAgents/*.plist',
  '/Library/LaunchDaemons/*.plist',
  '/System/Library/LaunchAgents/*.plist',
  '/System/Library/LaunchDaemons/*.plist',
  '/Users/*/Library/LaunchAgents/*.plist'
])
ORDER BY Mtime DESC
```

### 最近新增持久化 (7天)
```vql
SELECT FullPath, Mtime
FROM glob(globs=[
  '/Library/LaunchAgents/*.plist',
  '/Library/LaunchDaemons/*.plist',
  '/Users/*/Library/LaunchAgents/*.plist'
])
WHERE Mtime > now() - 604800
ORDER BY Mtime DESC
```

### 隐藏的 LaunchAgent
```vql
SELECT FullPath, Mtime
FROM glob(globs=[
  '/Library/LaunchAgents/.*.plist',
  '/Library/LaunchDaemons/.*.plist',
  '/Users/*/Library/LaunchAgents/.*.plist'
])
```

### Login Items (背景任务)
```vql
SELECT FullPath, Mtime
FROM glob(globs='/Users/*/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm')
```

### Overrides.plist (高级持久化)
```vql
SELECT FullPath, Mtime
FROM glob(globs='/var/db/launchd.db/*/overrides.plist')
```

### 内核扩展
```vql
SELECT FullPath, Mtime
FROM glob(globs=[
  '/Library/Extensions/*.kext',
  '/System/Library/Extensions/*.kext'
])
WHERE NOT FullPath =~ 'com\\.apple\\.'
```

---

## 文件系统狩猎查询

### /tmp 可疑文件
```vql
SELECT FullPath, Size, Mtime, Mode
FROM glob(globs='/tmp/**')
WHERE Size > 0
  AND (FullPath =~ '\\.(sh|py|pl|rb|dylib|so|app|scpt|command)$' OR Mode =~ 'x')
LIMIT 100
```

### 隐藏文件
```vql
SELECT FullPath, Mtime, Size
FROM glob(globs=['/tmp/.*', '/private/tmp/.*', '/Users/*/.*'])
WHERE NOT FullPath =~ '(DS_Store|Trash|CFUserTextEncoding|zsh_history|bash_history|viminfo)'
```

### 可疑 dylib 文件
```vql
SELECT FullPath, Mtime, Size
FROM glob(globs=[
  '/tmp/*.dylib',
  '/private/tmp/*.dylib',
  '/var/folders/**/*.dylib',
  '/Users/*/.*.dylib'
])
```

### 最近下载的可疑文件
```vql
SELECT FullPath, Mtime, Size
FROM glob(globs='/Users/*/Downloads/*.{sh,command,pkg,dmg,app,scpt,terminal}')
WHERE Mtime > now() - 604800
ORDER BY Mtime DESC
```

### Stealer 特征文件
```vql
SELECT FullPath, Mtime
FROM glob(globs=[
  '/tmp/pw.dat',
  '/private/tmp/pw.dat',
  '/Users/*/pw.dat',
  '/tmp/*.txt',
  '/tmp/cookies*',
  '/tmp/*wallet*'
])
```

---

## 防御规避检测查询

### TCC 数据库
```vql
SELECT FullPath, Mtime
FROM glob(globs=[
  '/Library/Application Support/com.apple.TCC/TCC.db',
  '/Users/*/Library/Application Support/com.apple.TCC/TCC.db'
])
```

### Gatekeeper 绕过检测
```vql
SELECT Pid, CommandLine
FROM pslist()
WHERE CommandLine =~ 'xattr -d com.apple.quarantine|xattr -c|xattr -w com.apple.quarantine'
```

### 扩展属性检查
```bash
# 非 VQL，使用系统命令
find ~/Downloads -name "*.app" -exec xattr -l {} \; 2>/dev/null
```

---

## 凭据访问检测查询

### Keychain 命令
```vql
SELECT Pid, Name, CommandLine
FROM pslist()
WHERE CommandLine =~ 'security find-.*password|security dump-keychain|security export'
```

### Keychain 文件
```vql
SELECT FullPath, Mtime
FROM glob(globs='/Users/*/Library/Keychains/*')
WHERE Mtime > now() - 86400
```

### 浏览器凭据
```vql
SELECT FullPath, Mtime
FROM glob(globs=[
  '/Users/*/Library/Application Support/Google/Chrome/*/Login Data',
  '/Users/*/Library/Application Support/Firefox/Profiles/*/logins.json',
  '/Users/*/Library/Safari/LocalStorage/*'
])
```

---

## SSH 检测查询

### authorized_keys
```vql
SELECT FullPath, Mtime, Size
FROM glob(globs='/Users/*/.ssh/authorized_keys')
```

### SSH 配置
```vql
SELECT FullPath, Mtime
FROM glob(globs=[
  '/Users/*/.ssh/config',
  '/etc/ssh/sshd_config'
])
```

### 已知主机
```vql
SELECT FullPath, Mtime
FROM glob(globs='/Users/*/.ssh/known_hosts')
WHERE Mtime > now() - 604800
```

---

## 组合狩猎查询

### 一键快速检查
```bash
VR=~/tools/velociraptor/velociraptor

# 组合查询: 可疑进程 + 网络 + 持久化
echo "=== 可疑进程 ==="
$VR query "SELECT Pid, Name, Exe, CommandLine FROM pslist() WHERE Exe =~ '/tmp/|/private/tmp' OR Name =~ '^\\.' OR CommandLine =~ 'osascript.*-e|base64|curl.*\\|.*sh' LIMIT 10"

echo "=== 高危监听 ==="
$VR query "SELECT Pid, Name, Laddr FROM netstat() WHERE Status = 'LISTEN' AND Laddr.Port IN (4444, 5555, 6666, 1337)"

echo "=== 最近 LaunchAgent ==="
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/Library/LaunchAgents/*.plist', '/Users/*/Library/LaunchAgents/*.plist']) WHERE Mtime > now() - 604800"
```

### 全面狩猎脚本
```bash
#!/bin/bash
VR=~/tools/velociraptor/velociraptor

echo "[*] macOS 威胁狩猎 - $(date)"
echo ""

echo "[1/8] 检查可疑进程..."
$VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE Exe =~ '/tmp/|/private/tmp' OR CommandLine =~ 'osascript.*password|base64 -d|curl.*\\|.*sh'"

echo "[2/8] 检查高危端口..."
$VR query "SELECT Pid, Name, Laddr FROM netstat() WHERE Status = 'LISTEN' AND Laddr.Port IN (4444, 5555, 6666, 1337, 31337)"

echo "[3/8] 检查最近 LaunchAgent..."
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/Library/LaunchAgents/*.plist', '/Library/LaunchDaemons/*.plist', '/Users/*/Library/LaunchAgents/*.plist']) WHERE Mtime > now() - 604800"

echo "[4/8] 检查 TCC 数据库..."
$VR query "SELECT FullPath, Mtime FROM glob(globs='*/com.apple.TCC/TCC.db') WHERE Mtime > now() - 604800"

echo "[5/8] 检查可疑 dylib..."
$VR query "SELECT FullPath FROM glob(globs=['/tmp/*.dylib', '/Users/*/.*.dylib'])"

echo "[6/8] 检查 Keychain 访问..."
$VR query "SELECT Pid, CommandLine FROM pslist() WHERE CommandLine =~ 'security find-.*password'"

echo "[7/8] 检查 SSH keys..."
$VR query "SELECT FullPath, Mtime FROM glob(globs='/Users/*/.ssh/authorized_keys')"

echo "[8/8] 检查 SIP 状态..."
csrutil status

echo ""
echo "[*] 狩猎完成"
```

---

## 性能优化建议

1. **使用 LIMIT**: 大目录遍历时限制结果数量
2. **精确 glob**: 避免过度递归 (`**`)
3. **时间过滤**: 优先检查最近修改的文件
4. **组合查询**: 在单个 VQL 中组合多个条件
