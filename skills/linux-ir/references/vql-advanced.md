# Linux 高级 VQL 狩猎查询

## 环境准备

```bash
# Velociraptor 本地模式
VR=~/tools/velociraptor/velociraptor

# 安装 (如未安装)
mkdir -p ~/tools/velociraptor
# x86_64
curl -L -o ~/tools/velociraptor/velociraptor \
  https://github.com/Velocidex/velociraptor/releases/download/v0.73.3/velociraptor-v0.73.3-linux-amd64
# ARM64
curl -L -o ~/tools/velociraptor/velociraptor \
  https://github.com/Velocidex/velociraptor/releases/download/v0.73.3/velociraptor-v0.73.3-linux-arm64
chmod +x ~/tools/velociraptor/velociraptor
```

---

## 进程狩猎

### 基础进程查询

```bash
# 所有进程
$VR query "SELECT Pid, Ppid, Name, Exe, CommandLine, Username FROM pslist()"

# 按 CPU 排序
$VR query "SELECT Pid, Name, Exe, CommandLine FROM pslist() ORDER BY Threads DESC LIMIT 20"
```

### 可疑进程检测

```bash
# 临时目录执行
$VR query "SELECT Pid, Name, Exe, CommandLine FROM pslist() WHERE Exe =~ '/tmp/|/dev/shm|/var/tmp|/run/user'"

# 隐藏进程名
$VR query "SELECT Pid, Name, Exe, CommandLine FROM pslist() WHERE Name =~ '^\\.'"

# 已删除但运行
$VR query "SELECT Pid, Name, Exe FROM pslist() WHERE Exe =~ '\\(deleted\\)'"

# 可疑命令行
$VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE CommandLine =~ 'base64|curl.*\\|.*sh|wget.*\\|.*bash|nc\\s+-[el]|nohup|/dev/tcp'"
```

### 挖矿检测

```bash
# 挖矿进程特征
$VR query "SELECT Pid, Name, Exe, CommandLine FROM pslist() WHERE Name =~ 'xmrig|minerd|kdevtmpfsi|kinsing|.x11' OR CommandLine =~ 'stratum|pool|xmr|monero|cryptonight'"

# 高 CPU 进程
$VR query "SELECT Pid, Name, Exe FROM pslist() WHERE Name =~ 'kworker[0-9]{3,}'"
```

### 反弹 Shell 检测

```bash
# bash/nc 反弹
$VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE CommandLine =~ 'bash\\s+-i|nc\\s+-e|ncat.*-e|python.*socket|perl.*socket|/dev/tcp'"

# script 命令（常用于 TTY 升级）
$VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE Name = 'script' OR CommandLine =~ 'script.*-q'"
```

---

## 网络狩猎

### 基础网络查询

```bash
# 所有连接
$VR query "SELECT Pid, Name, Laddr, Raddr, Status FROM netstat()"

# 监听端口
$VR query "SELECT Pid, Name, Laddr FROM netstat() WHERE Status = 'LISTEN'"

# 已建立连接
$VR query "SELECT Pid, Name, Laddr, Raddr FROM netstat() WHERE Status = 'ESTABLISHED'"
```

### 可疑连接检测

```bash
# 外部连接 (排除内网)
$VR query "SELECT Pid, Name, Raddr FROM netstat() WHERE Status = 'ESTABLISHED' AND NOT Raddr.IP =~ '^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)'"

# 高危端口监听
$VR query "SELECT Pid, Name, Laddr FROM netstat() WHERE Status = 'LISTEN' AND Laddr.Port IN (4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337)"

# 矿池端口
$VR query "SELECT Pid, Name, Raddr FROM netstat() WHERE Raddr.Port IN (3333, 4444, 5555, 7777, 8888, 14433, 45700)"

# 数据库端口 (可能未授权)
$VR query "SELECT Pid, Name, Laddr FROM netstat() WHERE Status = 'LISTEN' AND Laddr.Port IN (6379, 27017, 9200, 5432, 3306, 1433)"
```

---

## 持久化狩猎

### Systemd 服务

```bash
# 系统服务
$VR query "SELECT FullPath, Mtime, Size FROM glob(globs='/etc/systemd/system/*.service')"

# 用户服务
$VR query "SELECT FullPath, Mtime FROM glob(globs='/home/*/.config/systemd/user/*.service')"

# 最近 7 天新增
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/etc/systemd/system/*.service', '/lib/systemd/system/*.service']) WHERE Mtime > now() - 604800"

# Timers
$VR query "SELECT FullPath, Mtime FROM glob(globs='/etc/systemd/system/*.timer')"
```

### Cron 任务

```bash
# 系统 crontab
$VR query "SELECT * FROM crontab()"

# /etc/cron.d
$VR query "SELECT FullPath, Mtime, Size FROM glob(globs='/etc/cron.d/*')"

# cron 目录
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/etc/cron.hourly/*', '/etc/cron.daily/*', '/etc/cron.weekly/*', '/etc/cron.monthly/*'])"

# 最近修改
$VR query "SELECT FullPath, Mtime FROM glob(globs='/etc/cron.d/*') WHERE Mtime > now() - 604800"
```

### Init 脚本

```bash
# rc.local
$VR query "SELECT FullPath, Size, Mtime FROM stat(filename='/etc/rc.local')"

# init.d
$VR query "SELECT FullPath, Mtime FROM glob(globs='/etc/init.d/*') WHERE Mtime > now() - 604800"

# profile.d
$VR query "SELECT FullPath, Mtime FROM glob(globs='/etc/profile.d/*.sh')"
```

### Shell 配置

```bash
# bashrc
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/etc/bash.bashrc', '/etc/bashrc', '/home/*/.bashrc', '/root/.bashrc'])"

# profile
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/home/*/.profile', '/home/*/.bash_profile', '/root/.profile'])"
```

---

## 用户狩猎

### 用户检查

```bash
# 所有用户
$VR query "SELECT * FROM users()"

# UID=0 用户 (除 root)
$VR query "SELECT * FROM users() WHERE Uid = 0 AND Name != 'root'"

# 可登录用户
$VR query "SELECT Name, Uid, Shell FROM users() WHERE Shell =~ 'bash|sh|zsh' AND Uid >= 1000"

# 无密码用户
$VR query "SELECT Name, Uid FROM users() WHERE NOT Shell =~ 'nologin|false'"
```

### SSH 密钥

```bash
# authorized_keys
$VR query "SELECT FullPath, Mtime, Size FROM glob(globs=['/home/*/.ssh/authorized_keys', '/root/.ssh/authorized_keys'])"

# 最近修改
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/home/*/.ssh/authorized_keys', '/root/.ssh/authorized_keys']) WHERE Mtime > now() - 604800"

# 私钥
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/home/*/.ssh/id_*', '/root/.ssh/id_*'])"
```

### 登录记录

```bash
# 最近登录
$VR query "SELECT * FROM last() LIMIT 50"

# wtmp
$VR query "SELECT * FROM wtmp() LIMIT 50"
```

---

## 文件狩猎

### 临时目录

```bash
# /tmp 可疑文件
$VR query "SELECT FullPath, Size, Mtime, Mode FROM glob(globs='/tmp/**') WHERE Size > 0 AND (FullPath =~ '\\.(sh|py|pl|elf|so)$' OR Mode =~ 'x') LIMIT 50"

# /dev/shm
$VR query "SELECT FullPath, Size, Mtime FROM glob(globs='/dev/shm/*') WHERE Size > 0"

# 隐藏文件
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/tmp/.*', '/var/tmp/.*', '/dev/shm/.*'])"
```

### SUID/SGID

```bash
# 异常位置的 SUID
$VR query "SELECT FullPath, Mode FROM glob(globs=['/tmp/**', '/var/tmp/**', '/home/**']) WHERE Mode =~ 's'"
```

### 最近修改

```bash
# /usr/bin 最近修改
$VR query "SELECT FullPath, Mtime FROM glob(globs='/usr/bin/*') WHERE Mtime > now() - 604800 LIMIT 20"

# /etc 最近修改
$VR query "SELECT FullPath, Mtime FROM glob(globs='/etc/**') WHERE Mtime > now() - 604800 LIMIT 50"
```

### Webshell

```bash
# PHP Webshell
$VR query "SELECT FullPath, Mtime FROM glob(globs='/var/www/**/*.php') WHERE Mtime > now() - 604800 LIMIT 50"

# JSP Webshell
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/var/lib/tomcat/**/*.jsp', '/opt/tomcat/**/*.jsp']) WHERE Mtime > now() - 604800 LIMIT 50"
```

---

## LD_PRELOAD 检测

```bash
# ld.so.preload
$VR query "SELECT FullPath, Size FROM glob(globs='/etc/ld.so.preload')"

# 读取内容
$VR query "SELECT * FROM read_file(filename='/etc/ld.so.preload')"

# ld.so.conf.d 可疑条目
$VR query "SELECT FullPath, Mtime FROM glob(globs='/etc/ld.so.conf.d/*.conf') WHERE Mtime > now() - 604800"
```

---

## 内核模块

```bash
# 最近加载的模块
$VR query "SELECT FullPath, Mtime FROM glob(globs='/lib/modules/*/kernel/**/*.ko') WHERE Mtime > now() - 604800 LIMIT 20"

# modules-load.d
$VR query "SELECT FullPath, Mtime FROM glob(globs='/etc/modules-load.d/*.conf')"
```

---

## 日志分析

### 认证日志

```bash
# auth.log 失败登录
$VR query "SELECT * FROM parse_lines(filename='/var/log/auth.log') WHERE Line =~ 'Failed password' LIMIT 50"

# SSH 暴力破解
$VR query "SELECT * FROM parse_lines(filename='/var/log/auth.log') WHERE Line =~ 'Failed password.*ssh' LIMIT 100"

# 成功的 sudo
$VR query "SELECT * FROM parse_lines(filename='/var/log/auth.log') WHERE Line =~ 'sudo.*COMMAND' LIMIT 50"
```

### 系统日志

```bash
# syslog 错误
$VR query "SELECT * FROM parse_lines(filename='/var/log/syslog') WHERE Line =~ 'error|failed|denied' LIMIT 50"
```

---

## 组合查询

### 进程 + 网络关联

```bash
# 有外连的可疑进程
$VR query "
LET suspicious_pids = SELECT Pid FROM pslist() WHERE Exe =~ '/tmp/|/dev/shm'
SELECT * FROM netstat() WHERE Pid IN suspicious_pids.Pid AND Status = 'ESTABLISHED'
"
```

### 时间线分析

```bash
# 最近 24 小时的可疑活动
$VR query "
SELECT FullPath, Mtime, 'file' as Type FROM glob(globs=['/tmp/**', '/etc/systemd/system/*.service', '/etc/cron.d/*'])
WHERE Mtime > now() - 86400
ORDER BY Mtime DESC
LIMIT 50
"
```

---

## VQL 技巧

### 时间过滤

```vql
-- 最近 7 天
WHERE Mtime > now() - 604800

-- 最近 24 小时
WHERE Mtime > now() - 86400

-- 最近 1 小时
WHERE Mtime > now() - 3600
```

### 正则表达式

```vql
-- 大小写不敏感
WHERE Name =~ '(?i)xmrig'

-- 多选项
WHERE Exe =~ '/tmp/|/dev/shm|/var/tmp'

-- 排除
WHERE NOT Raddr.IP =~ '^127\\.'
```

### 限制输出

```vql
-- 限制行数
LIMIT 50

-- 排序后取前 N
ORDER BY Mtime DESC LIMIT 20
```
