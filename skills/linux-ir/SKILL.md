---
name: linux-ir
description: Linux 入侵检查与应急响应。当用户要求"Linux入侵检查"、"Linux应急响应"、"Linux后门检测"、"systemd检查"、"crontab检查"、"Linux持久化检测"、"Rootkit检测"、"容器安全检查"、"挖矿木马检测"、"Webshell检测"、"供应链安全检测"、"无文件恶意软件检测"、"eBPF后门检测"、"BPFDoor检测"、"memfd检测"时使用此技能。
metadata:
  version: 2.2.0
  builtin: true
---

# Linux 入侵检查与威胁狩猎

使用 Velociraptor 本地模式执行 VQL 查询，结合 MITRE ATT&CK 框架检测 Linux 系统入侵迹象。

## 依赖

```bash
# Velociraptor (x86_64)
mkdir -p ~/tools/velociraptor
curl -L -o ~/tools/velociraptor/velociraptor \
  https://github.com/Velocidex/velociraptor/releases/download/v0.73.3/velociraptor-v0.73.3-linux-amd64
chmod +x ~/tools/velociraptor/velociraptor

# ARM64
curl -L -o ~/tools/velociraptor/velociraptor \
  https://github.com/Velocidex/velociraptor/releases/download/v0.73.3/velociraptor-v0.73.3-linux-arm64
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

# 专项检测模式
bash <SKILL_DIR>/scripts/ir.sh persistence  # 持久化深度分析
bash <SKILL_DIR>/scripts/ir.sh rootkit      # Rootkit 检测
bash <SKILL_DIR>/scripts/ir.sh container    # 容器安全检测
bash <SKILL_DIR>/scripts/ir.sh forensic     # 取证采集 (含SSH爆破分析)
bash <SKILL_DIR>/scripts/ir.sh miner        # 挖矿木马检测
bash <SKILL_DIR>/scripts/ir.sh supply       # 供应链安全 (pip投毒/Redis/JDWP)
bash <SKILL_DIR>/scripts/ir.sh webshell     # Webshell检测 (菜刀/蚁剑/冰蝎/哥斯拉)
bash <SKILL_DIR>/scripts/ir.sh fileless     # 无文件恶意软件 (memfd_create/内存执行)
bash <SKILL_DIR>/scripts/ir.sh ebpf         # eBPF/BPF 后门 (BPFDoor/Symbiote)
bash <SKILL_DIR>/scripts/ir.sh advanced     # 高级持久化 (MOTD/XDG/Udev/Git Hooks)

# 帮助信息
bash <SKILL_DIR>/scripts/ir.sh help
```

**执行顺序建议**：
1. 先运行 `ir.sh` 查看摘要
2. 发现问题再运行 `ir.sh full` 深入检查
3. 根据发现使用下方 VQL 手动查询取证

---

## 阶段 1: 进程狩猎 (ATT&CK T1059)

### 基础进程检查

```bash
# 所有进程
$VR query "SELECT Pid, Ppid, Name, Exe, CommandLine, Username FROM pslist()"

# 可疑进程（临时目录/隐藏名/可疑命令行）
$VR query "SELECT Pid, Name, Exe, CommandLine FROM pslist() WHERE Exe =~ '/tmp/|/dev/shm|/var/tmp|/run/user' OR Name =~ '^\\.' OR CommandLine =~ 'base64|curl.*\\|.*sh|wget.*\\|.*bash|nc\\s+-[el]|nohup'"

# 已删除但运行的进程 (高危)
$VR query "SELECT Pid, Name, Exe FROM pslist() WHERE Exe =~ '\\(deleted\\)'"

# 非标准路径进程
$VR query "SELECT Pid, Name, Exe FROM pslist() WHERE NOT Exe =~ '^/usr/|^/bin/|^/sbin/|^/lib/'"
```

### 高级进程狩猎

```bash
# 挖矿特征
$VR query "SELECT Pid, Name, Exe, CommandLine FROM pslist() WHERE Name =~ 'xmrig|minerd|kdevtmpfsi|kinsing' OR CommandLine =~ 'stratum|pool|xmr|cryptonight'"

# 伪装系统进程 (kworker 伪装)
$VR query "SELECT Pid, Name, Exe FROM pslist() WHERE Name =~ 'kworker[0-9]{3,}|kthread[0-9]'"

# 反弹 Shell 特征
$VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE CommandLine =~ '/dev/tcp|nc\\s+-e|bash\\s+-i|python.*socket|perl.*socket'"

# 编码命令检测
$VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE CommandLine =~ 'base64\\s+-d|openssl.*enc|xxd'"
```

---

## 阶段 2: 网络狩猎 (ATT&CK T1071)

### 基础网络检查

```bash
# 所有连接
$VR query "SELECT Pid, Name, Laddr, Raddr, Status FROM netstat()"

# 监听端口
$VR query "SELECT Pid, Name, Laddr FROM netstat() WHERE Status = 'LISTEN'"

# 外部连接（排除内网）
$VR query "SELECT Pid, Name, Raddr FROM netstat() WHERE Status = 'ESTABLISHED' AND NOT Raddr.IP =~ '^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)'"
```

### 高级网络狩猎

```bash
# 高危端口监听 (C2/反弹Shell)
$VR query "SELECT Pid, Name, Laddr FROM netstat() WHERE Status = 'LISTEN' AND Laddr.Port IN (4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337)"

# 数据库未授权访问风险
$VR query "SELECT Pid, Name, Laddr FROM netstat() WHERE Status = 'LISTEN' AND Laddr.Port IN (6379, 27017, 9200, 5432, 3306)"

# 矿池连接
$VR query "SELECT Pid, Name, Raddr FROM netstat() WHERE Raddr.Port IN (3333, 4444, 5555, 7777, 14433, 45700)"

# 非标准端口外连
ss -tunp 2>/dev/null | grep ESTABLISHED | grep -vE ':80|:443|:22|:53'
```

---

## 阶段 3: 持久化狩猎 (ATT&CK TA0003)

### Systemd 服务 (T1543.002)

```bash
# 系统服务
$VR query "SELECT FullPath, Mtime, Size FROM glob(globs='/etc/systemd/system/*.service')"

# 用户服务
$VR query "SELECT FullPath, Mtime FROM glob(globs='/home/*/.config/systemd/user/*.service')"

# 最近 7 天新增
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/etc/systemd/system/*.service', '/lib/systemd/system/*.service']) WHERE Mtime > now() - 604800"

# Timers
$VR query "SELECT FullPath, Mtime FROM glob(globs='/etc/systemd/system/*.timer')"

# 可疑服务内容分析
for svc in /etc/systemd/system/*.service; do
  if grep -qE 'ExecStart=.*/tmp/|/dev/shm|curl|wget|base64' "$svc" 2>/dev/null; then
    echo "[!] 可疑: $svc"
    grep -E 'ExecStart|Description' "$svc"
  fi
done
```

### Cron 任务 (T1053.003)

```bash
# 用户 crontab
$VR query "SELECT * FROM crontab()"

# /etc/cron.d
$VR query "SELECT FullPath, Mtime, Size FROM glob(globs='/etc/cron.d/*')"

# cron 目录
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/etc/cron.hourly/*', '/etc/cron.daily/*', '/etc/cron.weekly/*', '/etc/cron.monthly/*'])"

# 可疑 cron 命令
grep -rE 'curl|wget|python|perl|nc\s|/tmp/' /etc/cron* /var/spool/cron/ 2>/dev/null
```

### 其他持久化机制

```bash
# rc.local (T1037.004)
$VR query "SELECT FullPath, Size, Mtime FROM stat(filename='/etc/rc.local')"
cat /etc/rc.local 2>/dev/null | grep -vE '^#|^$|^exit'

# init.d
$VR query "SELECT FullPath, Mtime FROM glob(globs='/etc/init.d/*') WHERE Mtime > now() - 604800"

# profile.d (T1546.004)
$VR query "SELECT FullPath, Mtime FROM glob(globs='/etc/profile.d/*.sh')"

# bashrc
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/etc/bash.bashrc', '/etc/bashrc', '/home/*/.bashrc', '/root/.bashrc'])"

# LD_PRELOAD 劫持 (T1574.006)
$VR query "SELECT FullPath, Size FROM glob(globs='/etc/ld.so.preload')"
cat /etc/ld.so.preload 2>/dev/null

# 内核模块 (T1547.006)
$VR query "SELECT FullPath, Mtime FROM glob(globs='/lib/modules/*/kernel/**/*.ko') WHERE Mtime > now() - 604800 LIMIT 20"
lsmod | grep -vE 'Module|nvidia|nouveau|iwl|virtio|kvm'
```

---

## 阶段 4: 用户与认证检查 (ATT&CK TA0006)

### 用户检查

```bash
# 所有用户
$VR query "SELECT * FROM users()"

# UID=0 用户（除 root）
$VR query "SELECT * FROM users() WHERE Uid = 0 AND Name != 'root'"

# 可登录用户
$VR query "SELECT Name, Uid, Shell FROM users() WHERE Shell =~ 'bash|sh|zsh' AND Uid >= 1000"

# 最近登录
$VR query "SELECT * FROM last()"

# /etc/passwd 和 /etc/shadow 修改时间
$VR query "SELECT FullPath, Mtime FROM stat(filename='/etc/passwd')"
$VR query "SELECT FullPath, Mtime FROM stat(filename='/etc/shadow')"
```

### SSH 密钥检查 (T1098.004)

```bash
# authorized_keys
$VR query "SELECT FullPath, Mtime, Size FROM glob(globs=['/home/*/.ssh/authorized_keys', '/root/.ssh/authorized_keys'])"

# 最近修改
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/home/*/.ssh/authorized_keys', '/root/.ssh/authorized_keys']) WHERE Mtime > now() - 604800"
```

### sudo 配置检查

```bash
# sudoers 危险配置
grep -E 'NOPASSWD|ALL.*ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null

# sudoers.d 目录
ls -la /etc/sudoers.d/
```

### PAM 后门检测 (T1556.003)

```bash
# PAM 配置最近修改
find /etc/pam.d -mtime -7 -ls

# 可疑 PAM 模块
grep -rE 'pam_exec|pam_script|pam_python' /etc/pam.d/
```

---

## 阶段 5: 文件系统检查

### 临时目录检查

```bash
# /tmp 可疑文件
$VR query "SELECT FullPath, Size, Mtime, Mode FROM glob(globs='/tmp/**') WHERE Size > 0 AND (FullPath =~ '\\.(sh|py|pl|elf|so)$' OR Mode =~ 'x') LIMIT 50"

# /dev/shm 可疑文件
$VR query "SELECT FullPath, Size, Mtime FROM glob(globs='/dev/shm/*') WHERE Size > 0"

# 隐藏文件
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/tmp/.*', '/var/tmp/.*', '/dev/shm/.*'])"
```

### SUID/权限检查

```bash
# 异常位置的 SUID 文件
$VR query "SELECT FullPath, Mode FROM glob(globs=['/tmp/**', '/var/tmp/**', '/home/**']) WHERE Mode =~ 's'"

# 最近修改的 /usr/bin
$VR query "SELECT FullPath, Mtime FROM glob(globs='/usr/bin/*') WHERE Mtime > now() - 604800 LIMIT 20"
```

### Webshell 检测

```bash
# PHP Webshell
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/var/www/**/*.php', '/var/www/**/*.phtml']) WHERE Mtime > now() - 604800 LIMIT 50"

# JSP Webshell
$VR query "SELECT FullPath, Mtime FROM glob(globs='/var/lib/tomcat/**/*.jsp') WHERE Mtime > now() - 604800 LIMIT 50"
```

---

## 阶段 6: 日志检查

```bash
# auth.log 登录失败
$VR query "SELECT * FROM parse_lines(filename='/var/log/auth.log') WHERE Line =~ 'Failed password' LIMIT 50"

# secure 日志
$VR query "SELECT * FROM parse_lines(filename='/var/log/secure') WHERE Line =~ 'Failed|Invalid' LIMIT 50"

# 可疑 sudo 命令
grep 'sudo.*COMMAND' /var/log/auth.log 2>/dev/null | tail -20
```

---

## 阶段 7: 无文件恶意软件检测 (ATT&CK T1620)

### memfd_create 执行检测

```bash
# memfd 执行的进程
$VR query "SELECT Pid, Name, Exe, CommandLine FROM pslist() WHERE Exe =~ 'memfd:' OR Exe =~ '/memfd:'"

# 已删除但运行的进程
$VR query "SELECT Pid, Name, Exe FROM pslist() WHERE Exe =~ '\\(deleted\\)'"

# 恢复 memfd 二进制
$VR query "SELECT Pid, Name, Exe,
  copy(filename=format(format='/proc/%d/exe', args=[Pid]),
       dest=format(format='/tmp/recovered_%d', args=[Pid])) AS Recovered
FROM pslist()
WHERE Exe =~ 'memfd:'"
```

### 内存映射异常

```bash
# 匿名可执行内存段 (无文件映射)
$VR query "SELECT Pid, Name, count() AS AnonExecCount
FROM foreach(
  row={SELECT Pid, Name FROM pslist()},
  query={
    SELECT Pid, Name
    FROM parse_lines(filename=format(format='/proc/%d/maps', args=[Pid]))
    WHERE Line =~ '^[0-9a-f]+-[0-9a-f]+.*x.*\\s+0\\s+00:00\\s+0\\s*$'
  }
)
GROUP BY Pid, Name
HAVING AnonExecCount > 10"

# 无环境变量的用户进程 (可疑)
$VR query "SELECT Pid, Name, Exe FROM pslist()
WHERE NOT Name =~ '^k' AND
  stat(filename=format(format='/proc/%d/environ', args=[Pid])).Size = 0"
```

### /dev/shm 共享内存

```bash
# /dev/shm 可执行文件
find /dev/shm -type f -executable 2>/dev/null

# 文件描述符中的 memfd
find /proc/*/fd -lname '*memfd*' 2>/dev/null
```

---

## 阶段 8: eBPF/BPF 后门检测 (ATT&CK T1014, T1205.002)

### BPF 程序枚举

```bash
# 已加载 BPF 程序 (需要 bpftool)
bpftool prog list 2>/dev/null
bpftool map list 2>/dev/null
```

### BPFDoor 特征检测

```bash
# packet_recvmsg 等待进程 (BPFDoor 特征)
$VR query "SELECT Pid, Name, Exe
FROM foreach(
  row={SELECT Pid, Name, Exe FROM pslist()},
  query={
    SELECT Pid, Name, Exe
    FROM parse_lines(filename=format(format='/proc/%d/stack', args=[Pid]))
    WHERE Line =~ 'packet_recvmsg|wait_for_more_packets'
  }
)"

# BPFDoor 端口范围 42391-43391
$VR query "SELECT Pid, Name, Laddr
FROM netstat()
WHERE Status = 'LISTEN' AND Laddr.Port >= 42391 AND Laddr.Port <= 43391"

# BPFDoor 常见进程名
ps aux | grep -iE 'kdmtmpflush|dbus-srv|hald-addon|irqbalanced' | grep -v grep

# AF_PACKET socket
$VR query "SELECT Pid, Name, Family FROM netstat() WHERE Family = 'AF_PACKET'"
```

### Symbiote/LD_PRELOAD 检测

```bash
# ld.so.preload 内容
$VR query "SELECT FullPath, Size, Mtime,
  read_file(filename='/etc/ld.so.preload', length=1000) AS Content
FROM stat(filename='/etc/ld.so.preload')
WHERE Size > 0"

# 进程 LD_PRELOAD 环境变量
grep -l LD_PRELOAD /proc/*/environ 2>/dev/null

# 可疑共享库位置
find /tmp /var/tmp /dev/shm /home -name '*.so*' -type f 2>/dev/null
```

---

## 阶段 9: 高级持久化检测 (ATT&CK T1037, T1546, T1547)

### MOTD 后门 (T1037.003)

```bash
# MOTD 文件
$VR query "SELECT FullPath, Mtime, Size FROM glob(globs='/etc/update-motd.d/*')"

# 可疑 MOTD 内容
$VR query "SELECT FullPath, Mtime,
  read_file(filename=FullPath, length=2000) AS Content
FROM glob(globs='/etc/update-motd.d/*')
WHERE Content =~ 'curl|wget|nc\\s|python|bash\\s+-i|/dev/tcp'"
```

### XDG Autostart (T1546.013)

```bash
# 用户 autostart
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/home/*/.config/autostart/*.desktop', '/etc/xdg/autostart/*.desktop'])"

# 可疑 Exec 命令
$VR query "SELECT FullPath, Mtime,
  parse_string_with_regex(string=read_file(filename=FullPath), regex='Exec=(?P<Cmd>.*)').Cmd AS ExecCmd
FROM glob(globs=['/home/*/.config/autostart/*.desktop', '/etc/xdg/autostart/*.desktop'])
WHERE ExecCmd =~ 'curl|wget|nc\\s|python|/tmp/|base64'"
```

### Udev Rules (T1546.016)

```bash
# udev 规则
$VR query "SELECT FullPath, Mtime FROM glob(globs='/etc/udev/rules.d/*.rules')"

# 可疑 RUN 命令
$VR query "SELECT FullPath, Mtime, read_file(filename=FullPath, length=2000) AS Content
FROM glob(globs='/etc/udev/rules.d/*.rules')
WHERE Content =~ 'RUN\\+?=.*curl|RUN\\+?=.*wget|RUN\\+?=.*/tmp/'"
```

### At Jobs (T1053.002)

```bash
# at 队列
atq 2>/dev/null
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/var/spool/at/*', '/var/spool/cron/atjobs/*'])"
```

### Git Hooks (T1547.015)

```bash
# 可执行 git hooks
$VR query "SELECT FullPath, Mtime, Mode
FROM glob(globs='/home/*/**/.git/hooks/*')
WHERE Mode =~ 'x'"

# 可疑 hook 内容
$VR query "SELECT FullPath, Mtime, read_file(filename=FullPath, length=2000) AS Content
FROM glob(globs='/home/*/**/.git/hooks/*')
WHERE Mode =~ 'x' AND Content =~ 'curl|wget|nc\\s|/dev/tcp'"
```

### Package Manager Hooks (T1547.013)

```bash
# APT hooks
$VR query "SELECT FullPath, read_file(filename=FullPath, length=2000) AS Content
FROM glob(globs='/etc/apt/apt.conf.d/*')
WHERE Content =~ 'Pre-Invoke|Post-Invoke'"

# 最近修改的 dpkg 脚本
find /var/lib/dpkg/info -name '*.postinst' -mtime -7 2>/dev/null
```

### 历史记录清除检测 (T1070.003)

```bash
# 空的 history 文件
find /home /root -name '.bash_history' -empty 2>/dev/null
find /home /root -name '.zsh_history' -empty 2>/dev/null

# HISTFILE 篡改
grep -rE 'HISTSIZE=0|HISTFILESIZE=0|unset HISTFILE|HISTFILE=/dev/null' /home/*/.bashrc /root/.bashrc /etc/profile* 2>/dev/null
```

---

## 快速研判流程

### 第一层: 快速扫描 (~10秒)

```bash
VR=~/tools/velociraptor/velociraptor

# 1. 可疑进程
$VR query "SELECT Pid, Name, Exe FROM pslist() WHERE Exe =~ '/tmp/|/dev/shm|/var/tmp' OR Name =~ '^\\.' OR Exe =~ '\\(deleted\\)' LIMIT 10"

# 2. 异常外连
ss -tunp 2>/dev/null | grep ESTAB | grep -vE '127\.|10\.|192\.168\.' | head -10

# 3. 高危监听
$VR query "SELECT Pid, Name, Laddr FROM netstat() WHERE Status = 'LISTEN' AND Laddr.Port IN (4444, 5555, 6666, 6379)"

# 4. ld.so.preload
cat /etc/ld.so.preload 2>/dev/null && echo "[!] ld.so.preload 存在!"
```

### 第二层: 持久化检查 (~30秒)

```bash
# 5. 最近 systemd 服务
$VR query "SELECT FullPath, Mtime FROM glob(globs='/etc/systemd/system/*.service') WHERE Mtime > now() - 604800"

# 6. Crontab
$VR query "SELECT * FROM crontab()"

# 7. UID=0 异常用户
$VR query "SELECT * FROM users() WHERE Uid = 0 AND Name != 'root'"

# 8. SSH keys
$VR query "SELECT FullPath, Mtime FROM glob(globs=['/home/*/.ssh/authorized_keys', '/root/.ssh/authorized_keys'])"
```

---

## ATT&CK 映射表

| 战术 | 技术 ID | 技术名称 | 检测方法 |
|------|---------|----------|----------|
| 执行 | T1059.004 | Unix Shell | bash/sh 命令行 |
| 执行 | T1059.006 | Python | python 进程 |
| 执行 | T1620 | Reflective Code Loading | memfd_create/内存执行 |
| 持久化 | T1543.002 | Systemd Service | /etc/systemd/system/ |
| 持久化 | T1053.003 | Cron | crontab, /etc/cron.d/ |
| 持久化 | T1053.002 | At Jobs | atq, /var/spool/at/ |
| 持久化 | T1037.003 | MOTD Modification | /etc/update-motd.d/ |
| 持久化 | T1037.004 | RC Scripts | /etc/rc.local |
| 持久化 | T1546.004 | Shell Config | .bashrc, profile.d |
| 持久化 | T1546.013 | XDG Autostart | ~/.config/autostart/ |
| 持久化 | T1546.016 | Udev Rules | /etc/udev/rules.d/ |
| 持久化 | T1547.006 | Kernel Modules | lsmod |
| 持久化 | T1547.013 | Package Manager Hooks | APT/YUM hooks |
| 持久化 | T1547.015 | Git Hooks | .git/hooks/* |
| 持久化 | T1098.004 | SSH Keys | authorized_keys |
| 权限提升 | T1548.001 | SUID/SGID | find -perm |
| 防御规避 | T1014 | Rootkit | 进程/文件隐藏, eBPF |
| 防御规避 | T1070.003 | Clear History | HISTFILE, .bash_history |
| 防御规避 | T1070.006 | Timestomp | mtime < ctime |
| 防御规避 | T1205.002 | Socket Filters | AF_PACKET, BPF filter |
| 防御规避 | T1574.006 | LD_PRELOAD | /etc/ld.so.preload |
| 防御规避 | T1556.003 | PAM Modification | /etc/pam.d/ |
| 凭据访问 | T1552.004 | Private Keys | ~/.ssh/id_* |
| 命令控制 | T1571 | Non-Standard Port | 4444/5555/1337 |
| 容器 | T1611 | Container Escape | 特权容器/挂载 |

---

## 高危指标速查

| 检查项 | 高危特征 | ATT&CK | 说明 |
|--------|----------|--------|------|
| 进程路径 | /tmp, /dev/shm, /var/tmp | T1036 | 临时目录执行 |
| 进程路径 | memfd: | T1620 | 无文件执行 |
| 进程状态 | (deleted) | T1070 | 删除但运行 |
| 进程名 | 以点开头, kworker伪装 | T1036 | 隐藏/伪装 |
| 进程名 | kdmtmpflush, dbus-srv | T1014 | BPFDoor 特征 |
| 进程栈 | packet_recvmsg | T1205.002 | BPFDoor 等待 |
| 命令行 | nc -e, bash -i, /dev/tcp | T1059 | 反弹 Shell |
| 命令行 | curl\|sh, wget\|bash | T1105 | 远程下载执行 |
| 网络 | 4444/5555/1337 监听 | T1571 | C2 端口 |
| 网络 | 42391-43391 监听 | T1205.002 | BPFDoor 端口 |
| 网络 | AF_PACKET socket | T1205.002 | 原始包监听 |
| 网络 | 6379/27017/9200 监听 | - | 未授权访问 |
| 用户 | UID=0 非 root | T1136 | 后门用户 |
| systemd | 可疑 ExecStart | T1543.002 | 服务后门 |
| crontab | curl\|sh, wget\|bash | T1053.003 | 定时后门 |
| MOTD | 可疑脚本 | T1037.003 | 登录时触发 |
| XDG | 可疑 Exec | T1546.013 | 桌面自启 |
| Udev | 可疑 RUN | T1546.016 | 设备触发 |
| Git Hooks | 可执行 hooks | T1547.015 | 代码提交触发 |
| SUID | /tmp, /home 下 | T1548.001 | 提权后门 |
| ld.so.preload | 文件存在且非空 | T1574.006 | 库劫持 |
| LD_PRELOAD | 进程环境变量 | T1574.006 | Symbiote 特征 |
| .bash_history | 文件为空 | T1070.003 | 历史清除 |

---

## 辅助脚本

| 脚本 | 用途 | 说明 |
|------|------|------|
| [scripts/ir.sh](scripts/ir.sh) | **统一入口** | 推荐使用，支持15种检测模式 |
| [scripts/quick_scan.sh](scripts/quick_scan.sh) | 快速扫描 | 进程/网络/持久化/环境变量 |
| [scripts/deep_persistence.sh](scripts/deep_persistence.sh) | 深度持久化 | systemd/cron/PAM |
| [scripts/rootkit_check.sh](scripts/rootkit_check.sh) | Rootkit 检测 | 隐藏进程/模块/文件 |
| [scripts/container_check.sh](scripts/container_check.sh) | 容器安全 | Docker/K8s/逃逸 |
| [scripts/forensic_artifacts.sh](scripts/forensic_artifacts.sh) | 取证采集 | 日志/历史/配置/SSH爆破分析 |
| [scripts/miner_check.sh](scripts/miner_check.sh) | 挖矿检测 | XMRig/kinsing/TeamTNT/矿池连接 |
| [scripts/supply_chain_check.sh](scripts/supply_chain_check.sh) | 供应链检测 | pip投毒/Redis/JDWP/Docker API |
| [scripts/webshell_check.sh](scripts/webshell_check.sh) | Webshell检测 | 菜刀/蚁剑/冰蝎/哥斯拉 |
| [scripts/fileless_check.sh](scripts/fileless_check.sh) | 无文件恶意软件 | memfd_create/内存执行/进程注入 |
| [scripts/ebpf_check.sh](scripts/ebpf_check.sh) | eBPF/BPF 后门 | BPFDoor/Symbiote/AF_PACKET |
| [scripts/advanced_persistence.sh](scripts/advanced_persistence.sh) | 高级持久化 | MOTD/XDG/Udev/At/Git Hooks |

```bash
# 推荐使用顺序
bash scripts/ir.sh              # 1. 摘要报告
bash scripts/ir.sh quick        # 2. 快速扫描
bash scripts/ir.sh full         # 3. 完整检查

# 根据发现选择专项检测
bash scripts/ir.sh rootkit      # Rootkit 专项
bash scripts/ir.sh container    # 容器专项
bash scripts/ir.sh miner        # 挖矿木马专项
bash scripts/ir.sh webshell     # Webshell 专项
bash scripts/ir.sh supply       # 供应链安全专项
bash scripts/ir.sh forensic     # 取证采集
bash scripts/ir.sh fileless     # 无文件恶意软件专项
bash scripts/ir.sh ebpf         # eBPF/BPF 后门专项
bash scripts/ir.sh advanced     # 高级持久化专项
```

---

## 报告模板

详见 [references/report-format.md](references/report-format.md)

## 附加资源

- [references/attack-techniques.md](references/attack-techniques.md) - Linux ATT&CK 技术详解
- [references/linux-threats.md](references/linux-threats.md) - 2024-2025 Linux 威胁情报
- [references/vql-advanced.md](references/vql-advanced.md) - 高级 VQL 狩猎查询
- [references/vql-community.md](references/vql-community.md) - 社区 VQL 查询库
