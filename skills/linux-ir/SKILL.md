---
name: linux-ir
description: Linux 入侵检查与应急响应。当用户要求"Linux入侵检查"、"Linux应急响应"、"Linux后门检测"、"systemd检查"、"crontab检查"、"Linux持久化检测"、"Rootkit检测"、"容器安全检查"、"挖矿木马检测"、"Webshell检测"、"供应链安全检测"、"无文件恶意软件检测"、"eBPF后门检测"、"BPFDoor检测"、"memfd检测"时使用此技能。
metadata:
  version: 2.3.0
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

## OWASP Top 10 + CWE 映射（Linux IR 视角）

Linux 应急响应中发现的攻击行为与 OWASP Top 10 应用安全风险和 CWE 的映射关系：

| OWASP 类别 | CWE ID | 漏洞名称 | Linux IR 场景 | ATT&CK 映射 |
|-----------|--------|---------|-------------|------------|
| A01:2021 Broken Access Control | CWE-284 | Improper Access Control | SUID 提权、sudo 配置错误、UID=0 后门用户 | T1548.001 |
| A01:2021 Broken Access Control | CWE-269 | Improper Privilege Management | root 权限获取、容器逃逸、内核提权 | T1068 |
| A03:2021 Injection | CWE-78 | OS Command Injection | Web 应用注入导致 Linux 主机沦陷、Shellshock | T1059.004 |
| A04:2021 Insecure Design | CWE-1188 | Insecure Default Initialization | 默认配置弱口令、SSH 允许 root 登录、Redis 未授权 | T1190 |
| A05:2021 Security Misconfiguration | CWE-16 | Configuration | 暴露的数据库端口(6379/27017/9200)、错误 sudoers | T1571 |
| A06:2021 Vulnerable Components | CWE-1035 | Outdated Components | 过时内核/库存在已知漏洞、供应链投毒 | T1195 |
| A07:2021 Auth Failures | CWE-307 | Improper Restriction of Excessive Auth Attempts | SSH 爆破、PAM 后门绕过认证 | T1110 |
| A08:2021 Software/Data Integrity | CWE-503 | Non-Verifiable Integrity | APT hooks 注入、dpkg 脚本篡改、包管理器后门 | T1547.013 |
| A09:2021 Logging Failures | CWE-778 | Insufficient Logging | 攻击者清除 .bash_history、篡改 journald | T1070.003 |
| A10:2021 SSRF | CWE-918 | Server-Side Request Forgery | 云元数据 API SSRF 导致 IAM 凭证泄露到 Linux 实例 | T1552.005 |

---

## Sigma 检测规则

### Sigma 规则 1: 反弹 Shell 检测

```yaml
title: Linux Reverse Shell Connection Detected
id: 8f1c2a3b-4d5e-6789-abcd-ef0123456789
status: experimental
description: >
    Detects potential reverse shell connections via common bash/tcp, netcat,
    or python/perl socket patterns on Linux systems.
references:
    - https://attack.mitre.org/techniques/T1059/004/
    - https://attack.mitre.org/techniques/T1571/
author: SecSkill Evolution
 date: 2026/06/24
logsource:
    product: linux
    service: syslog
detection:
    selection_cmd:
        message|contains:
            - '/dev/tcp/'
            - '/dev/udp/'
            - 'bash -i'
            - 'nc -e'
            - 'ncat -e'
            - 'socat TCP:'
    selection_python:
        message|contains|all:
            - 'socket'
            - 'subprocess'
            - 'pty'
    selectionperl:
        message|contains|all:
            - 'IO::Socket'
            - 'exec'
    condition: selection_cmd or selection_python or selection_perl
falsepositives:
    - Legitimate administrative scripts using network sockets
    - Monitoring tools using persistent connections
level: high
tags:
    - attack.execution
    - attack.t1059.004
    - attack.command_and_control
    - attack.t1571
```

### Sigma 规则 2: 持久化机制检测（systemd + cron + LD_PRELOAD）

```yaml
title: Linux Persistence Mechanism Created or Modified
id: 9a2b3c4d-5e6f-7890-abcd-ef1234567890
status: experimental
description: >
    Detects creation or modification of systemd services, cron jobs,
    LD_PRELOAD configuration, and PAM modules — common Linux persistence vectors.
references:
    - https://attack.mitre.org/techniques/T1543/002/
    - https://attack.mitre.org/techniques/T1053/003/
    - https://attack.mitre.org/techniques/T1574/006/
author: SecSkill Evolution
date: 2026/06/24
logsource:
    product: linux
    service: file_event
detection:
    selection_systemd:
        TargetFilename|contains:
            - '/etc/systemd/system/'
            - '/.config/systemd/user/'
        TargetFilename|endswith: '.service'
    selection_cron:
        TargetFilename|contains:
            - '/etc/cron.d/'
            - '/etc/cron.hourly/'
            - '/etc/cron.daily/'
            - '/var/spool/cron/'
    selection_preload:
        TargetFilename: '/etc/ld.so.preload'
    selection_pam:
        TargetFilename|contains: '/etc/pam.d/'
    condition: selection_systemd or selection_cron or selection_preload or selection_pam
falsepositives:
    - Package installation updating service files
    - Administrator configuring legitimate cron jobs
level: medium
tags:
    - attack.persistence
    - attack.t1543.002
    - attack.t1053.003
    - attack.t1574.006
    - attack.t1556.003
```

---

## YARA 规则

### YARA 规则 1: ELF 恶意软件通用检测

```yara
rule Linux_ELF_Generic_Malware {
    meta:
        description = "Detects common patterns in Linux ELF malware"
        author = "SecSkill Evolution"
        date = "2026-06-24"
        reference = "ATT&CK T1059.004, T1620"
    strings:
        $elf_header = { 7f 45 4c 46 }
        $rev_shell1 = "/dev/tcp/" ascii
        $rev_shell2 = "/dev/udp/" ascii
        $rev_shell3 = "bash -i" ascii
        $rev_shell4 = "nc -e" ascii nocase
        $mining1 = "stratum+tcp" ascii nocase
        $mining2 = "cryptonight" ascii nocase
        $mining3 = "xmrig" ascii nocase
        $curl_pipe = "curl" ascii
        $wget_pipe = "wget" ascii
        $bash_pipe = "| bash" ascii
        $base64_d = "base64 -d" ascii nocase
    condition:
        $elf_header at 0 and (
            3 of ($rev_shell*) or
            2 of ($mining*) or
            ($curl_pipe and $bash_pipe) or
            ($wget_pipe and $bash_pipe) or
            $base64_d
        )
}
```

### YARA 规则 2: BPFDoor/Symbiote 后门特征

```yara
rule Linux_BPFDoor_Symbiote_Backdoor {
    meta:
        description = "Detects BPFDoor and Symbiote eBPF/LD_PRELOAD backdoor families"
        author = "SecSkill Evolution"
        date = "2026-06-24"
        reference = "ATT&CK T1014, T1205.002, T1574.006"
    strings:
        $bpfdoor_proc1 = "kdmtmpflush" ascii
        $bpfdoor_proc2 = "dbus-srv" ascii
        $bpfdoor_proc3 = "hald-addon" ascii
        $bpfdoor_proc4 = "irqbalanced" ascii
        $bpfdoor_port = "42391" ascii
        $bpfdoor_port2 = "43391" ascii
        $bpfdoor_magic = { 53 59 4e 43 4f 4d 4d }  // "SYNCOMM"
        $symbiote_ldpreload = "ld.so.preload" ascii
        $symbiote_hook1 = "__libc_start_main" ascii
        $symbiote_hook2 = "ptrace" ascii
        $af_packet = "AF_PACKET" ascii
        $packet_recv = "packet_recvmsg" ascii
    condition:
        any of ($bpfdoor_proc*) or
        any of ($bpfdoor_port*) or
        $bpfdoor_magic or
        (2 of ($symbiote*) and $af_packet) or
        $packet_recv
}
```

---

## CVE 参考表

Linux 应急响应中高频出现的 CVE 及其检测方法：

| CVE ID | 漏洞名称 | CVSS | ATT&CK | Linux IR 检测要点 |
|--------|---------|------|--------|------------------|
| CVE-2024-3094 | XZ Utils 后门 (liblzma) | 10.0 | T1195.002 | 检查 liblzma.so 版本、sshd 进程异常、SSH 认证后门 |
| CVE-2024-1086 | Linux Kernel nf_tables LPE | 7.8 | T1068 | 检查 nf_tables 模块加载、内核版本 <=5.14.21 |
| CVE-2023-32233 | Linux Kernel Netfilter nft_set UAF | 7.8 | T1068 | nft_set 模块使用、内核版本范围 5.x-6.x |
| CVE-2022-0847 | Dirty Pipe | 7.8 | T1068 | 检查 /etc/passwd 覆写、内核 5.8-5.16.10 |
| CVE-2021-4034 | PwnKit (pkexec LPE) | 7.8 | T1548.001 | pkexec SUID 检查、GUEST 相关环境变量 |
| CVE-2021-3156 | Sudo Heap Overflow (Baron Samedit) | 7.8 | T1548.001 | sudo 版本 < 1.9.5p2、/etc/passwd 异常创建 |
| CVE-2019-5736 | runc Container Escape |  8.6 | T1611 | 容器内 runc 版本、宿主机进程异常 |
| CVE-2014-0160 | Heartbleed (OpenSSL) | 7.5 | T1552 | OpenSSL 版本检查、内存泄露痕迹 |

---

## IOC 采集指引

Linux IR 完成后应提取以下 IOC 并转发至威胁情报平台：

| 优先级 | IOC 类型 | 采集方法 | 存储格式 | 转发目标 |
|--------|---------|---------|---------|--------|
| 🔴 高 | C2 IP:Port | `ss -tunp` / `netstat` / `/proc/net/tcp` | IP:Port | ip-analysis |
| 🔴 高 | 恶意域名 | DNS 日志 `/var/log/syslog` + `/etc/resolv.conf` | domain | domain-analysis |
| 🔴 高 | 恶意文件 Hash | `sha256sum /tmp/*` / 文件系统扫描 | SHA256 | binary-reverse-engineering |
| 🔴 高 | C2 URL | 进程命令行参数 + bash_history | URL | url-analysis |
| 🟡 中 | 恶意 systemd 服务 | `/etc/systemd/system/*.service` 内容 | service文件+hash | ttp-extractor |
| 🟡 中 | SSH 后门公钥 | `authorized_keys` 全量提取 | SSH公钥 | auth-log-analysis |
| 🟡 中 | 恶意内核模块 | `lsmod` + `/lib/modules/**/*.ko` | 模块名+hash | binary-reverse-engineering |
| 🟡 中 | LD_PRELOAD 库 | `/etc/ld.so.preload` + `/proc/*/environ` | .so文件+hash | binary-reverse-engineering |
| 🟢 低 | 恶意 cron 条目 | `/etc/cron.d/*` + `crontab -l -u *` | cron表达式 | ttp-extractor |
| 🟢 低 | Webshell 路径 | `/var/www/**/*.php` + access log | 文件路径+hash | code-audit |

---

## 合规标准参考表

| 标准 | 相关章节 | Linux IR 要求 |
|------|---------|--------------|
| ISO/IEC 27001 | A.16.1 Incident Management | 事件响应流程、取证保留、根因分析 |
| ISO/IEC 27035 | Phase 4 Detection & Identification | 安全事件检测、日志分析、告警分类 |
| NIST SP 800-61 | 3.2 Containment | 隔离受感染主机、防止横向移动 |
| NIST SP 800-86 | Section 3 | 收集和保全数字证据、内存取证、磁盘镜像 |
| NIST SP 800-92 | Section 4 | 日志管理策略、syslog/journald 配置 |
| 等保2.0 第八章 | 8.1.3 入侵防范 | 主机入侵检测、恶意代码防范、入侵告警 |
| 等保2.0 第九章 | 9.1.4 安全审计 | 安全审计日志、日志留存≥6个月、集中分析 |
| GDPR | Art.33 | 72小时内向监管机构报告数据泄露事件 |
| PIPL | 第57条 | 个人信息泄露事件应急响应、通知义务 |
| PCI DSS | 12.10 | 事件响应计划、证据收集、取证分析 |
| SOC 2 | CC7.3 | 安全事件检测、应急响应、恢复 |

---

## 跨技能生态工作流

| 场景 | 上游技能 → 本技能 → 下游技能 | 数据流 |
|------|-------------------------------|--------|
| 主机入侵响应 | traffic-analysis → **linux-ir** → binary-reverse-engineering | 流量告警 → 主机取证 → 恶意样本逆向 |
| 持久化清除 | auth-log-analysis → **linux-ir** → ttp-extractor | 认证异常 → 主机检查 → TTP 提取归档 |
| 挖矿木马处置 | asset-monitor → **linux-ir** → ip-analysis | 资产告警 → 主机检查 → C2 IP 分析 |
| 供应链事件 | code-audit → **linux-ir** → pdf-report | 代码投毒 → 主机影响评估 → IR 报告 |
| 容器安全事件 | asset-discovery → **linux-ir** → data-desensitize | 容器逃逸 → 主机影响范围 → 敏感数据脱敏 |

---

## 报告模板

详见 [references/report-format.md](references/report-format.md)

## 附加资源

- [references/attack-techniques.md](references/attack-techniques.md) - Linux ATT&CK 技术详解
- [references/linux-threats.md](references/linux-threats.md) - 2024-2025 Linux 威胁情报
- [references/vql-advanced.md](references/vql-advanced.md) - 高级 VQL 狩猎查询
- [references/vql-community.md](references/vql-community.md) - 社区 VQL 查询库
