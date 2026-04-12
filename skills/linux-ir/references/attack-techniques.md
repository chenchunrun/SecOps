# Linux ATT&CK 技术检测参考

## 持久化 (Persistence - TA0003)

### T1543.002 - Systemd Service

**描述**: 攻击者创建或修改 systemd 服务实现持久化。

**检测位置**:
- `/etc/systemd/system/*.service`
- `/lib/systemd/system/*.service`
- `/home/*/.config/systemd/user/*.service`

**检测命令**:
```bash
# 查找最近修改的服务
find /etc/systemd/system -name '*.service' -mtime -7 -ls

# 检查可疑 ExecStart
grep -r 'ExecStart=.*/tmp/\|/dev/shm\|curl\|wget\|base64' /etc/systemd/system/
```

**可疑特征**:
- ExecStart 指向 /tmp、/dev/shm
- ExecStart 包含 curl|sh、wget|bash
- 服务名与系统服务相似 (伪装)
- 最近创建且非包管理器安装

---

### T1053.003 - Cron

**描述**: 使用 cron 定时任务实现持久化。

**检测位置**:
- `/etc/crontab`
- `/etc/cron.d/*`
- `/var/spool/cron/crontabs/*`
- `/etc/cron.{hourly,daily,weekly,monthly}/`

**检测命令**:
```bash
# 所有 crontab
cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null

# 可疑命令
grep -rE 'curl|wget|python|perl|nc\s|/tmp/' /etc/cron* /var/spool/cron/
```

**可疑特征**:
- 下载并执行远程脚本
- 执行 /tmp 或隐藏目录中的文件
- 高频率执行 (每分钟)
- 重定向输出到 /dev/null

---

### T1546.004 - Unix Shell Configuration

**描述**: 修改 shell 配置文件实现登录时执行恶意代码。

**检测位置**:
- `/etc/profile`, `/etc/profile.d/*.sh`
- `/etc/bash.bashrc`, `/etc/bashrc`
- `~/.bashrc`, `~/.bash_profile`, `~/.profile`
- `~/.zshrc`

**检测命令**:
```bash
# 检查可疑命令
grep -rE '^[^#]*(curl|wget|python.*http|nc\s+-|/dev/tcp)' /etc/profile* ~/.bashrc ~/.zshrc
```

---

### T1098.004 - SSH Authorized Keys

**描述**: 添加 SSH 公钥实现持久访问。

**检测位置**:
- `~/.ssh/authorized_keys`
- `/root/.ssh/authorized_keys`

**检测命令**:
```bash
# 查找所有 authorized_keys
find /home /root -name 'authorized_keys' -ls

# 检查最近修改
find /home /root -name 'authorized_keys' -mtime -7
```

---

### T1547.006 - Kernel Modules

**描述**: 加载恶意内核模块实现持久化和隐藏。

**检测命令**:
```bash
# 已加载模块
lsmod

# 检查非标准模块
lsmod | grep -vE 'nvidia|nouveau|iwl|ath|virtio|kvm'

# 内核污染状态
cat /proc/sys/kernel/tainted
```

---

## 权限提升 (Privilege Escalation - TA0004)

### T1548.001 - Setuid/Setgid

**描述**: 利用 SUID/SGID 程序提权。

**检测命令**:
```bash
# 查找异常位置的 SUID 文件
find /tmp /var/tmp /home /dev/shm -perm -4000 -type f 2>/dev/null

# 查找所有 SUID
find / -perm -4000 -type f 2>/dev/null
```

---

### T1548.003 - Sudo Caching

**描述**: 利用 sudo 缓存或配置不当提权。

**检测命令**:
```bash
# 检查 sudoers
cat /etc/sudoers
cat /etc/sudoers.d/*

# 危险配置
grep -E 'NOPASSWD|ALL.*ALL' /etc/sudoers /etc/sudoers.d/*
```

---

## 防御规避 (Defense Evasion - TA0005)

### T1014 - Rootkit

**描述**: 使用 Rootkit 隐藏进程、文件、网络连接。

**检测命令**:
```bash
# /proc vs ps 对比
ls -d /proc/[0-9]* | wc -l
ps -e | wc -l

# 检查 /etc/ld.so.preload
cat /etc/ld.so.preload

# 检查已删除但运行的进程
ls -la /proc/*/exe 2>/dev/null | grep deleted
```

---

### T1574.006 - LD_PRELOAD

**描述**: 使用 LD_PRELOAD 劫持动态链接库。

**检测位置**:
- `/etc/ld.so.preload`
- 环境变量 `LD_PRELOAD`
- `/etc/ld.so.conf.d/`

**检测命令**:
```bash
# 检查 ld.so.preload
cat /etc/ld.so.preload

# 检查进程环境变量
grep -l LD_PRELOAD /proc/*/environ 2>/dev/null
```

---

### T1070.003 - Clear Command History

**描述**: 清除命令历史隐藏活动痕迹。

**检测命令**:
```bash
# 检查历史文件大小
ls -la ~/.bash_history ~/.zsh_history

# 检查 HISTFILE 环境变量
env | grep HIST

# 检查 unset 或重定向
grep -E 'HISTFILE|HISTSIZE=0|/dev/null' ~/.bashrc ~/.zshrc
```

---

### T1556.003 - PAM Modification

**描述**: 修改 PAM 配置植入后门。

**检测命令**:
```bash
# 检查 PAM 配置修改
find /etc/pam.d -mtime -7 -ls

# 检查可疑模块
grep -rE 'pam_exec|pam_script' /etc/pam.d/
```

---

## 凭据访问 (Credential Access - TA0006)

### T1552.001 - Credentials in Files

**描述**: 搜索文件中的凭据信息。

**常见位置**:
- `/etc/shadow`
- `~/.ssh/id_rsa`
- 配置文件中的密码
- `.bash_history` 中的敏感命令

---

### T1552.004 - Private Keys

**描述**: 窃取 SSH 私钥。

**检测命令**:
```bash
# 查找私钥文件
find /home /root -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null

# 检查访问时间
find /home /root -name 'id_*' -atime -7 2>/dev/null
```

---

## 命令与控制 (Command and Control - TA0011)

### T1571 - Non-Standard Port

**描述**: 使用非标准端口进行 C2 通信。

**检测命令**:
```bash
# 非标准端口外连
ss -tunp | grep ESTAB | grep -vE ':80|:443|:22|:53'

# 高危端口监听
ss -tlnp | grep -E ':4444|:5555|:6666|:1337'
```

---

### T1572 - Protocol Tunneling

**描述**: 使用协议隧道进行通信。

**检测命令**:
```bash
# DNS 隧道 (大量 DNS 连接)
ss -tunp | grep ':53'

# ICMP 隧道
ping -c 1 127.0.0.1 &
ps aux | grep ping
```

---

## 容器相关 (Container)

### T1610 - Deploy Container

**描述**: 部署恶意容器。

**检测命令**:
```bash
# 运行中的容器
docker ps

# 可疑镜像
docker images | grep -iE 'hack|shell|miner'
```

---

### T1611 - Escape to Host

**描述**: 从容器逃逸到宿主机。

**检测命令**:
```bash
# 特权容器
docker ps -q | xargs docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}}'

# 危险挂载
docker ps -q | xargs docker inspect --format '{{.Name}} {{.Mounts}}'
```

---

## 快速检测矩阵

| ATT&CK ID | 技术名称 | 快速检测命令 |
|-----------|----------|--------------|
| T1543.002 | Systemd Service | `find /etc/systemd/system -mtime -7` |
| T1053.003 | Cron | `crontab -l; cat /etc/cron.d/*` |
| T1098.004 | SSH Keys | `find /home -name authorized_keys -mtime -7` |
| T1014 | Rootkit | `cat /etc/ld.so.preload` |
| T1574.006 | LD_PRELOAD | `grep LD_PRELOAD /proc/*/environ` |
| T1548.001 | SUID | `find /tmp -perm -4000` |
| T1571 | Non-Standard Port | `ss -tlnp \| grep -E ':4444\|:5555'` |
| T1610 | Container | `docker ps` |
| T1611 | Container Escape | `docker inspect --format '{{.HostConfig.Privileged}}'` |
