# Linux 威胁情报参考

## 2024-2025 高危威胁

### 1. 挖矿木马 (Cryptominer)

#### 常见家族
- **XMRig**: 最流行的门罗币挖矿程序
- **kdevtmpfsi/kinsing**: 针对云环境的挖矿僵尸网络
- **TeamTNT**: 针对 Docker/K8s 的挖矿团伙
- **WatchDog**: 长期活跃的挖矿僵尸网络
- **Outlaw/Shellbot**: SSH 爆破传播的挖矿僵尸网络
- **8220 Gang**: 利用 Oracle WebLogic 漏洞传播
- **Lemon Duck**: 跨平台挖矿蠕虫
- **Sysrv**: Go 语言编写的挖矿蠕虫
- **z0Miner**: 利用 Confluence/Weblogic 漏洞传播

#### 检测特征

**进程特征**:
```bash
# 常见进程名
ps aux | grep -iE 'xmrig|minerd|kdevtmpfsi|kinsing|watchdog|dbused|.x11|xmr'

# CPU 占用异常
ps aux --sort=-%cpu | head -10

# 伪装成系统进程
ps aux | grep -E 'kworker[0-9]{3,}|kthread[0-9]'
```

**网络特征**:
```bash
# 常见矿池端口
ss -tunp | grep -E ':3333|:4444|:5555|:7777|:8888|:14433|:45700'

# 矿池域名
cat /etc/hosts | grep -iE 'pool|xmr|mine'
```

**文件特征**:
- `/tmp/.X11-unix/`, `/tmp/.ICE-unix/` 下的可执行文件
- `/var/tmp/` 下的隐藏文件
- `/dev/shm/` 下的挖矿程序

**持久化**:
```bash
# crontab
grep -rE 'xmrig|kdevtmpfsi|curl.*\|.*sh' /etc/cron* /var/spool/cron/

# systemd
grep -rE 'ExecStart.*/tmp/|/dev/shm' /etc/systemd/system/
```

---

### 2. 云环境攻击

#### AWS/GCP/Azure Metadata 滥用

**检测**:
```bash
# 进程访问 metadata
ps aux | grep -E '169.254.169.254|metadata'

# 网络连接
ss -tunp | grep '169.254.169.254'

# 历史命令
grep -rE 'curl.*169.254.169.254|wget.*169.254.169.254' ~/.bash_history ~/.zsh_history
```

**IMDS 凭据窃取特征**:
- 访问 `/latest/meta-data/iam/security-credentials/`
- 访问 `/computeMetadata/v1/`
- 环境变量中的 AWS_ACCESS_KEY_ID

---

### 3. 容器逃逸

#### Docker Socket 挂载

**检测**:
```bash
# 检查 socket
ls -la /var/run/docker.sock

# 容器内检测
if [ -S /var/run/docker.sock ]; then echo "Docker socket mounted!"; fi
```

#### 特权容器逃逸

**检测**:
```bash
# 宿主机检查
docker ps -q | xargs docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}'

# 容器内检查
cat /proc/self/status | grep Cap
```

#### CVE-2022-0847 (Dirty Pipe)

**影响**: Linux 5.8 - 5.16.11
**检测**:
```bash
uname -r  # 检查内核版本
```

---

### 4. Rootkit

#### 用户态 Rootkit

**Jynx2**:
- 位置: `/lib/security/`, `/lib64/security/`
- 特征: 修改 PAM 配置

**Azazel**:
- 位置: `/lib/libselinux.so`
- 特征: LD_PRELOAD 劫持

**检测**:
```bash
# ld.so.preload
cat /etc/ld.so.preload

# 异常共享库
ldd /bin/ls | grep -v '^/'
```

#### 内核态 Rootkit

**Reptile**:
- 特征: 隐藏进程、文件、网络连接
- 检测: `cat /proc/modules | grep -i reptile`

**Diamorphine**:
- 特征: 通过 signal 控制
- 检测: 发送 signal 63/64 观察行为

**通用检测**:
```bash
# 模块隐藏检测
ls /sys/module | wc -l
lsmod | wc -l

# 内核污染
cat /proc/sys/kernel/tainted
```

---

### 5. 供应链攻击

#### XZ Utils 后门 (CVE-2024-3094)

**影响版本**: xz 5.6.0, 5.6.1

**检测**:
```bash
xz --version
# 受影响版本应立即降级或更新

# 检查 sshd 是否链接到 liblzma
ldd $(which sshd) | grep lzma
```

#### Python pip 投毒 (参考 LinuxCheck)

**已知恶意包列表**:
```
# Typosquatting 仿冒包
python3-dateutil      # 仿冒 python-dateutil
jeIlyfish             # 仿冒 jellyfish (大写I)
beautifulsup4         # 仿冒 beautifulsoup4
cllorama              # 仿冒 colorama
colourama             # 仿冒 colorama
djanga                # 仿冒 django
httplib3              # 仿冒 httplib2
numpyx                # 仿冒 numpy
matlolib              # 仿冒 matplotlib
openvc                # 仿冒 opencv
opencv-python4        # 仿冒 opencv-python
setup-tools           # 仿冒 setuptools
virtualnv             # 仿冒 virtualenv
virtaulenv            # 仿冒 virtualenv
colourfull            # 仿冒 colorful

# 恶意包
python-sqlite, libpeshnern, libpeshka, libari
libtoolz, libzeffyr, craborern, ffloaps
maratlib, maratlib1, pipsqlite, pylogging
pysqlite2, pysqlite3, pywget, sqlitedict
```

**检测**:
```bash
# 检查已安装的 pip 包
pip3 list --format=freeze 2>/dev/null | grep -iE 'python3-dateutil|jeIlyfish|beautifulsup4|cllorama|djanga|httplib3|numpyx|matlolib|setup-tools|virtualnv'

# 检查最近安装的包
find /usr/lib/python*/site-packages /usr/local/lib/python*/site-packages ~/.local/lib/python*/site-packages -maxdepth 1 -type d -mtime -7 2>/dev/null
```

#### npm 恶意包

**可疑特征**:
```bash
# 包名检查
npm list -g --depth=0 2>/dev/null | grep -iE 'crypto|wallet|password|stealer|logger|keylogger'

# postinstall 脚本检查
find /home -path '*/node_modules/*/package.json' -exec grep -l 'postinstall' {} \; 2>/dev/null
```

#### Redis 未授权访问攻击

**检测**:
```bash
# 检查 Redis 是否绑定到公网
ss -tlnp | grep ':6379' | grep '0.0.0.0'

# 检查无密码访问
redis-cli ping 2>/dev/null | grep -q PONG && echo "Redis 无密码!"

# 检查可疑配置
redis-cli config get dir 2>/dev/null
redis-cli config get dbfilename 2>/dev/null
```

**攻击模式**:
- 写入 SSH 公钥: `config set dir /root/.ssh/`
- 写入 Crontab: `config set dir /var/spool/cron/`
- 写入 Webshell: `config set dir /var/www/html/`

#### JDWP 远程代码执行

**检测**:
```bash
# JDWP 端口
ss -tlnp | grep -E ':5005|:8000|:8787|:9999'

# Java 进程调试参数
ps aux | grep -E 'agentlib:jdwp|Xdebug|Xrunjdwp'
```

#### Docker Remote API 未授权

**检测**:
```bash
# 检查暴露的端口
ss -tlnp | grep -E ':2375|:2376'

# 尝试访问
curl -s --connect-timeout 2 http://127.0.0.1:2375/version

# 配置文件检查
cat /etc/docker/daemon.json | grep -E 'hosts|tls'
```

---

### 6. Webshell

#### 中国菜刀 (Chopper)

**特征**:
- 单行一句话木马
- 参数名通常为 `z0`, `z1`, `z2`
- 使用 `@eval($_POST[xxx])` 形式

**检测**:
```bash
# 菜刀特征
grep -rE '@eval\s*\(\s*\$_(POST|GET|REQUEST)' /var/www/ 2>/dev/null
grep -rE '\$_(POST|GET)\[["\x27](z0|z1|cmd|pass)["\x27]\]' /var/www/ 2>/dev/null
```

#### 蚁剑 (AntSword)

**特征**:
- 支持多种编码器 (base64, chr, rot13)
- 特征函数: `base64_decode` + `eval`
- 可自定义连接密码

**检测**:
```bash
# 蚁剑编码特征
grep -rE '@eval\s*\(\s*base64_decode' /var/www/ 2>/dev/null
grep -rE 'chr\([0-9]+\)\.chr\([0-9]+\)' /var/www/ 2>/dev/null
grep -rE 'str_rot13\s*\(\s*base64_decode' /var/www/ 2>/dev/null
```

#### 冰蝎 (Behinder)

**特征**:
- AES 加密通信
- 2.0: `openssl_decrypt` / `mcrypt_decrypt`
- 3.0: 自定义类 + 反射执行
- 4.0: 支持传输协议 (HTTP/HTTPS/ICMP/DNS)

**检测**:
```bash
# 冰蝎 2.0
grep -rE 'openssl_decrypt|mcrypt_decrypt.*AES' /var/www/ 2>/dev/null

# 冰蝎 3.0
grep -rE 'class\s+\w+\s*\{.*@session_start.*\$_(POST|GET)' /var/www/ 2>/dev/null
grep -rE '\$key\s*=\s*["\x27][a-f0-9]{16}["\x27]' /var/www/ 2>/dev/null

# 冰蝎 4.0
grep -rE 'Decrypt\s*\(\s*\$data.*AES-128' /var/www/ 2>/dev/null
```

#### 哥斯拉 (Godzilla)

**特征**:
- 多编码器支持
- 免杀能力强
- `@session_start()` + `@set_time_limit`
- 特征字符串: `pass=`, `methodName`

**检测**:
```bash
# 哥斯拉特征
grep -rE 'session_start\s*\(\s*\)\s*;.*@set_time_limit' /var/www/ 2>/dev/null
grep -rE 'pass\s*=\s*["\x27].*["\x27]\s*;.*@eval' /var/www/ 2>/dev/null
grep -rE '\$methodName\s*=\s*\$_(POST|GET)' /var/www/ 2>/dev/null
```

#### Weevely

**特征**:
- Python 编写的 Webshell 生成器
- 使用 str_replace 混淆

**检测**:
```bash
grep -rE 'str_replace\(["\x27].*["\x27]\s*,\s*["\x27]["\x27]\s*,\s*\$' /var/www/ 2>/dev/null
```

#### PHP 通用检测

**常见位置**:
- `/var/www/html/`
- `/var/www/*/`
- Web 应用上传目录

**检测**:
```bash
# 危险函数
grep -rE 'eval\(|base64_decode|system\(|passthru|shell_exec|exec\(|assert\(' /var/www/ 2>/dev/null

# 动态函数调用
grep -rE '\$\w+\s*\(\s*\$' /var/www/ 2>/dev/null

# 可疑文件名
find /var/www -name '*.php' | grep -iE 'shell|hack|cmd|backdoor|c99|r57|b374k'

# 最近修改的 PHP
find /var/www -name '*.php' -mtime -7 -ls
```

#### JSP Webshell

**检测**:
```bash
# 命令执行
grep -rE 'Runtime.getRuntime|ProcessBuilder' /var/lib/tomcat/ 2>/dev/null

# 冰蝎 JSP
grep -rE 'AES/ECB/PKCS5Padding|javax.crypto.Cipher' /var/lib/tomcat/ 2>/dev/null

# 最近修改
find /var/lib/tomcat -name '*.jsp' -mtime -7 -ls
```

#### ASP/ASPX Webshell

**检测**:
```bash
# ASP 危险函数
grep -rE 'Execute\(|Eval\(|CreateObject' /var/www/ 2>/dev/null

# ASPX 反射执行
grep -rE 'Assembly\.Load|Reflection\.Assembly' /var/www/ 2>/dev/null
```

---

### 7. SSH 后门

#### SSH Wrapper

**检测**:
```bash
# 检查 sshd 是否被替换
file $(which sshd)
ls -la /usr/sbin/sshd

# 检查 PAM
grep -rE 'pam_exec|pam_script' /etc/pam.d/sshd
```

#### SSH Motd 后门

**检测**:
```bash
# 检查 motd 脚本
ls -la /etc/update-motd.d/
cat /etc/update-motd.d/*
```

---

### 8. 勒索软件

#### Linux 勒索软件家族

- **LockBit 3.0**: 支持 Linux/ESXi
- **BlackCat/ALPHV**: Rust 编写，跨平台
- **Hive**: 针对 Linux 服务器
- **ESXiArgs**: 针对 VMware ESXi

**检测**:
```bash
# 文件加密特征
find / -name '*.encrypted' -o -name '*.locked' -o -name 'README.txt' 2>/dev/null | head -20

# 可疑进程
ps aux | grep -iE 'encrypt|ransom|locker'

# 大量文件操作
lsof | grep -E 'open|write' | wc -l
```

---

## IOC 速查表

### 恶意 IP 范围 (示例)

> 注: 以下为示例，实际应参考威胁情报平台

```
# TeamTNT
45.9.148.0/24

# Kinsing
194.38.20.0/24
```

### 恶意域名特征

```bash
# 矿池相关
*pool*.*
*xmr*.*
*monero*.*

# C2 特征
*.onion
*.tk, *.ml, *.ga (免费域名)
```

### 常见 C2 端口

| 端口 | 用途 |
|------|------|
| 4444 | Metasploit 默认 |
| 5555 | Android ADB |
| 6666 | 常见后门 |
| 1337 | "Leet" 端口 |
| 31337 | Back Orifice |
| 8888 | 常见反弹 shell |
| 9999 | 常见反弹 shell |

### 可疑进程名

```
# 伪装系统进程
kworker/0:1+events  # 正常
kworker12345        # 可疑

# 常见恶意进程
.x11
.rsync
.sshd
bioset
```

---

## 威胁情报源

### 开源情报

- [Abuse.ch](https://abuse.ch/) - 恶意软件/僵尸网络
- [AlienVault OTX](https://otx.alienvault.com/) - 开放威胁情报
- [VirusTotal](https://www.virustotal.com/) - 文件/URL 分析
- [Shodan](https://www.shodan.io/) - 互联网设备搜索

### Linux 特定

- [The DFIR Report](https://thedfirreport.com/) - 详细入侵分析
- [Trend Micro Research](https://www.trendmicro.com/en_us/research.html)
- [Aqua Security Blog](https://blog.aquasec.com/) - 容器安全

### CVE 追踪

- [NVD](https://nvd.nist.gov/)
- [Linux Kernel CVEs](https://www.linuxkernelcves.com/)

---

## 环境变量攻击 (参考 LinuxCheck)

### LD_PRELOAD 劫持

**原理**: 通过 LD_PRELOAD 环境变量预加载恶意共享库

**检测**:
```bash
# 环境变量检查
env | grep LD_PRELOAD

# 系统配置检查
cat /etc/ld.so.preload

# 进程环境变量
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD
```

### LD_LIBRARY_PATH 劫持

**原理**: 修改库搜索路径，优先加载恶意库

**检测**:
```bash
env | grep LD_LIBRARY_PATH
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep LD_LIBRARY_PATH
```

### PROMPT_COMMAND 后门

**原理**: Bash 每次显示提示符前执行此变量中的命令

**检测**:
```bash
env | grep PROMPT_COMMAND
grep PROMPT_COMMAND ~/.bashrc ~/.bash_profile /etc/profile /etc/bash.bashrc
```

### Alias 后门

**原理**: 通过 alias 劫持常用命令

**检测**:
```bash
# 可疑 alias
alias | grep -iE 'curl|wget|python|nc|bash|sh|chmod|rm|mv|cp|sudo'

# 检查配置文件
grep -E '^alias' ~/.bashrc ~/.bash_profile /etc/profile.d/*.sh 2>/dev/null
```

---

## SSH 爆破分析 (参考 Emergency-Response-Notes)

### 日志分析

**Debian/Ubuntu**: `/var/log/auth.log`
**RHEL/CentOS**: `/var/log/secure`

**快速分析**:
```bash
# 失败登录 IP TOP 20
grep "Failed password" /var/log/auth.log | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort | uniq -c | sort -rn | head -20

# 爆破后成功登录 (危险!)
for ip in $(grep "Failed password" /var/log/auth.log | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | awk '$1>10{print $2}'); do
    grep "Accepted" /var/log/auth.log | grep -q "$ip" && echo "[!] $ip 爆破后成功登录"
done

# 失败登录用户名
grep "Failed password" /var/log/auth.log | grep -oE 'for .+ from' | sed 's/for //' | sed 's/ from//' | sort | uniq -c | sort -rn | head -20
```

### 时间线分析

```bash
# 按小时统计失败登录
grep "Failed password" /var/log/auth.log | awk '{print $3}' | cut -d: -f1 | sort | uniq -c | sort -rn

# 今日失败登录
today=$(date '+%b %e')
grep "Failed password" /var/log/auth.log | grep "^$today"
```

---

## ATT&CK 技术映射

| 技术 ID | 技术名称 | 检测脚本 |
|---------|----------|----------|
| T1059.004 | Unix Shell | quick_scan.sh |
| T1053.003 | Cron | deep_persistence.sh |
| T1543.002 | Systemd Service | deep_persistence.sh |
| T1547.006 | Kernel Modules | rootkit_check.sh |
| T1014 | Rootkit | rootkit_check.sh |
| T1496 | Resource Hijacking | miner_check.sh |
| T1505.003 | Web Shell | webshell_check.sh |
| T1195.001 | Supply Chain Compromise | supply_chain_check.sh |
| T1552.001 | Credentials in Files | forensic_artifacts.sh |
| T1110.001 | Password Guessing | forensic_artifacts.sh (SSH爆破分析) |
| T1612 | Container Escape | container_check.sh |
