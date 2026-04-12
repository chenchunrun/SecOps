# VQL 社区查询库

Velociraptor VQL 威胁狩猎查询，来源于社区最佳实践。

## 目录

1. [无文件恶意软件检测](#无文件恶意软件检测)
2. [eBPF/BPF 后门检测](#ebpfbpf-后门检测)
3. [高级持久化检测](#高级持久化检测)
4. [进程能力检测](#进程能力检测)
5. [协议隧道检测](#协议隧道检测)
6. [Living off the Land](#living-off-the-land)

---

## 无文件恶意软件检测

### memfd_create 检测 (T1620)

```sql
-- memfd 执行的进程
SELECT Pid, Name, Exe, CommandLine, Username
FROM pslist()
WHERE Exe =~ 'memfd:' OR Exe =~ '/memfd:.*\(deleted\)'

-- 已删除但运行的进程
SELECT Pid, Name, Exe, CommandLine
FROM pslist()
WHERE Exe =~ '\(deleted\)'

-- 恢复 memfd 二进制
SELECT Pid, Name, Exe,
  copy(filename=format(format='/proc/%d/exe', args=[Pid]),
       dest=format(format='/tmp/recovered_%d', args=[Pid])) AS Recovered
FROM pslist()
WHERE Exe =~ 'memfd:'
```

### 内存映射异常

```sql
-- 检查匿名可执行内存段
SELECT Pid, Name, count() AS AnonExecCount
FROM foreach(
  row={SELECT Pid, Name FROM pslist()},
  query={
    SELECT Pid, Name
    FROM parse_lines(filename=format(format='/proc/%d/maps', args=[Pid]))
    WHERE Line =~ '^[0-9a-f]+-[0-9a-f]+.*x.*\s+0\s+00:00\s+0\s*$'
  }
)
GROUP BY Pid, Name
HAVING AnonExecCount > 10
```

### 无环境变量进程

```sql
-- 缺少环境变量的用户进程 (可疑)
SELECT Pid, Name, Exe
FROM pslist()
WHERE NOT Name =~ '^k' AND
  stat(filename=format(format='/proc/%d/environ', args=[Pid])).Size = 0
```

---

## eBPF/BPF 后门检测

### BPFDoor 特征

```sql
-- packet_recvmsg 等待进程
SELECT Pid, Name, Exe
FROM foreach(
  row={SELECT Pid, Name, Exe FROM pslist()},
  query={
    SELECT Pid, Name, Exe
    FROM parse_lines(filename=format(format='/proc/%d/stack', args=[Pid]))
    WHERE Line =~ 'packet_recvmsg|wait_for_more_packets'
  }
)

-- BPFDoor 端口范围 42391-43391
SELECT Pid, Name, Laddr
FROM netstat()
WHERE Status = 'LISTEN'
  AND Laddr.Port >= 42391
  AND Laddr.Port <= 43391

-- AF_PACKET socket
SELECT Pid, Name, Family
FROM netstat()
WHERE Family = 'AF_PACKET'
```

### LD_PRELOAD 检测

```sql
-- ld.so.preload 内容
SELECT FullPath, Size, Mtime,
  read_file(filename='/etc/ld.so.preload', length=1000) AS Content
FROM stat(filename='/etc/ld.so.preload')
WHERE Size > 0

-- 进程 LD_PRELOAD 环境变量
SELECT Pid, Name, Environ
FROM foreach(
  row={SELECT Pid, Name FROM pslist()},
  query={
    SELECT Pid, Name,
      read_file(filename=format(format='/proc/%d/environ', args=[Pid])) AS Environ
    FROM scope()
    WHERE Environ =~ 'LD_PRELOAD'
  }
)
```

---

## 高级持久化检测

### MOTD 后门 (T1037.003)

```sql
-- MOTD 文件
SELECT FullPath, Mtime, Size, Mode
FROM glob(globs='/etc/update-motd.d/*')

-- 最近修改的 MOTD
SELECT FullPath, Mtime
FROM glob(globs='/etc/update-motd.d/*')
WHERE Mtime > now() - 604800

-- 可疑 MOTD 内容
SELECT FullPath, Mtime,
  read_file(filename=FullPath, length=2000) AS Content
FROM glob(globs='/etc/update-motd.d/*')
WHERE Content =~ 'curl|wget|nc\s|python|bash\s+-i|/dev/tcp'
```

### XDG Autostart (T1546.013)

```sql
-- 用户 autostart
SELECT FullPath, Mtime, Size
FROM glob(globs=['/home/*/.config/autostart/*.desktop', '/etc/xdg/autostart/*.desktop'])

-- 最近添加
SELECT FullPath, Mtime
FROM glob(globs='/home/*/.config/autostart/*.desktop')
WHERE Mtime > now() - 604800

-- 可疑 Exec 命令
SELECT FullPath, Mtime,
  parse_string_with_regex(
    string=read_file(filename=FullPath),
    regex='Exec=(?P<Cmd>.*)'
  ).Cmd AS ExecCmd
FROM glob(globs=['/home/*/.config/autostart/*.desktop', '/etc/xdg/autostart/*.desktop'])
WHERE ExecCmd =~ 'curl|wget|nc\s|python|/tmp/|base64'
```

### Udev Rules (T1546.016)

```sql
-- udev 规则
SELECT FullPath, Mtime, Size
FROM glob(globs='/etc/udev/rules.d/*.rules')

-- 可疑 RUN 命令
SELECT FullPath, Mtime,
  read_file(filename=FullPath, length=2000) AS Content
FROM glob(globs='/etc/udev/rules.d/*.rules')
WHERE Content =~ 'RUN\+?=.*curl|RUN\+?=.*wget|RUN\+?=.*/tmp/'
```

### At Jobs (T1053.002)

```sql
-- at 队列
SELECT FullPath, Mtime, Size
FROM glob(globs=['/var/spool/at/*', '/var/spool/cron/atjobs/*'])

-- at 任务内容
SELECT FullPath, Mtime,
  read_file(filename=FullPath, length=2000) AS Content
FROM glob(globs='/var/spool/at/[a-z]*')
WHERE Content =~ 'curl|wget|python|/tmp/'
```

### Git Hooks (T1547.015)

```sql
-- 可执行 git hooks
SELECT FullPath, Mtime, Mode
FROM glob(globs='/home/*/**/.git/hooks/*')
WHERE Mode =~ 'x'

-- 可疑 hook 内容
SELECT FullPath, Mtime,
  read_file(filename=FullPath, length=2000) AS Content
FROM glob(globs='/home/*/**/.git/hooks/*')
WHERE Mode =~ 'x' AND Content =~ 'curl|wget|nc\s|/dev/tcp'
```

### Package Manager Hooks (T1547.013)

```sql
-- APT hooks
SELECT FullPath, Mtime
FROM glob(globs='/etc/apt/apt.conf.d/*')

-- 可疑 APT 配置
SELECT FullPath,
  read_file(filename=FullPath, length=2000) AS Content
FROM glob(globs='/etc/apt/apt.conf.d/*')
WHERE Content =~ 'Pre-Invoke|Post-Invoke'

-- 最近修改的 dpkg 脚本
SELECT FullPath, Mtime
FROM glob(globs='/var/lib/dpkg/info/*.postinst')
WHERE Mtime > now() - 604800
```

---

## 进程能力检测

### 危险 Capabilities (T1548.004)

```sql
-- 检查二进制 capabilities
SELECT FullPath, Capabilities
FROM foreach(
  row={SELECT FullPath FROM glob(globs=['/usr/bin/*', '/usr/sbin/*'])},
  query={
    SELECT FullPath,
      execve(argv=['getcap', FullPath]).Stdout AS Capabilities
    FROM scope()
    WHERE Capabilities != ''
  }
)
WHERE Capabilities =~ 'cap_setuid|cap_sys_admin|cap_sys_ptrace|cap_net_raw|cap_dac_override'
```

---

## 协议隧道检测

### DNS 隧道 (T1572)

```sql
-- 大量 DNS 连接
SELECT Pid, Name, count() AS DnsConnCount
FROM netstat()
WHERE Raddr.Port = 53
GROUP BY Pid, Name
HAVING DnsConnCount > 50

-- DNS 客户端进程 (非标准)
SELECT Pid, Name, Exe, Raddr
FROM netstat()
WHERE Raddr.Port = 53 AND NOT Name =~ 'systemd-resolve|named|dnsmasq'
```

### ICMP 隧道

```sql
-- 使用 raw socket 的进程
SELECT Pid, Name, Exe
FROM netstat()
WHERE Family = 'AF_INET' AND Protocol = 'RAW'
```

---

## Living off the Land

### GTFOBins 检测

```sql
-- 可疑的合法工具使用
SELECT Pid, Name, CommandLine
FROM pslist()
WHERE
  (Name = 'curl' AND CommandLine =~ '\|.*sh|\|.*bash') OR
  (Name = 'wget' AND CommandLine =~ '\|.*sh|\|.*bash|-O\s*-') OR
  (Name = 'python' AND CommandLine =~ '-c.*import.*socket|http.server') OR
  (Name = 'perl' AND CommandLine =~ '-e.*socket') OR
  (Name = 'nc' AND CommandLine =~ '-e|-c') OR
  (Name = 'ncat' AND CommandLine =~ '-e|-c|--exec') OR
  (Name = 'socat' AND CommandLine =~ 'EXEC|exec') OR
  (Name = 'openssl' AND CommandLine =~ 's_client.*cmd') OR
  (Name = 'awk' AND CommandLine =~ '/inet/') OR
  (Name = 'tar' AND CommandLine =~ '--checkpoint-action')

-- chattr 滥用 (Mirai 特征)
SELECT Pid, Name, CommandLine
FROM pslist()
WHERE Name = 'chattr' AND CommandLine =~ '\+i'
```

### 编码/混淆命令

```sql
-- Base64 编码命令
SELECT Pid, Name, CommandLine
FROM pslist()
WHERE CommandLine =~ 'base64\s+-d|base64\s+--decode|echo.*\|.*base64|openssl.*enc'

-- 十六进制编码
SELECT Pid, Name, CommandLine
FROM pslist()
WHERE CommandLine =~ 'xxd\s+-r|printf.*\\\\x'
```

---

## 资源链接

| 资源 | URL |
|------|-----|
| Velociraptor Artifact Exchange | https://docs.velociraptor.app/exchange/ |
| DetectRaptor | https://github.com/mgreen27/DetectRaptor |
| Elastic Detection Rules | https://github.com/elastic/detection-rules/tree/main/rules/linux |
| EQL to VQL | https://github.com/Velocidex/eql2vql |
| Sigma Rules | https://github.com/SigmaHQ/sigma |
| PANIX (持久化测试) | https://github.com/Aegrah/PANIX |

## 使用方法

```bash
# 设置 Velociraptor
VR=~/tools/velociraptor/velociraptor

# 执行 VQL 查询
$VR query "SELECT * FROM pslist() WHERE Exe =~ 'memfd:'"

# 导出结果为 JSON
$VR query "SELECT * FROM pslist()" --format json > processes.json

# 导出结果为 CSV
$VR query "SELECT Pid, Name, Exe FROM pslist()" --format csv > processes.csv
```
