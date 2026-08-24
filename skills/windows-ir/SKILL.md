---
name: windows-ir
description: Windows 系统入侵应急响应与取证分析。当用户要求"Windows应急响应"、"入侵排查"、"后门检测"、"Webshell检测"、"网页木马"、"Web后门"、"Windows取证"、"事件日志分析"、"持久化检测"、"异常进程排查"、"计划任务检查"、"服务检查"、"注册表分析"时使用此技能。
metadata:
  version: 1.3.0
  builtin: true
---

# Windows 应急响应技能

## 依赖要求

**分析环境**: Windows / 跨平台（分析导出的日志）

**内置工具**: PowerShell 5.0+, wevtutil, schtasks, netstat, tasklist

**可选工具**: Autoruns, Process Explorer, TCPView (Sysinternals), hayabusa

**权限**: 推荐管理员权限。普通用户无法读取 Security 日志和部分系统目录。

## 快速使用

> **重要**：以下所有检测项均需**按顺序执行**，不可跳过

### 基础检测

```powershell
# 1. 网络连接
netstat -ano | findstr ESTABLISHED

# 2. 可疑进程
tasklist /v | findstr -i "cmd powershell wscript cscript mshta"

# 3. 计划任务
schtasks /query /fo LIST /v

# 4. 启动项
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### Webshell 检测

```powershell
# 5. Webshell 检测（必须执行这两个脚本）
python "$HOME\.cybersec\skills\windows-ir\scripts\find_web_dirs.py"
python "$HOME\.cybersec\skills\windows-ir\scripts\webshell_check.py" --deep
```

### 深度检测

```powershell
# 6. 挖矿木马检测
Get-Process | Where-Object {$_.Name -match 'xmrig|xmr-stak|minerd|kinsing|kdevtmpfsi'} | Select-Object Name, Id, Path
Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -match 'stratum\+|pool\.|cryptonight|nicehash'} | Select-Object Name, ProcessId, CommandLine

# 7. 反弹Shell检测
Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -match 'powershell.*(-enc\s|-e\s|-EncodedCommand)'} | Select-Object Name, ProcessId, CommandLine
Get-NetTCPConnection -State Established | Where-Object {$_.RemotePort -in @(4444,5555,6666,7777,1337,9001)} | Select-Object RemoteAddress, RemotePort, @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}}

# 8. 高级持久化检测
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v Debugger 2>$null | Select-String "Debugger"

# 9. C2端口/矿池连接
Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in @(4444,5555,6666,7777,1337,9001,31337)} | Select-Object LocalAddress, LocalPort, @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}}
Get-NetTCPConnection -State Established | Where-Object {$_.RemotePort -in @(3333,4444,5555,7777,14433,45700)} | Select-Object RemoteAddress, RemotePort, @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}}
```

## 应急响应工作流

### Phase 1: 初步研判

#### 1.1 确认入侵迹象

| 迹象 | 检查方法 | 严重程度 |
|------|----------|----------|
| 异常网络连接 | netstat -ano | 高 |
| 可疑进程 | tasklist /v | 高 |
| 新增用户 | net user | 高 |
| 异常服务 | sc query | 中 |
| 计划任务异常 | schtasks /query | 中 |

#### 1.2 时间线锚定

```powershell
# 查看最近修改的文件
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue |
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
  Sort-Object LastWriteTime -Descending |
  Select-Object FullName, LastWriteTime -First 50
```

### Phase 2: 进程分析

> 详细说明参见 [references/lolbins.md](references/lolbins.md)、[references/powershell-hunting.md](references/powershell-hunting.md)

#### 可疑进程特征

| 特征 | 说明 | 风险 |
|------|------|------|
| 无签名 | 未经微软签名的可执行文件 | 高 |
| 异常路径 | 非 System32/Program Files 目录 | 高 |
| 伪装名称 | svch0st.exe、lsass.exe（多实例） | 高 |
| 编码命令行 | -enc/-e/-encodedcommand 参数 | 高 |
| 异常资源占用 | CPU/内存持续高占用 | 中 |

#### 正常父子进程关系

| 进程 | 正常父进程 | 异常情况 |
|------|-----------|----------|
| svchost.exe | services.exe | 其他父进程启动 |
| lsass.exe | wininit.exe | 多个实例运行 |
| csrss.exe | smss.exe | 用户态进程启动 |
| cmd/powershell | explorer.exe 或服务 | 来自 Office/IIS/浏览器 |
| smss.exe | System | 多个实例运行 |

#### 2.1 进程检查命令

```powershell
# 详细进程列表
Get-Process | Select-Object Name, Id, Path, Company, StartTime | Format-Table -AutoSize

# 检查进程签名
Get-Process -ErrorAction SilentlyContinue |
  Where-Object { $_.Path } |
  ForEach-Object {
    try {
      $sig = Get-AuthenticodeSignature $_.Path -ErrorAction Stop
      if ($sig.Status -ne "Valid") {
        [PSCustomObject]@{ Name = $_.Name; Path = $_.Path; Status = $sig.Status }
      }
    } catch { }
  } | Format-Table -AutoSize

# 查看进程命令行
Get-WmiObject Win32_Process | Select-Object Name, ProcessId, CommandLine

# 查看父子进程关系
Get-WmiObject Win32_Process | Select-Object Name, ProcessId, ParentProcessId, CommandLine
```

#### 2.2 挖矿木马检测

```powershell
# 挖矿进程名检测
Get-Process | Where-Object {
  $_.Name -match 'xmrig|xmr-stak|minerd|kinsing|kdevtmpfsi|carbon|ddgs|systemctI|kthreaddi'
} | Select-Object Name, Id, Path, CPU

# 挖矿命令行特征
Get-WmiObject Win32_Process |
  Where-Object {$_.CommandLine -match 'stratum\+|pool\.|cryptonight|--donate-level|nicehash|monero|--coin'} |
  Select-Object Name, ProcessId, CommandLine

# CPU 异常占用进程
Get-Process | Sort-Object CPU -Descending | Select-Object Name, Id, CPU, Path -First 10
```

#### 2.3 反弹Shell检测

```powershell
# PowerShell 编码命令检测（高危）
Get-WmiObject Win32_Process |
  Where-Object {$_.CommandLine -match 'powershell.*(-enc\s|-e\s|-EncodedCommand)'} |
  Select-Object Name, ProcessId, CommandLine

# 可疑父子进程关系（Office/IIS 启动 cmd/powershell）
Get-WmiObject Win32_Process | ForEach-Object {
  $parent = Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue
  if ($parent.Name -match 'WINWORD|EXCEL|OUTLOOK|POWERPNT|w3wp|httpd|tomcat' -and
      $_.Name -match 'cmd|powershell|wscript|cscript|mshta') {
    [PSCustomObject]@{
      ParentName = $parent.Name; ChildName = $_.Name
      ChildPID = $_.ProcessId; CommandLine = $_.CommandLine
    }
  }
}

# 可疑 C2 端口外连
Get-NetTCPConnection -State Established |
  Where-Object {$_.RemotePort -in @(4444,5555,6666,7777,1337,9001)} |
  Select-Object LocalPort, RemoteAddress, RemotePort, @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}}
```

### Phase 3: 持久化检测

> 详细说明参见 [references/persistence-locations.md](references/persistence-locations.md)

#### 3.1 注册表启动项

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s | findstr ImagePath
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

#### 3.2 计划任务

```powershell
schtasks /query /fo LIST /v

# PowerShell 方式（更详细）
Get-ScheduledTask | Where-Object {$_.State -in @('Ready','Running')} |
  ForEach-Object {
    $info = $_ | Get-ScheduledTaskInfo
    [PSCustomObject]@{
      TaskName = $_.TaskName; TaskPath = $_.TaskPath; State = $_.State
      LastRunTime = $info.LastRunTime
      Actions = ($_.Actions | ForEach-Object {$_.Execute + " " + $_.Arguments}) -join "; "
    }
  }
```

#### 3.3 服务

```powershell
# 列出非微软服务
Get-WmiObject win32_service |
  Where-Object {$_.PathName -notlike "*Windows*" -and $_.PathName -notlike "*Microsoft*"} |
  Select-Object Name, DisplayName, State, PathName, StartMode
```

#### 3.4 WMI 持久化

```powershell
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```

#### 3.5 高级持久化

```powershell
# AppInit_DLLs
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs

# IFEO 调试器劫持
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v Debugger 2>$null | Select-String "Debugger"

# 辅助功能后门检查
$files = @("sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe")
foreach ($f in $files) {
  $path = "C:\Windows\System32\$f"
  $sig = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
  if ($sig.Status -ne "Valid") { Write-Host "[!] 签名异常: $path" -ForegroundColor Red }
}

# PowerShell Profile
$profiles = @("$PSHOME\Profile.ps1", "$HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1")
foreach ($p in $profiles) {
  if (Test-Path $p) {
    Write-Host "[!] Profile 存在: $p" -ForegroundColor Yellow
    if (Select-String -Path $p -Pattern "IEX|Invoke-Expression|DownloadString" -Quiet) {
      Write-Host "[!!] 包含可疑内容" -ForegroundColor Red
    }
  }
}

# 屏幕保护程序 (T1546.002)
reg query "HKCU\Control Panel\Desktop" /v SCRNSAVE.EXE

# 历史记录清除检测 (T1070.003)
$histPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $histPath) {
  if ((Get-Item $histPath).Length -eq 0) { Write-Host "[!] PowerShell 历史为空（可能被清除）" -ForegroundColor Yellow }
} else { Write-Host "[!] PowerShell 历史文件不存在" -ForegroundColor Yellow }
```

### Phase 4: 网络分析

#### 可疑网络特征

| 特征 | 风险 | 说明 |
|------|------|------|
| 境外 IP | 高 | 非业务相关国家/地区 |
| C2 常用端口 | 高 | 4444, 5555, 6666, 1337, 9001 |
| 矿池端口 | 高 | 3333, 14433, 45700 |
| 高位随机端口 | 中 | >10000 的非标准端口 |
| DNS 隧道 | 高 | 大量异常 DNS 请求 |

#### 4.1 当前连接

```powershell
netstat -ano

# 关联进程名
Get-NetTCPConnection |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
    @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}, OwningProcess

# 监听端口
netstat -ano | findstr LISTENING
```

#### 4.2 高危端口检测

```powershell
# C2/反弹Shell 常用端口监听
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalPort -in @(4444,5555,6666,7777,1337,9001,31337)} |
  Select-Object LocalAddress, LocalPort, @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}}

# 矿池连接检测
Get-NetTCPConnection -State Established |
  Where-Object {$_.RemotePort -in @(3333,4444,5555,7777,14433,45700)} |
  Select-Object RemoteAddress, RemotePort, @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}}
```

#### 4.3 DNS 缓存

```powershell
ipconfig /displaydns
Get-DnsClientCache | Export-Csv dns_cache.csv
```

### Phase 5: Webshell 检测

> 详细说明参见 [references/webshell-detection.md](references/webshell-detection.md)

```powershell
# 第一步：自动发现 Web 目录
python "$HOME\.cybersec\skills\windows-ir\scripts\find_web_dirs.py"

# 第二步：深度扫描
python "$HOME\.cybersec\skills\windows-ir\scripts\webshell_check.py" --deep

# 第三步：生成报告（可选）
python "$HOME\.cybersec\skills\windows-ir\scripts\webshell_check.py" --deep -o "webshell_report.json"
```

### Phase 6: 用户与凭证

**可疑用户特征**: 用户名以 `$` 结尾（隐藏用户）、Guest 被启用、非工作时间登录、LogonType=10（RDP）

#### 6.1 用户检查

```powershell
net user
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet
net localgroup administrators

# 最近登录
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 50 |
  Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[8].Value}}
```

#### 6.2 凭证痕迹

```powershell
# 检查 Mimikatz 痕迹
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" |
  Where-Object {$_.Message -like "*mimikatz*" -or $_.Message -like "*sekurlsa*"}

# LSASS 访问
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4663]]" |
  Where-Object {$_.Message -like "*lsass*"}
```

### Phase 7: 事件日志分析

> 详细说明参见 [references/event-ids.md](references/event-ids.md)

#### 7.1 关键事件 ID

| 事件 ID | 日志 | 说明 |
|---------|------|------|
| 4624/4625 | Security | 登录成功/失败 |
| 4672 | Security | 特权登录 |
| 4688 | Security | 进程创建 |
| 4698 | Security | 计划任务创建 |
| 4720 | Security | 用户创建 |
| 7045 | System | 服务安装 |

#### 7.2 日志查询

```powershell
# 登录事件
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624 or EventID=4625]]" -MaxEvents 100

# 进程创建
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" -MaxEvents 100

# 服务安装
Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045]]" -MaxEvents 50

# PowerShell 日志
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100

# 日志清除检测
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=1102]]"
Get-WinEvent -LogName System -FilterXPath "*[System[EventID=104]]"
```

#### 7.3 RDP 爆破分析

```powershell
# 登录失败统计（按 IP 分组）
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4625]]" -MaxEvents 1000 |
  ForEach-Object {
    [PSCustomObject]@{
      Time = $_.TimeCreated; IP = $_.Properties[19].Value
      User = $_.Properties[5].Value; LogonType = $_.Properties[10].Value
    }
  } | Where-Object {$_.LogonType -eq 10} |
  Group-Object IP | Sort-Object Count -Descending | Select-Object Count, Name -First 20
```

### Phase 8: 时间线重建

1. 确定入侵时间窗口
2. 收集各数据源时间点（文件系统、事件日志、注册表、预读取）
3. 按时间排序事件
4. 建立攻击链

### Phase 9: ATT&CK 技术映射表

Windows IR 覆盖 ATT&CK 矩阵全攻击链检测，以下映射指导应急响应的技术覆盖范围：

#### Initial Access 战术 (TA0001)

| ATT&CK ID | 技术名称 | 子技术 | Windows IR 检测方法 |
|-----------|---------|--------|---------------------|
| T1566 | 钓鱼 | - | Event ID 4624 登录事件关联 |
| T1566.001 | 鱼叉式钓鱼附件 | 恶意文档 | Office 进程启动 cmd/powershell 检测 |
| T1566.002 | 鱼叉式钓鱼链接 | 恶意链接 | 浏览器历史记录 + 下载文件分析 |
| T1190 | 利用公开应用 | - | IIS 日志分析、Web 漏洞利用检测 |
| T1133 | 外部远程服务 | - | RDP/VPN 异常登录检测 |

#### Execution 战术 (TA0002)

| ATT&CK ID | 技术名称 | 子技术 | Windows IR 检测方法 |
|-----------|---------|--------|---------------------|
| T1059 | 命令和脚本解释器 | - | Event ID 4688 进程创建监控 |
| T1059.001 | PowerShell | - | ScriptBlock 日志 (4104) + 历史 |
| T1059.003 | Windows Command Shell | cmd.exe | 命令行参数审计 |
| T1059.005 | Visual Basic | VBA | Office 宏执行检测 |
| T1059.006 | Python | - | 非标准 Python 执行检测 |
| T1106 | 原生 API 调用 | - | API 调用监控、rundll32 异常 |
| T1129 | 共享模块加载 | DLL | AppInit_DLLs + DLL 劫持检测 |
| T1053 | 计划任务/作业 | - | Event ID 4698 计划任务创建 |
| T1053.005 | 计划任务 | schtasks | schtasks /query 审计 |
| T1543.003 | Windows 服务 | services.exe | Event ID 7045 服务安装 |

#### Persistence 战术 (TA0003)

| ATT&CK ID | 技术名称 | 子技术 | Windows IR 检测方法 |
|-----------|---------|--------|---------------------|
| T1547 | Boot/Logon 自启动 | - | 注册表 Run/RunOnce 审计 |
| T1547.001 | 注册表运行键 | Run Key | reg query HKLM/HKCU Run |
| T1547.009 | 快捷方式修改 | .lnk | 启动文件夹快捷方式检查 |
| T1136 | 创建账户 | - | Event ID 4720 用户创建 |
| T1136.001 | 本地账户 | net user | 异常本地用户创建检测 |
| T1543 | 创建/修改系统进程 | - | 服务路径和签名验证 |
| T1543.003 | Windows 服务 | - | 非微软服务路径检查 |
| T1574 | 劫持执行流程 | - | IFEO 调试器劫持检测 |
| T1574.002 | DLL 旁加载 | - | 进程模块加载路径验证 |
| T1546 | 事件触发执行 | - | WMI 事件订阅检查 |
| T1546.003 | WMI 事件订阅 | - | root\\Subscription 命名空间审计 |
| T1505.003 | Web Shell | - | Web 目录文件扫描 |

#### Credential Access 战术 (TA0006)

| ATT&CK ID | 技术名称 | 子技术 | Windows IR 检测方法 |
|-----------|---------|--------|---------------------|
| T1003 | 操作系统凭证转储 | - | LSASS 进程访问检测 |
| T1003.001 | LSASS 内存 | mimikatz | Event ID 4663 + 4656 |
| T1003.002 | 安全账户管理器 | SAM | reg save HKLM\\SAM 检测 |
| T1003.003 | NTDS.dit | - | ntdsutil / vssadmin 使用检测 |
| T1110 | 暴力破解 | - | Event ID 4625 登录失败分析 |
| T1110.001 | 密码猜测 | - | 短时间高频登录失败 |
| T1555 | 密码存储中的凭证 | - | 凭证管理器事件审计 |

#### Defense Evasion 战术 (TA0005)

| ATT&CK ID | 技术名称 | 子技术 | Windows IR 检测方法 |
|-----------|---------|--------|---------------------|
| T1027 | 混淆文件或信息 | - | 编码/加密命令行检测 |
| T1027.002 | 软件加壳 | - | PE 文件熵值分析 |
| T1036 | 伪装 | - | 进程名/签名伪装检测 |
| T1036.005 | 匹配合法名称 | - | svch0st / lsass 多实例 |
| T1036.008 | 伪装文件类型 | - | magic bytes vs 扩展名校验 |
| T1070 | 痕迹清除 | - | Event ID 1102/104 日志清除 |
| T1070.003 | 清除历史 | - | PowerShell 历史为空/删除 |
| T1070.004 | 文件删除 | - | 文件系统时间线分析 |
| T1140 | 反混淆/解码 | - | base64/hex 解码命令检测 |
| T1218 | 系统二进制代理执行 | - | LOLBins 使用检测 |
| T1218.001 | 编译 HTML | hh.exe | HTML Help 非标准使用 |
| T1218.005 | Mshta | mshta.exe | Mshta 执行 URL/HTA |
| T1218.010 | Regsvr32 | regsvr32.exe | /s /u scrobj.dll 加载 |
| T1218.011 | Rundll32 | rundll32.exe | 可疑 DLL 加载检测 |

#### Discovery 战术 (TA0007)

| ATT&CK ID | 技术名称 | 子技术 | Windows IR 检测方法 |
|-----------|---------|--------|---------------------|
| T1087 | 账户发现 | - | net user / Get-LocalUser 审计 |
| T1087.002 | 域账户 | - | net user /domain 异常查询 |
| T1018 | 远程系统发现 | - | ping / arp -a 网络扫描 |
| T1046 | 网络服务发现 | - | 端口扫描 / nmap 检测 |
| T1082 | 系统信息发现 | - | systeminfo / whoami 审计 |
| T1083 | 文件和目录发现 | - | dir / Get-ChildItem 异常 |
| T1135 | 网络共享发现 | - | net view / net share 检测 |

#### Lateral Movement 战术 (TA0008)

| ATT&CK ID | 技术名称 | 子技术 | Windows IR 检测方法 |
|-----------|---------|--------|---------------------|
| T1021 | 远程服务 | - | RDP/WinRM/SMB 登录审计 |
| T1021.001 | 远程桌面 | RDP | Event ID 4624 LogonType=10 |
| T1021.002 | SMB/Admin | PsExec | ADMIN$ 共享访问检测 |
| T1021.006 | Windows 远程管理 | WinRM | Event ID 4624 LogonType=3 |
| T1072 | 软件部署工具 | - | SCCM/Altiris 异常使用 |
| T1570 | 横向工具传输 | - | 可执行文件网络传输 |

#### Command and Control 战术 (TA0011)

| ATT&CK ID | 技术名称 | 子技术 | Windows IR 检测方法 |
|-----------|---------|--------|---------------------|
| T1071 | 应用层协议 | - | netstat 异常出站连接 |
| T1071.001 | Web协议 | HTTP/HTTPS | 非标准端口 HTTP 流量 |
| T1071.004 | DNS | DNS隧道 | DNS 缓存 + 高频 TXT 查询 |
| T1095 | 非应用层协议 | - | 原始 TCP/UDP/ICMP |
| T1105 | 入口工具传输 | - | certutil/urlclip/bitsadmin 下载 |
| T1132 | 数据编码 | - | Base64 编码 C2 通信 |
| T1573 | 加密通道 | - | 非标准 TLS/自定义加密协议 |

#### Exfiltration 战术 (TA0010)

| ATT&CK ID | 技术名称 | 子技术 | Windows IR 检测方法 |
|-----------|---------|--------|---------------------|
| T1041 | C2 通道外传 | - | 网络流量 + 文件大小异常 |
| T1048 | 替代协议外传 | - | DNS/ICMP/HTTPS 异常上传 |
| T1567 | 通过Web服务外传 | - | 云存储 API 调用检测 |

#### Impact 战术 (TA0040)

| ATT&CK ID | 技术名称 | 子技术 | Windows IR 检测方法 |
|-----------|---------|--------|---------------------|
| T1486 | 数据加密勒索 | - | 文件批量修改事件 + 加密扩展名 |
| T1490 | 阻止恢复 | - | vssadmin delete shadows |
| T1496 | 资源劫持 | - | 挖矿进程 CPU 占用检测 |
| T1529 | 系统关机/重启 | - | shutdown / tsshutdn 检测 |

#### ATT&CK 缓解措施参考

| Mitigation ID | 名称 | IR 应用 |
|---------------|------|---------|
| M1042 | 禁用或限制功能 | 限制 PowerShell/Office 宏 |
| M1041 | 加密敏感信息 | BitLocker/EFI 安全启动 |
| M1028 | 账户锁定 | 组策略账户锁定策略 |
| M1017 | 用户培训 | 安全意识培训防钓鱼 |
| M1030 | 网络分段 | 隔离受感染网段 |
| M1027 | 密码策略 | 强制强密码 + 定期更换 |
| M1047 | 审计 | 启用 PowerShell 日志 + 命令行日志 |
| M1054 | 服务扫描 | 定期漏洞扫描和补丁管理 |

### Phase 10: 报告生成

按 [references/report-format.md](references/report-format.md) 输出报告

## ATT&CK 附加框架映射

### OWASP Top 10 关联

Windows IR 虽然以主机检测为主，但很多攻击初始向量来自 Web 应用漏洞：

| OWASP 类别 | Windows IR 关联场景 |
|-----------|---------------------|
| A01:2021 - Broken Access Control | 横向移动后权限提升检测 |
| A03:2021 - Injection | Web Shell 检测和 SQL 注入痕迹 |
| A05:2021 - Security Misconfiguration | 持久化机制利用的错误配置 |
| A06:2021 - Vulnerable Components | CVE 漏洞利用后的系统文件篡改 |
| A08:2021 - Software Integrity Failures | DLL 旁加载和供应链攻击检测 |
| A09:2021 - Logging Failures | 日志清除检测 (T1070) |

### Sigma 检测规则

#### 规则 1: 可疑 PowerShell 编码命令执行

```yaml
title: 可疑PowerShell编码命令执行 - 可能的入侵后执行
id: c1a2b3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: 检测PowerShell执行Base64编码命令，常见于入侵后阶段的无文件攻击和反弹Shell
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://attack.mitre.org/techniques/T1027/
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059.001
    - attack.t1027
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: powershell.exe
        CommandLine|contains:
            - '-enc '
            - '-EncodedCommand '
            - '-e '
            - 'FromBase64String'
            - 'IEX'
            - 'Invoke-Expression'
            - 'DownloadString'
            - 'DownloadFile'
    condition: selection
falsepositives:
    - 合法管理员脚本（需白名单）
    - 软件安装脚本
level: high
```

#### 规则 2: Windows 服务安装 - 可能的持久化

```yaml
title: 可疑Windows服务安装 - 可能的持久化机制
id: d2b3c4e5-f6a7-8901-bcde-f23456789012
status: stable
description: 检测非标准Windows服务安装，可能是攻击者建立的持久化后门
references:
    - https://attack.mitre.org/techniques/T1543/003/
tags:
    - attack.persistence
    - attack.t1543.003
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    filter_legitimate:
        ServiceName|startswith:
            - 'Microsoft'
            - 'Windows'
            - 'VMware'
            - 'Docker'
            - 'NVIDIA'
    condition: selection and not filter_legitimate
falsepositives:
    - 软件安装（需确认）
    - 系统更新服务
level: medium
```

#### 规则 3: LSASS 凭证转储检测

```yaml
title: LSASS进程访问 - 可能的凭证转储行为
id: e3c4f5a6-b7c8-9012-cdef-345678901234
status: stable
description: 检测非标准进程访问LSASS内存，常见于Mimikatz等凭证窃取工具
references:
    - https://attack.mitre.org/techniques/T1003/001/
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4663
        ObjectType: Process
        ObjectName|endswith: lsass.exe
        AccessMask|contains:
            - '0x1410'
            - '0x1010'
            - '0x143a'
    filter_system:
        SubjectUserName|endswith:
            - '$'
            - 'SYSTEM'
            - 'LOCAL SERVICE'
            - 'NETWORK SERVICE'
    condition: selection and not filter_system
falsepositives:
    - 安全软件扫描（需白名单）
    - Windows Defender
level: critical
```

### YARA 规则

#### 规则 1: 常见Web Shell检测

```yara
rule WebShell_Generic_Windows {
    meta:
        description = "检测常见Windows Web Shell特征"
        author = "sec-skills-evolution"
        date = "2026-06-23"
        reference = "T1505.003"
    strings:
        $eval_asp = "eval(Request" ascii
        $exec_asp = "execute(request" ascii nocase
        $system_asp = "Server.CreateObject(\"WSCRIPT.SHELL\")" ascii nocase
        $stream_asp = "Server.CreateObject(\"ADODB.Stream\")" ascii nocase
        $php_system = "system($_" ascii
        $php_exec = "exec($_" ascii
        $php_eval = "eval($_" ascii
        $jsp_runtime = "Runtime.getRuntime().exec" ascii
        $aspx_csharp = "cmd.exe /c" ascii
        $certutil = "certutil -decode" ascii nocase
    condition:
        any of them
}
```

#### 规则 2: Windows后门/木马特征

```yara
rule Windows_Backdoor_Features {
    meta:
        description = "检测Windows后门和木马的常见特征"
        author = "sec-skills-evolution"
        date = "2026-06-23"
        reference = "T1547,T1053,T1003"
    strings:
        $rev_shell_cmd = "cmd.exe /c powershell -nop -w hidden" nocase
        $rev_shell_ps = "$client = New-Object System.Net.Sockets.TCPClient" nocase
        $mimikatz = "sekurlsa::logonpasswords" nocase
        $mimikatz2 = "lsadump::sam" nocase
        $mimikatz3 = "kerberos::ptt" nocase
        $c2_beacon = "beacon.dll" nocase
        $cobalt = "Start-Sleep -Milliseconds" nocase
        $rundll32 = "rundll32.exe javascript:" nocase
        $mshta = "mshta.exe http" nocase
        $regsave = "reg save HKLM" nocase
        $vssadmin = "vssadmin delete shadows" nocase
    condition:
        any of them
}
```

### CVE 参考表

Windows IR 需要关注的高危 CVE，这些漏洞经常被用于初始访问和权限提升：

| CVE ID | 漏洞名称 | CVSS | ATT&CK 关联 | IR 检测重点 |
|--------|---------|------|-------------|------------|
| CVE-2024-3094 | XZ Utils 后门 | 10.0 | T1195.002 供应链 | SSH 后门检测、liblzma 异常 |
| CVE-2024-21413 | Outlook 远程代码执行 | 9.8 | T1566.002 钓鱼链接 | Outlook 进程异常子进程 |
| CVE-2023-36884 | Windows HTML RCE | 8.3 | T1566.002 钓鱼链接 | msedge/ie 子进程异常 |
| CVE-2023-23397 | Outlook 提权 | 9.8 | T1566.002 钓鱼 | Outlook 日历项异常 |
| CVE-2022-30190 | Follina MSDT RCE | 7.8 | T1566.002 钓鱼链接 | ms-msdt: 协议处理检测 |
| CVE-2021-34527 | PrintNightmare | 8.8 | T1068 利用漏洞 | spoolsv.exe 子进程检测 |
| CVE-2021-1675 | 打印后台漏洞 | 8.8 | T1068 利用漏洞 | Print Spooler 服务异常 |
| CVE-2020-1472 | Zerologon | 10.0 | T1068 利用漏洞 | Netlogon 加密降级检测 |
| CVE-2020-0796 | SMBGhost | 10.0 | T1210 利用远程服务 | SMBv3 压缩异常数据包 |
| CVE-2019-0708 | BlueKeep | 9.8 | T1210 利用远程服务 | RDP TermDD 异常崩溃 |
| CVE-2024-38077 | Windows LDAPS RCE | 9.8 | T1210 远程服务利用 | LDAP 服务异常子进程 |
| CVE-2024-26233 | Windows 权限提升 | 7.8 | T1068 漏洞利用 | phExecutor.exe 异常调用 |

### IOC 采集指引

#### 高优先级 IOC

| IOC 类型 | 采集目标 | 格式 | 用途 |
|---------|---------|------|------|
| 恶意文件哈希 | 文件系统扫描 | MD5/SHA256 | 威胁情报匹配、变种检测 |
| 恶意IP地址 | netstat/防火墙日志 | IP:Port | C2 通信检测、IP 信誉 |
| 恶意域名 | DNS 缓存/网络日志 | domain.tld | C2 域名分析、阻断 |
| 可疑进程 | 任务管理器/Event 4688 | name:pid:path | 进程行为分析 |
| 注册表持久化 | 注册表扫描 | HKLM\\path\\value | 持久化清除、IOC 转发 |
| 计划任务 | schtasks 导出 | taskname:action | 持久化清除 |
| 异常服务 | sc query 导出 | svcname:binarypath | 服务后门清除 |

#### 中优先级 IOC

| IOC 类型 | 采集目标 | 格式 | 用途 |
|---------|---------|------|------|
| 用户账户 | net user 导出 | username:priv | 异常账户识别 |
| 网络连接 | netstat -ano 导出 | local:remote:pid | 通信链路分析 |
| 事件日志 | wevtutil 导出 | EventID:Time | 时间线重建 |
| PowerShell 历史 | ConsoleHost_history | command:timestamp | 攻击命令复现 |
| 预读取文件 | Prefetch 文件夹 | exe.pf | 程序执行历史 |
| 文件系统时间线 | USN Journal | file:action:time | 文件操作追踪 |

### 合规标准参考表

| 标准 | 相关条款 | IR 应用场景 |
|------|---------|------------|
| ISO 27001 A.16 | 事件管理 | 安全事件响应流程规范 |
| ISO 27001 A.12.4 | 事件日志 | 日志记录和监控要求 |
| NIST SP 800-61 | 计算机安全事件处理 | IR 流程方法论参考 |
| NIST SP 800-86 | 取证整合 | 数字取证标准流程 |
| NIST SP 800-53 IR-4 | 事件处理 | 事件响应控制要求 |
| NIST SP 800-53 IR-6 | 事件报告 | 事件上报机制 |
| 等保2.0 第八章 | 网络通信安全 | 安全事件监测和响应 |
| 等保2.0 第10章 | 安全管理中心 | 集中安全运营要求 |
| GDPR Art. 33 | 数据泄露通知 | 72小时内上报数据泄露 |
| PIPL 第五十七条 | 安全事件通知 | 个人信息泄露通知义务 |
| PCI DSS 12.10 | 事件响应计划 | 支付卡数据安全事件处理 |
| ISO/IEC 27035 | 安全事件管理 | 事件响应国际标准 |

### 跨技能工作流

#### 工作流 1: Windows 勒索软件 IR

```
windows-ir (主机检测和遏制)
    ↓
traffic-analysis (网络流量取证)
    ↓
domain-analysis / ip-analysis (C2基础设施分析)
    ↓
auth-log-analysis (横向移动检测)
    ↓
pdf-report (事件报告生成)
```

#### 工作流 2: Windows Web Shell 应急响应

```
windows-ir (Webshell检测 + 系统取证)
    ↓
office-malware-analyzer (恶意文档分析)
    ↓
ip-analysis / url-analysis (C2通信分析)
    ↓
ttp-extractor (攻击技术提取)
    ↓
pdf-report (综合报告)
```

#### 工作流 3: Windows 域渗透 IR

```
windows-ir (主机检测 + 凭证泄露 + 横向移动)
    ↓
auth-log-analysis (域控认证日志分析)
    ↓
traffic-analysis (域内异常流量)
    ↓
binary-reverse-engineering (恶意样本分析)
    ↓
ttp-extractor (APT TTP映射)
    ↓
pdf-report (域渗透事件报告)
```

## 工具命令速查

| 任务 | 命令 |
|------|------|
| 进程列表 | `tasklist /v` 或 `Get-Process` |
| 网络连接 | `netstat -ano` |
| 计划任务 | `schtasks /query /fo LIST /v` |
| 服务列表 | `sc query` 或 `Get-Service` |
| 注册表启动项 | `reg query HKLM\..\Run` |
| 用户列表 | `net user` |
| 事件日志 | `wevtutil qe Security /c:100` |

## 输出格式

### IOC 清单

```
# 恶意文件
MD5: abc123...
SHA256: def456...
Path: C:\Windows\Temp\malware.exe

# 恶意 IP/域名
1.2.3.4 (C2)
evil.com

# 持久化
注册表: HKLM\...\Run\malware
计划任务: \Microsoft\Windows\evil
服务: evilsvc
```

## 关联技能调用

| 发现的 IOC | 调用技能 | 说明 |
|-----------|----------|------|
| 可疑 IP | `ip-analysis` | IP 信誉和地理分析 |
| C2 域名 | `domain-analysis` | 域名 WHOIS/DNS 分析 |
| 恶意 URL | `url-analysis` | URL 安全分析 |
| 恶意样本 | `binary-reverse-engineering` | 逆向分析 |
| 恶意文档 | `office-malware-analyzer` | Office 宏分析 |
| 钓鱼邮件 | `phishing-analysis` | 钓鱼载荷分析 |
| 认证异常 | `auth-log-analysis` | 登录行为分析 |
| 流量异常 | `traffic-analysis` | 网络流量分析 |
| TTP 提取 | `ttp-extractor` | 检测规则生成 |
| 综合报告 | `pdf-report` | IR 报告生成 |

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 报告格式规范
- [references/webshell-detection.md](references/webshell-detection.md) - Webshell 检测详细说明
- [references/event-ids.md](references/event-ids.md) - 关键事件 ID 速查
- [references/persistence-locations.md](references/persistence-locations.md) - 持久化位置清单
- [references/lolbins.md](references/lolbins.md) - Living off the Land 二进制
- [references/powershell-hunting.md](references/powershell-hunting.md) - PowerShell 威胁狩猎
