---
name: windows-ir
description: Windows 系统入侵应急响应与取证分析。当用户要求"Windows应急响应"、"入侵排查"、"后门检测"、"Webshell检测"、"网页木马"、"Web后门"、"Windows取证"、"事件日志分析"、"持久化检测"、"异常进程排查"、"计划任务检查"、"服务检查"、"注册表分析"时使用此技能。
metadata:
  version: 1.2.0
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

### Phase 9: ATT&CK 映射

| 阶段 | 技术 | 检测点 |
|------|------|--------|
| 初始访问 | T1566 钓鱼 | 邮件附件 |
| 执行 | T1059 命令行 | 进程命令行 |
| 持久化 | T1053 计划任务 | schtasks |
| 持久化 | T1547 启动项 | 注册表 Run |
| 凭证访问 | T1003 LSASS | 进程访问 |
| 横向移动 | T1021 远程服务 | RDP/SMB |

### Phase 10: 报告生成

按 [references/report-format.md](references/report-format.md) 输出报告

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

| 发现的 IOC | 调用技能 |
|-----------|---------|
| 可疑 IP | `ip-analysis` |
| C2 域名 | `domain-analysis` |
| 恶意样本 | `binary-reverse-engineering` |

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 报告格式规范
- [references/webshell-detection.md](references/webshell-detection.md) - Webshell 检测详细说明
- [references/event-ids.md](references/event-ids.md) - 关键事件 ID 速查
- [references/persistence-locations.md](references/persistence-locations.md) - 持久化位置清单
- [references/lolbins.md](references/lolbins.md) - Living off the Land 二进制
- [references/powershell-hunting.md](references/powershell-hunting.md) - PowerShell 威胁狩猎
