# Windows 持久化位置清单

## 注册表启动项

### Run/RunOnce 键

| 位置 | 权限 | 说明 |
|------|------|------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | 管理员 | 所有用户启动 |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | 管理员 | 运行一次后删除 |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | 用户 | 当前用户启动 |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | 用户 | 运行一次 |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` | 管理员 | 32位程序 |

**检查命令**:
```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

### Winlogon

| 键值 | 正常值 | 说明 |
|------|--------|------|
| `Shell` | explorer.exe | Shell 程序 |
| `Userinit` | userinit.exe, | 登录初始化 |
| `Notify` | - | DLL 通知 |

**位置**: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

### 服务

| 位置 | 说明 |
|------|------|
| `HKLM\SYSTEM\CurrentControlSet\Services` | 服务注册 |

**检查命令**:
```powershell
Get-WmiObject win32_service | Where-Object {$_.PathName -notlike "*Windows*"} | Select-Object Name, PathName, StartMode
```

### AppInit_DLLs

| 位置 | 说明 |
|------|------|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` | DLL 注入 |
| `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` | 32位 |

### Image File Execution Options (IFEO)

| 位置 | 说明 |
|------|------|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>\Debugger` | 调试器劫持 |

### Shell Extensions

| 位置 | 说明 |
|------|------|
| `HKLM\SOFTWARE\Classes\*\ShellEx\ContextMenuHandlers` | 右键菜单 |
| `HKCU\SOFTWARE\Classes\*\ShellEx\ContextMenuHandlers` | 用户右键菜单 |

## 计划任务

### 任务位置

| 路径 | 说明 |
|------|------|
| `C:\Windows\System32\Tasks` | 系统任务 |
| `C:\Windows\Tasks` | 旧版任务 |

**检查命令**:
```powershell
schtasks /query /fo LIST /v
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}
```

### 可疑特征

- 随机命名的任务
- 执行 PowerShell 带编码参数
- 高频触发（每分钟）
- 位于 `\Microsoft\Windows\` 下的非标准任务

## 启动文件夹

| 路径 | 作用范围 |
|------|----------|
| `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` | 所有用户 |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | 当前用户 |

**检查命令**:
```powershell
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
```

## WMI 事件订阅

### 组件

| 类 | 说明 |
|----|------|
| `__EventFilter` | 事件过滤器 |
| `__EventConsumer` | 事件消费者 |
| `__FilterToConsumerBinding` | 绑定关系 |

**检查命令**:
```powershell
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```

## COM 劫持

### CLSID 位置

| 位置 | 说明 |
|------|------|
| `HKCU\SOFTWARE\Classes\CLSID` | 用户级 COM 对象 |
| `HKLM\SOFTWARE\Classes\CLSID` | 系统级 COM 对象 |

### 常被劫持的 CLSID

| CLSID | 程序 |
|-------|------|
| `{BCDE0395-E52F-467C-8E3D-C4579291692E}` | MMDeviceEnumerator |
| `{42aedc87-2188-41fd-b9a3-0c966feabec1}` | MruPidlList |

## DLL 劫持

### 搜索顺序

1. 应用程序目录
2. System32
3. System
4. Windows
5. 当前目录
6. PATH 环境变量

### 常见目标

- 程序安装目录
- 缺失的 DLL
- 已知可劫持 DLL

## BITS Jobs

**检查命令**:
```cmd
bitsadmin /list /allusers /verbose
```

**PowerShell**:
```powershell
Get-BitsTransfer -AllUsers | Select-Object JobId, DisplayName, TransferType
```

## Office 启动项

| 位置 | 说明 |
|------|------|
| `%APPDATA%\Microsoft\Word\STARTUP` | Word 启动 |
| `%APPDATA%\Microsoft\Excel\XLSTART` | Excel 启动 |
| `%APPDATA%\Microsoft\Outlook` | Outlook 加载项 |

## 打印处理器

| 位置 | 说明 |
|------|------|
| `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors` | 打印监视器 |
| `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors` | 打印处理器 |

## 安全支持提供程序 (SSP)

| 位置 | 说明 |
|------|------|
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` | SSP DLL |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages` | 配置 |

## Netsh Helper DLL

| 位置 | 说明 |
|------|------|
| `HKLM\SOFTWARE\Microsoft\Netsh` | Netsh 辅助 DLL |

## 时间提供程序

| 位置 | 说明 |
|------|------|
| `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders` | 时间服务 DLL |

## 检查脚本

```powershell
# 综合检查脚本
$results = @()

# Run 键
$results += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
$results += Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue

# 服务
$services = Get-WmiObject win32_service | Where-Object {
    $_.PathName -and
    $_.PathName -notlike "*Windows*" -and
    $_.PathName -notlike "*Microsoft*"
}

# 计划任务
$tasks = Get-ScheduledTask | Where-Object {
    $_.State -eq "Ready" -and
    $_.TaskPath -notlike "\Microsoft\*"
}

# 启动文件夹
$startup = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue

# 输出结果
Write-Host "=== Run 键 ===" -ForegroundColor Yellow
$results | Format-Table

Write-Host "=== 非系统服务 ===" -ForegroundColor Yellow
$services | Select-Object Name, PathName | Format-Table

Write-Host "=== 自定义计划任务 ===" -ForegroundColor Yellow
$tasks | Select-Object TaskName, TaskPath | Format-Table

Write-Host "=== 启动文件夹 ===" -ForegroundColor Yellow
$startup | Format-Table
```

## ATT&CK 映射

| 持久化方式 | ATT&CK ID |
|------------|-----------|
| Registry Run Keys | T1547.001 |
| Scheduled Task | T1053.005 |
| Windows Service | T1543.003 |
| WMI Subscription | T1546.003 |
| Startup Folder | T1547.001 |
| BITS Jobs | T1197 |
| DLL Search Order Hijacking | T1574.001 |
| COM Hijacking | T1546.015 |
