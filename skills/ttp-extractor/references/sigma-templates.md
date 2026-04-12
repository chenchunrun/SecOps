# Sigma 检测规则模板

## 基础模板结构

```yaml
title: 规则标题
id: UUID
status: experimental/test/stable
description: 规则描述
references:
    - https://attack.mitre.org/techniques/TXXXX/
author: 作者
date: YYYY/MM/DD
modified: YYYY/MM/DD
tags:
    - attack.tactic_name
    - attack.tXXXX
logsource:
    category: 类别
    product: 产品
detection:
    selection:
        字段: 值
    condition: selection
falsepositives:
    - 误报场景
level: low/medium/high/critical
```

## 常用攻击技术的 Sigma 规则

### T1059.001 PowerShell 执行

```yaml
title: 可疑 PowerShell 编码命令
id: f3a90c68-8e7e-4e8b-9b0a-8e7e4e8b9b0a
status: stable
description: 检测 Base64 编码的 PowerShell 命令
references:
    - https://attack.mitre.org/techniques/T1059/001/
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_encoded:
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
            - '-e '
    selection_base64:
        CommandLine|base64offset|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'downloadstring'
    condition: selection_encoded or selection_base64
falsepositives:
    - 管理员脚本
    - 自动化工具
level: high
```

### T1003 凭据转储

```yaml
title: Mimikatz 凭据转储
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: 检测 Mimikatz 工具执行
references:
    - https://attack.mitre.org/techniques/T1003/
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection_cli:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'lsadump::'
            - 'kerberos::'
            - 'crypto::'
    selection_image:
        Image|endswith:
            - '\mimikatz.exe'
            - '\mimi.exe'
    condition: selection_cli or selection_image
falsepositives:
    - 授权渗透测试
level: critical
```

### T1566.001 钓鱼附件

```yaml
title: Office 宏启动可疑进程
id: b2c3d4e5-f6a7-8901-bcde-f23456789012
status: stable
description: 检测 Office 应用启动命令行或脚本解释器
references:
    - https://attack.mitre.org/techniques/T1566/001/
tags:
    - attack.initial_access
    - attack.t1566.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\POWERPNT.EXE'
            - '\OUTLOOK.EXE'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
    condition: selection_parent and selection_child
falsepositives:
    - 合法的 Office 插件
level: high
```

### T1055 进程注入

```yaml
title: 可疑进程注入 API 调用
id: c3d4e5f6-a7b8-9012-cdef-345678901234
status: experimental
description: 检测常见进程注入 API 调用序列
references:
    - https://attack.mitre.org/techniques/T1055/
tags:
    - attack.defense_evasion
    - attack.t1055
logsource:
    category: process_access
    product: windows
detection:
    selection:
        GrantedAccess|contains:
            - '0x1F0FFF'  # PROCESS_ALL_ACCESS
            - '0x1FFFFF' # PROCESS_ALL_ACCESS
        CallTrace|contains:
            - 'VirtualAllocEx'
            - 'WriteProcessMemory'
            - 'CreateRemoteThread'
            - 'NtQueueApcThread'
    condition: selection
falsepositives:
    - 调试器
    - 安全软件
level: high
```

### T1047 WMI 执行

```yaml
title: WMI 远程命令执行
id: d4e5f6a7-b8c9-0123-defa-456789012345
status: stable
description: 检测通过 WMI 远程执行命令
references:
    - https://attack.mitre.org/techniques/T1047/
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wmic.exe'
        CommandLine|contains:
            - 'process call create'
            - '/node:'
    condition: selection
falsepositives:
    - 管理员远程管理
level: medium
```

### T1021.002 SMB/Windows Admin Shares

```yaml
title: PsExec 服务安装
id: e5f6a7b8-c9d0-1234-efab-567890123456
status: stable
description: 检测 PsExec 类工具的服务安装
references:
    - https://attack.mitre.org/techniques/T1021/002/
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|contains:
            - 'PSEXESVC'
            - 'csexec'
            - 'remcom'
    condition: selection
falsepositives:
    - 管理员使用 PsExec
level: medium
```

### T1070.001 日志清除

```yaml
title: Windows 安全日志清除
id: f6a7b8c9-d0e1-2345-fabc-678901234567
status: stable
description: 检测安全日志被清除
references:
    - https://attack.mitre.org/techniques/T1070/001/
tags:
    - attack.defense_evasion
    - attack.t1070.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 1102
    condition: selection
falsepositives:
    - 日志轮转策略
level: high
```

### T1547.001 注册表启动项

```yaml
title: 可疑注册表启动项添加
id: a7b8c9d0-e1f2-3456-abcd-789012345678
status: stable
description: 检测向 Run 键添加启动项
references:
    - https://attack.mitre.org/techniques/T1547/001/
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\CurrentVersion\Run'
            - '\CurrentVersion\RunOnce'
    filter:
        Details|contains:
            - 'C:\Program Files\'
            - 'C:\Windows\System32\'
    condition: selection and not filter
falsepositives:
    - 软件安装
level: medium
```

## 威胁狩猎查询模板

### Splunk

```spl
# 检测可疑父子进程关系
index=windows sourcetype=WinEventLog:Security EventCode=4688
| eval parent_child=ParentProcessName."->"ProcessName
| where match(parent_child, "(WINWORD|EXCEL|OUTLOOK).*->(cmd|powershell|wscript)")
| stats count by Computer, parent_child, CommandLine
```

### Elastic/KQL

```kql
// 检测 PowerShell 下载行为
event.category: process and
process.name: powershell.exe and
process.command_line: (*downloadstring* or *webclient* or *bitstransfer*)
```

### Microsoft Sentinel/KQL

```kql
// 检测横向移动
DeviceNetworkEvents
| where RemotePort in (445, 135, 3389, 22)
| summarize
    TargetCount = dcount(RemoteIP),
    Targets = make_set(RemoteIP)
  by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where TargetCount > 5
```

## 检测规则分级标准

| 级别 | 说明 | 误报率 | 响应优先级 |
|------|------|--------|-----------|
| critical | 明确恶意行为 | 极低 | 立即响应 |
| high | 高度可疑 | 低 | 优先调查 |
| medium | 需要关注 | 中等 | 正常调查 |
| low | 异常但可能合法 | 较高 | 低优先级 |
