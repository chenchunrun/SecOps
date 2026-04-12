---
name: ttp-extractor
description: 从安全报告和威胁情报中提取攻防技战法，映射到 MITRE ATT&CK 框架并生成检测规则。当用户要求"TTP 分析"、"ATT&CK 映射"、"提取攻击技术"、"生成 Sigma 规则"、"威胁狩猎规则提取"时使用此技能。
metadata:
  version: 1.0.0
  builtin: true
---

# 攻防技战法提取 (TTP Extractor)

## 核心任务

从安全报告、威胁情报、事件分析、漏洞披露等文档中提取：
1. **攻击技术** (Attack Techniques) - 攻击者使用的具体技术手段
2. **防御技术** (Defense Techniques) - 对应的检测和防御方法
3. **战术阶段** (Tactics) - 攻击所处的阶段（初始访问、执行、持久化等）

## 输出格式

### 标准输出格式
```markdown
# 攻防技战法分析报告

## 攻击技术

### [T1566] 钓鱼攻击
- **战术阶段**: 初始访问 (Initial Access)
- **技术描述**: 通过伪装的邮件附件投递恶意载荷
- **具体手法**:
  - 使用 .docm 宏文档
  - 伪装为发票/简历
- **IOC 指标**:
  - 发件人: xxx@malicious.com
  - 附件哈希: abc123...
- **检测规则**:
  ```yaml
  title: 可疑 Office 宏执行
  detection:
    selection:
      EventID: 1
      ParentImage|endswith: '\WINWORD.EXE'
      Image|endswith: '\cmd.exe'
  ```

### [T1059.001] PowerShell 执行
- **战术阶段**: 执行 (Execution)
- **技术描述**: 使用 PowerShell 下载并执行恶意脚本
- **具体手法**:
  - Base64 编码命令
  - 绕过执行策略
- **命令示例**: `powershell -enc JABjAD0A...`
- **检测规则**:
  ```sigma
  detection:
    selection:
      CommandLine|contains:
        - '-enc'
        - '-encodedcommand'
        - 'downloadstring'
  ```

## 防御技术

### 针对 [T1566] 的防御
| 防御层 | 措施 | 优先级 |
|--------|------|--------|
| 邮件网关 | 阻止宏文档附件 | 高 |
| 终端 | 禁用 Office 宏 | 高 |
| 用户 | 安全意识培训 | 中 |
| 监控 | 部署 Sigma 检测规则 | 高 |

### 针对 [T1059.001] 的防御
| 防御层 | 措施 | 优先级 |
|--------|------|--------|
| 策略 | 启用 Constrained Language Mode | 高 |
| 日志 | 启用 PowerShell 脚本块日志 | 高 |
| 终端 | 部署 AMSI 集成方案 | 中 |

## 攻击链路图

```
钓鱼邮件 → 宏执行 → PowerShell下载 → 持久化 → C2通信 → 数据窃取
[T1566]    [T1204]   [T1059.001]      [T1053]   [T1071]   [T1041]
```

## ATT&CK 矩阵映射

| 战术 | 技术 | 子技术 |
|------|------|--------|
| 初始访问 | T1566 钓鱼 | T1566.001 附件 |
| 执行 | T1059 脚本 | T1059.001 PowerShell |
| 持久化 | T1053 计划任务 | - |
| C2 | T1071 应用层协议 | T1071.001 HTTP |

## 威胁狩猎查询

### Splunk
```spl
index=windows EventCode=4688
| where ParentImage like "%WINWORD.EXE%"
| where Image like "%cmd.exe%" OR Image like "%powershell.exe%"
```

### KQL (Microsoft Sentinel)
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe")
| where FileName in~ ("cmd.exe", "powershell.exe")
```
```

## 提取规则

### 识别攻击技术
从文档中识别以下内容并映射到 ATT&CK：
- **漏洞利用**: CVE 编号、利用方式、影响范围
- **恶意软件行为**: 进程创建、文件操作、注册表修改、网络连接
- **攻击工具**: Cobalt Strike、Mimikatz、PsExec 等
- **攻击手法**: 钓鱼、水坑、供应链、暴力破解等

### 识别防御技术
- **检测方法**: 日志分析、行为监控、签名检测
- **防护措施**: 网络隔离、权限控制、补丁修复
- **响应动作**: 隔离主机、阻断IP、重置凭据

### ATT&CK 映射
自动将提取的技术映射到 MITRE ATT&CK 框架：
- 战术 (Tactics): 14 个阶段
- 技术 (Techniques): T 编号
- 子技术 (Sub-techniques): .xxx 编号

## 使用方式

### 分析安全报告
```
用户：分析这份 APT 报告，提取攻防技战法
```

### 从事件中提取
```
用户：从这个安全事件描述中提取攻击技术和防御建议
```

### 生成检测规则
```
用户：提取攻击技术并生成 Sigma 检测规则
```

### 生成防御手册
```
用户：分析这个攻击，给出完整的防御方案
```

## 工作流程

1. **读取文档**: 读取安全报告/事件描述
2. **识别攻击指标**: 提取 IOC、恶意行为、攻击工具
3. **ATT&CK 映射**: 将行为映射到技术编号
4. **生成防御措施**: 针对每个攻击技术生成防御建议
5. **输出报告**: 按标准格式输出分析结果

## 输出选项

| 选项 | 说明 |
|------|------|
| `--format markdown` | Markdown 报告（默认）|
| `--format json` | 结构化 JSON |
| `--with-sigma` | 包含 Sigma 检测规则 |
| `--with-hunt` | 包含威胁狩猎查询 |
| `--defense-only` | 仅输出防御措施 |
| `--attack-only` | 仅输出攻击技术 |

## 附加资源

- [ATT&CK 战术列表](references/attack-tactics.md)
- [常见攻击技术映射](references/common-techniques.md)
- [Sigma 规则模板](references/sigma-templates.md)
