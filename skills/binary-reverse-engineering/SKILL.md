---
name: binary-reverse-engineering
description: 二进制逆向工程和恶意软件分析。支持 PE/.NET/Go/ELF。使用 radare2、frida、pwntools、YARA。Use when analyzing binaries, reverse engineering, malware analysis, CTF, exploit development.
metadata:
  version: 1.1.0
  builtin: true
---

# 二进制逆向分析

## 依赖要求

**Python 版本**: 3.8+

**必需工具**:
| 工具 | 用途 |
|------|------|
| Python lief | PE/ELF 解析 |

```bash
pip install lief
```

**可选工具** (功能增强):

| 工具 | macOS | Windows | 用途 |
|------|-------|---------|------|
| radare2 | `brew install radare2` | [下载安装包](https://github.com/radareorg/radare2/releases) | 反汇编 |
| ghidra | `brew install ghidra` | [下载安装包](https://ghidra-sre.org/) | 反编译（**仅用无头模式**） |
| frida | `pip install frida-tools` | `pip install frida-tools` | 动态 Hook |
| pwntools | `pip install pwntools` | WSL 下安装 | 漏洞利用 |
| yara | `brew install yara` | [下载安装包](https://github.com/VirusTotal/yara/releases) | 恶意软件检测 |
| yara-python | `pip install yara-python` | `pip install yara-python` | YARA Python 绑定 |

> ⚠️ **Ghidra 使用规则**：**禁止**使用 `ghidraRun`（弹出 GUI），**必须**使用 `analyzeHeadless`（无头模式）

**环境检查**: `python3 scripts/check_env.py`

## 快速开始

```bash
# 环境检查
python3 scripts/check_env.py

# 恶意软件分析 (自动检测类型)
python3 scripts/malware_analyze.py <sample.exe>
python3 scripts/malware_analyze.py <sample.exe> --ioc       # IOC 提取
python3 scripts/malware_analyze.py <sample.exe> --json      # JSON 输出
python3 scripts/malware_analyze.py <sample.exe> --embedded  # 嵌入式 PE 检测
python3 scripts/malware_analyze.py <sample.exe> --injection # 进程注入检测

# 嵌入式 PE 提取
python3 scripts/extract_embedded.py <sample.exe>
python3 scripts/extract_embedded.py <sample.exe> --output ./extracted/

# YARA 扫描
yara yara/malware.yar <sample.exe>
yara yara/process_injection.yar <sample.exe>   # 进程注入检测
```

## 分析工作流

### Phase 1: 环境检查与文件识别
```bash
python3 scripts/check_env.py
python3 scripts/malware_analyze.py <sample> --quick
```
输出：文件类型、架构、编译器

### Phase 2: 静态分析
```bash
r2 -qc 'aaa; afl; pdf @ main' <binary>  # 反汇编
```
检查项：字符串、导入表、函数列表

### Phase 3: YARA 扫描
```bash
yara yara/malware.yar <sample>
```
输出：匹配的恶意软件家族

### Phase 4: IOC 提取
```bash
python3 scripts/malware_analyze.py <sample> --ioc
```
提取：C2 地址、URL、文件哈希

### Phase 5: 动态分析（可选）
```bash
frida -f ./<binary> -l scripts/hook.js --no-pause
```

### Phase 6: 报告生成
按 `references/report-format.md` 输出报告

## 工具栈

| 工具 | 用途 | 命令 |
|------|------|------|
| radare2 | 反汇编/反编译 | `r2 -A binary` |
| frida | 动态 Hook | `frida -f ./bin -l hook.js` |
| pwntools | 漏洞利用 | `pwn checksec binary` |
| lief | PE/ELF 解析 | Python API |
| yara | 恶意软件检测 | `yara rules.yar target` |

---

## Ghidra 无头模式（跨平台）

> ⚠️ **禁止使用 `ghidraRun`**，会弹出 GUI 界面！

```bash
# 使用封装脚本（推荐）
python3 scripts/ghidra_analyze.py <binary>
python3 scripts/ghidra_analyze.py <binary> --decompile main
python3 scripts/ghidra_analyze.py <binary> --export-all

# 手动调用 analyzeHeadless
# macOS (Homebrew)
/opt/homebrew/Cellar/ghidra/*/libexec/support/analyzeHeadless \
  /tmp/ghidra_proj TempProj -import <binary> -postScript ExportFunctions.java -deleteProject

# Windows
"%GHIDRA_HOME%\support\analyzeHeadless.bat" ^
  C:\temp\ghidra_proj TempProj -import <binary> -postScript ExportFunctions.java -deleteProject

# Linux
$GHIDRA_HOME/support/analyzeHeadless \
  /tmp/ghidra_proj TempProj -import <binary> -postScript ExportFunctions.java -deleteProject
```

**常用参数**:
| 参数 | 说明 |
|------|------|
| `-import <file>` | 导入二进制 |
| `-postScript <script>` | 分析后执行脚本 |
| `-scriptPath <dir>` | 脚本搜索路径 |
| `-deleteProject` | 分析完删除项目 |
| `-noanalysis` | 跳过自动分析 |

---

## Radare2 速查

```bash
r2 -qc 'aaa; afl; pdf @ main' binary   # 一行完整分析

# 交互模式常用命令
aaa          # 分析
afl          # 函数列表
pdf @ main   # 反汇编
pdc @ main   # 伪代码
iz           # 字符串
ii           # 导入表
/R pop rdi   # ROP gadgets
```

## Frida Hook

```javascript
// scripts/hook.js
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        console.log("s1:", Memory.readUtf8String(args[0]));
        console.log("s2:", Memory.readUtf8String(args[1]));
    }
});
```

```bash
frida -f ./binary -l scripts/hook.js --no-pause
```

## Windows 进程注入监控 (Frida)

> ⚠️ **需要 Windows 环境运行**

`hook_injection.js` 监控以下注入技术：
- Process Hollowing (CreateProcess+CREATE_SUSPENDED → NtUnmapViewOfSection → WriteProcessMemory → SetThreadContext)
- DLL Injection (VirtualAllocEx → WriteProcessMemory → CreateRemoteThread)
- APC Injection (QueueUserAPC)
- Thread Hijacking (SuspendThread → GetThreadContext → SetThreadContext)

```bash
# 启动时注入
frida -f malware.exe -l scripts/hook_injection.js --no-pause

# 附加到运行进程
frida -p <PID> -l scripts/hook_injection.js
```

**输出示例**:
```
[CRITICAL] [Process Hollowing] CreateProcessW with CREATE_SUSPENDED
    Application: C:\Windows\System32\svchost.exe
[CRITICAL] [Injection] WriteProcessMemory
    [!] Writing PE file (MZ header detected)
[CRITICAL] [Hollowing] SetThreadContext - New Entry Point: 0x00400000
```

## pwntools 模板

```python
from pwn import *
context.binary = elf = ELF('./vuln')
p = process('./vuln') if not args.REMOTE else remote('host', 1337)
payload = flat([b'A' * 64, elf.symbols['win']])
p.sendline(payload)
p.interactive()
```

---

## 脚本说明

| 脚本 | 功能 |
|------|------|
| `malware_analyze.py` | 恶意软件综合分析 (IOC/签名/C2/嵌入PE/注入检测) |
| `extract_embedded.py` | 嵌入式 PE/Shellcode 提取工具 |
| `hook_injection.js` | Windows 进程注入监控 (Frida) |
| `ghidra_analyze.py` | Ghidra 无头反编译（跨平台） |
| `check_env.py` | 环境检查和工具安装 |
| `hook.js` | Frida 通用 Hook |
| `exploit.py` | pwntools 利用模板 |
| `rop_finder.py` | ROP gadgets 搜索 |

## YARA 规则

| 规则文件 | 检测目标 |
|----------|----------|
| `malware.yar` | AsyncRAT, Amadey, LummaStealer, Formbook, AntiDebug, Keylogger, CryptoMiner |
| `process_injection.yar` | Process Hollowing, DLL Injection, APC Injection, Thread Hijacking, Process Doppelgänging |

```bash
yara yara/malware.yar ./samples/
yara yara/process_injection.yar ./samples/
yara -r yara/ ./samples/   # 所有规则
```

### 进程注入检测 (YARA)

`process_injection.yar` 覆盖以下 ATT&CK 技术：
- **T1055.012** - Process Hollowing
- **T1055.001** - DLL Injection
- **T1055.003** - Thread Execution Hijacking
- **T1055.004** - APC Injection
- **T1055.013** - Process Doppelgänging
- **T1620** - Reflective DLL Loading

## 输出规范

**必须遵循**: `references/report-format.md`

报告核心要求：
1. **11 章节结构** - 包含用途分析、攻击路径、IOC 汇总、关联分析
2. **风险评分** - 100 分制，按检测项累加
3. **攻击路径** - 必须使用 ASCII 图 + MITRE ATT&CK 映射
4. **IOC 集中** - 所有 IOC 统一在第 8 章，提供可导出格式
5. **关联分析** - 列出待深入分析的 IOC 及推荐调用的 skill
6. **问题章节** - 必须诚实说明分析局限性

---

## 与其他技能的关联

**分析过程中发现 IOC 时的处理：**

| 提取到的 IOC | 调用的技能 | 说明 |
|-------------|-----------|------|
| C2 域名 | `/domain-analysis` | 分析硬编码或解密的 C2 域名 |
| C2 IP | `/ip-analysis` | 分析回连 IP 地址 |
| 下载 URL | `/url-analysis` | 分析载荷下载地址 |

**上游技能**（可能调用本技能）：
- `office-malware-analyzer` - 分析嵌入的可执行载荷
- `pdf-analysis` - 分析嵌入的可执行文件
- `traffic-analysis` - 分析下载的恶意程序

**调用时机：**
1. 提取到 C2 配置后，对每个 IP/域名调用对应分析技能
2. 解密出下载 URL 后，调用 `/url-analysis`
3. 动态分析发现网络行为时，分析目标地址

---

## MITRE ATT&CK 技术映射

二进制逆向工程覆盖恶意软件分析和漏洞研究的多个 ATT&CK 战术：

| 战术 | 技术 | 名称 | 逆向分析场景 |
|------|------|------|-------------|
| **Execution (TA0002)** | T1055 | Process Injection | 分析注入型恶意软件的 API 调用链 |
| | T1055.001 | DLL Injection | 分析 VirtualAllocEx + WriteProcessMemory 模式 |
| | T1055.012 | Process Hollowing | 分析 CREATE_SUSPENDED + NtUnmapViewOfSection |
| | T1055.003 | Thread Execution Hijacking | 分析 SuspendThread + SetThreadContext |
| | T1055.004 | APC Injection | 分析 QueueUserAPC 调用 |
| | T1055.013 | Process Doppelgänging | 分析 TxF 事务操作 |
| | T1620 | Reflective DLL Loading | 分析自实现 Loader 的恶意 DLL |
| | T1106 | Native API | 分析直接 syscalls/Nt* 调用 |
| | T1129 | Shared Modules | 分析 LoadLibrary 动态加载 |
| | T1059.001 | PowerShell | 分析嵌入的 PowerShell 脚本 |
| **Defense Evasion (TA0005)** | T1027 | Obfuscated Files or Information | 分析加壳/加密/混淆代码 |
| | T1027.002 | Software Packing | 检测 UPX/Themida/VMProtect 等壳 |
| | T1027.007 | Dynamic API Resolution | 分析 GetProcAddress 动态解析 |
| | T1036 | Masquerading | 分析伪装系统进程名 |
| | T1140 | Deobfuscate/Decode Files | 分析运行时自解密 |
| | T1497.001 | System Checks | 分析反调试/反虚拟机代码 |
| | T1620 | Reflective DLL Loading | 分析内存加载的 DLL |
| **Credential Access (TA0006)** | T1555 | Credentials from Password Stores | 分析凭证提取代码 |
| | T1003 | OS Credential Dumping | 分析 LSASS 操作代码 |
| **Discovery (TA0007)** | T1082 | System Information Discovery | 分析环境检测代码 |
| | T1497 | Virtualization/Sandbox Evasion | 分析反沙箱技术 |
| **Collection (TA0009)** | T1056 | Input Capture | 分析键盘记录器 |
| | T1005 | Data from Local System | 分析文件搜索/窃取代码 |
| **Command and Control (TA0011)** | T1071 | Application Layer Protocol | 分析 C2 通信协议 |
| | T1573 | Encrypted Channel | 分析 TLS/自定义加密通信 |
| | T1105 | Ingress Tool Transfer | 分析下载器/投放器 |
| **Exfiltration (TA0010)** | T1041 | Exfiltration Over C2 Channel | 分析数据外泄代码 |

## OWASP Top 10 / CWE 映射

二进制逆向分析关联的应用安全维度：

| OWASP 类别 | CWE | 关联场景 |
|-----------|-----|---------|
| **A01** Broken Access Control | CWE-787 | 缓冲区溢出导致代码执行 |
| | CWE-125 | 越界读取泄露内存数据 |
| **A03** Injection | CWE-94 | 代码注入漏洞的二进制利用 |
| | CWE-119 | 内存操作不当 |
| **A04** Insecure Design | CWE-20 | 输入验证缺失导致漏洞 |
| **A05** Security Misconfiguration | CWE-732 | 权限配置错误被利用 |
| **A06** Vulnerable Components | CWE-1104 | 第三方库漏洞利用 |
| | CWE-918 | SSRF 在二进制中的利用 |
| **A08** Software & Data Integrity Failures | CWE-345 | 未验证的更新/加载 |
| **A10** SSRF | CWE-918 | 服务端请求伪造的载荷分析 |

## CVE 参考表

逆向分析中常见的高危 CVE 类型：

| CVE 类型 | 漏洞模式 | YARA 特征 | ATT&CK 映射 |
|---------|---------|-----------|------------|
| CVE-2021-34527 (PrintNightmare) | 打印服务权限提升 | RpcAddPrinterDriverEx | T1068 |
| CVE-2021-1675 | Windows Print Spooler | printer import 操作 | T1068 |
| CVE-2023-23397 | Outlook 权限提升 | PidLidReminderProperty | T1068 |
| CVE-2023-21716 | Word RTF RCE | RTF 对象解析 | T1203 |
| CVE-2021-44228 (Log4Shell) | JNDI 注入 | \${jndi:ldap://} | T1059 |
| CVE-2022-26923 | AD Kerberos 绕过 | dNSHostName 属性 | T1098 |

## IOC 采集指引

| IOC 类型 | 提取方法 | 存储格式 | 工具支持 |
|---------|---------|---------|----------|
| C2 IP/域名 | 字符串提取/内存转储 | ip_addr/domain | malware_analyze.py --ioc |
| C2 URL | 字符串扫描 | url | strings + regex |
| 文件哈希 | 计算 PE/ELF 哈希 | hash_sha256 | hashlib |
| Mutex 名称 | CreateMutex 调用分析 | mutex_name | YARA + radare2 |
| 注册表键 | RegCreateKey 分析 | registry_key | radare2 |
| API 调用序列 | IAT/动态分析 | api_call_chain | frida hook |
| 嵌入式 PE | 提取嵌入的二进制 | pe_file | extract_embedded.py |
| 加密密钥 | 解密代码分析 | crypto_key | radare2 + 脚本 |
| User-Agent | HTTP 分析 | user_agent | strings + mitmproxy |
| C2 协议特征 | 网络行为分析 | protocol_pattern | frida + Wireshark |

## Sigma 检测规则

### 规则 1: 恶意软件特征进程创建

```yaml
title: Malware Process Creation from Binary Analysis IOCs
description: >
  基于二进制逆向分析提取的 IOC，
  检测恶意软件创建的进程。
status: experimental
author: sec-skills
references:
  - https://attack.mitre.org/techniques/T1055/
  - https://attack.mitre.org/techniques/T1105/
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1055
  - attack.t1105
logsource:
  product: windows
  category: process_creation
detection:
  selection_suspicious_processes:
    Image:
      - 'C:\\Users\\*\\AppData\\Local\\Temp\\*.exe'
      - 'C:\\Users\\*\\AppData\\Roaming\\*.exe'
      - 'C:\\ProgramData\\*.exe'
  selection_suspicious_parent:
    ParentImage:
      - 'C:\\Windows\\System32\\svchost.exe'
      - 'C:\\Windows\\System32\\rundll32.exe'
      - 'C:\\Windows\\System32\\mshta.exe'
  condition: selection_suspicious_processes or (selection_suspicious_processes and selection_suspicious_parent)
falsepositives:
  - 合法的临时可执行文件
level: high
```

### 规则 2: 进程注入行为检测

```yaml
title: Process Injection API Call Sequence
description: >
  检测进程注入技术的 API 调用序列，
  基于二进制逆向分析中发现的注入模式。
status: experimental
author: sec-skills
references:
  - https://attack.mitre.org/techniques/T1055/001/
  - https://attack.mitre.org/techniques/T1055/012/
tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1055.001
  - attack.t1055.012
logsource:
  product: windows
  category: process_creation
detection:
  selection_injection_tools:
    Image:
      - 'C:\\Windows\\System32\\rundll32.exe'
      - 'C:\\Windows\\System32\\regsvr32.exe'
      - 'C:\\Windows\\System32\\mshta.exe'
  selection_suspicious_commandline:
    CommandLine:
      - '*\\AppData\\*'
      - '*http*'
      - '*javascript*'
      - '*eval*'
  condition: selection_injection_tools and selection_suspicious_commandline
falsepositives:
  - 合法的 regsvr32/rundll32 使用
level: high
```

## 合规标准关联

| 标准 | 条款 | 关联 |
|------|------|------|
| **ISO 27001** | A.8.7 | 恶意软件防范——逆向分析支持恶意软件检测能力 |
| **ISO 27001** | A.12.5.1 | 技术漏洞管理——二进制分析发现软件漏洞 |
| **ISO 27001** | A.16.1.2 | 事件报告——逆向分析为事件响应提供证据 |
| **NIST SP 800-83** | 3.2 | 恶意软件事件预防——低级分析增强检测能力 |
| **NIST SP 800-53** | SI-3 | 恶意代码检测——二进制扫描自动化 |
| **NIST SP 800-53** | SI-7 | 软件/固件完整性——逆向验证代码完整性 |
| **NIST SP 800-61** | 3.2 | 事件响应——恶意软件分析支持分类和优先级 |
| **PCI DSS** | 5.1 | 恶意软件防护——所有系统需定期扫描 |
| **PCI DSS** | 6.5 | 安全编码——逆向发现的安全漏洞需修复 |
| **GDPR** | Art. 33 | 数据泄露通知——逆向分析确定泄露范围 |
| **PIPL** | 第57条 | 数据安全事件处置——恶意软件分析支持事件调查 |

## 跨技能工作流

### 工作流 1: 文档载荷分析链

```
office-malware-analyzer (提取嵌入 PE)
  └─→ binary-reverse-engineering (逆向分析)
       └─→ url-analysis (分析 C2 URL)
            └─→ ttp-extractor (提取 TTP)
                 └─→ pdf-report (生成报告)
```

### 工作流 2: 恶意软件事件响应链

```
linux-ir/windows-ir (发现可疑文件)
  └─→ binary-reverse-engineering (分析样本)
       ├─→ domain-analysis (C2 域名)
       ├─→ ip-analysis (C2 IP)
       └─→ ttp-extractor (提取 ATT&CK 技术)
            └─→ pdf-report (事件报告)
```

### 工作流 3: PDF 嵌入载荷分析链

```
pdf-analysis (提取嵌入 PE)
  └─→ binary-reverse-engineering (逆向分析)
       └─→ code-audit (分析源码/反编译代码)
            └─→ sca-analyzer (依赖漏洞扫描)
                 └─→ ttp-extractor (TTP 提取)
```

## 附加资源

- `references/report-format.md` - 报告格式规范（必读）
