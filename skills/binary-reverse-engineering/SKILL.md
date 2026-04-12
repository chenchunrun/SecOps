---
name: binary-reverse-engineering
description: 二进制逆向工程和恶意软件分析。支持 PE/.NET/Go/ELF。使用 radare2、frida、pwntools、YARA。Use when analyzing binaries, reverse engineering, malware analysis, CTF, exploit development.
metadata:
  version: 1.0.0
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

## 附加资源

- `references/report-format.md` - 报告格式规范（必读）
