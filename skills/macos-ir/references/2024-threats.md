# 2024 年 macOS 威胁情报

## 主要威胁家族

### 1. Cuckoo Stealer (2024.04)

**概述**: 跨 Intel/ARM 的信息窃取+间谍软件混合体

**攻击链**:
1. 伪装音乐软件 DMG 分发
2. 使用 `osascript` 显示假密码弹窗
3. 收集系统信息 (`system_profiler`)
4. 窃取 Keychain、浏览器数据
5. 通过 LaunchAgent 持久化

**检测特征**:
```bash
# 密码文件
/tmp/pw.dat
/private/tmp/pw.dat

# 进程特征
osascript -e 'display dialog "macOS needs to access System Settings"'
CommandLine =~ 'hidden answer'

# LOTL 工具
xattr, osascript, system_profiler
```

**ATT&CK**: T1059.002, T1555.001, T1543.001

---

### 2. Atomic Stealer (AMOS) 变种

**概述**: 持续演进的 macOS 信息窃取器，2024 年新增后门功能

**新特性 (2024)**:
- AppleScript 代码混淆
- 后门持久化访问
- 加密货币钱包窃取增强

**检测特征**:
```bash
# osascript 密码窃取 (混淆变体)
CommandLine =~ 'osascript.*-e.*display dialog'
CommandLine =~ 'hidden answer'

# 钱包目标
~/Library/Application Support/Exodus/
~/Library/Application Support/Electrum/
```

---

### 3. Banshee Stealer

**概述**: 2024 年出现的 macOS 信息窃取即服务 (MaaS)

**特点**:
- 反分析检测
- 模块化架构
- Telegram 作为 C2

**检测**: 类似 Atomic/Cuckoo 的 osascript 技术

---

### 4. MacSync Stealer (2024.12)

**概述**: 首个滥用 Apple 公证 (Notarization) 的窃取器

**创新攻击**:
1. 使用有效签名和公证的 Swift 应用
2. **绕过 Gatekeeper 和 XProtect**
3. 运行后从互联网下载恶意负载
4. 公证时无法检测 (负载动态加载)

**检测要点**:
- 监控已签名应用的异常网络行为
- 关注运行后下载可执行文件的行为

---

### 5. DPRK/Lazarus 供应链攻击

**概述**: 朝鲜 APT 针对加密货币和开发者的持续攻击

**2024 年活动**:
- **Contagious Interview**: 假面试攻击开发者
- **Operation In(ter)ception**: 供应链投毒
- **ToDoSwift**: BlueNoroff 恶意软件
- **Tauri 框架应用**: 使用扩展属性隐藏代码

**目标**:
- 加密货币交易所
- DeFi 项目
- 开发者 (npm/PyPI 投毒)

**检测特征**:
```bash
# 可疑开发者工具
node/npm/python + crypto/wallet/defi

# 扩展属性隐藏
xattr -l [app] | grep -v "com.apple"

# PDF 诱饵文件
/Applications/*.app/Contents/Resources/*.pdf
```

---

### 6. Cthulhu Stealer (2024.08)

**概述**: 低成本 MaaS，月费 $500

**特点**:
- 类似 Atomic Stealer
- 目标: 游戏凭据、加密钱包

---

## 2024 年重大漏洞

### CVE-2024-44131 - TCC 绕过 (FileProvider)
- **影响**: macOS < 15, iOS < 18
- **危害**: 应用可在用户不知情下访问敏感数据
- **利用**: 通过 symlink 劫持 Files 应用操作

### CVE-2024-44133 - "HM Surf" TCC 绕过
- **影响**: macOS < Sequoia
- **危害**: 绕过 Safari 隐私设置，访问摄像头/麦克风/位置
- **利用**: 修改 Safari TCC 目录配置文件
- **在野利用**: Adload 恶意软件家族

---

## 攻击趋势总结

### 1. osascript 凭据窃取成为标准
几乎所有 2024 年的 macOS 信息窃取器都使用 `osascript` 显示假密码弹窗:
```applescript
display dialog "macOS needs to access System Settings" with hidden answer
```

### 2. 公证滥用
MacSync 展示了攻击者可以获得 Apple 公证，使恶意应用绕过 Gatekeeper。

### 3. LOTL (Living Off the Land) 技术
常用系统工具:
- `osascript` - AppleScript 执行
- `xattr` - 属性操作
- `system_profiler` - 系统信息收集
- `security` - Keychain 访问

### 4. 供应链攻击常态化
DPRK 持续通过 npm/PyPI 投毒和假面试攻击开发者。

---

## 检测优先级

| 优先级 | 检测项 | 原因 |
|--------|--------|------|
| P0 | osascript + "display dialog" + "password" | 2024 年最常见窃取技术 |
| P0 | 新增 LaunchAgent + 可疑内容 | 持久化后门 |
| P1 | TCC.db 异常修改 | TCC 绕过尝试 |
| P1 | 高危端口监听 | 反弹 Shell |
| P2 | 临时目录可执行文件 | 恶意软件落地 |
| P2 | xattr quarantine 移除 | Gatekeeper 绕过 |

---

## 参考来源

- [SentinelOne - 2024 macOS Malware Review](https://www.sentinelone.com/blog/2024-macos-malware-review-infostealers-backdoors-and-apt-campaigns-targeting-the-enterprise/)
- [Kandji - Cuckoo Stealer](https://www.kandji.io/blog/malware-cuckoo-infostealer-spyware)
- [Jamf - CVE-2024-44131 TCC Bypass](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [Microsoft - HM Surf Vulnerability](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [MITRE ATT&CK - macOS Matrix](https://attack.mitre.org/matrices/enterprise/macos/)
