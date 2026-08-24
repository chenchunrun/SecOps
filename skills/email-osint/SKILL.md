---
name: email-osint
description: 邮箱情报调查与关联分析。当用户要求"邮箱调查"、"邮箱搜索"、"查邮箱"、"邮箱关联"、"社交账号发现"、"用户名搜索"、"数字足迹"、"OSINT调查"、"人肉搜索"时使用此技能。
metadata:
  version: 2.0.0
  builtin: true
---

# 邮箱 OSINT 调查技能

基于邮箱地址进行多维度情报收集，发现关联账号、用户画像和数字足迹。

## 依赖要求

**Python 环境**: Python 3.8+

**内置工具** (已打包到 `tools/` 目录):

| 工具 | 用途 | 位置 |
|------|------|------|
| **holehe** | 邮箱注册检测 (120+ 站点) | `tools/holehe/` |
| **blackbird** | 用户名/邮箱搜索 (600+ 站点) | `tools/blackbird/` |

**安装依赖**:
```bash
# 一键安装所有依赖
bash scripts/setup_tools.sh

# 或手动安装
pip3 install -r requirements.txt
```

**可选依赖**:
```bash
pip3 install 'httpx[socks]'  # 代理支持
```

**环境检测**:
```bash
python3 scripts/check_env.py
```

---

## 调查工作流

```
输入: target@example.com
        │
        ├─► Phase 1: 邮箱服务商分析
        │
        ├─► Phase 2: 平台注册检测 (holehe)
        │
        ├─► Phase 3: 用户名提取与变体生成 + 风险评估
        │
        ├─► Phase 4: 用户名搜索 (blackbird)
        │
        ├─► Phase 4.5: 账号归属验证 ⭐ 关键步骤
        │
        ├─► Phase 5: 深度信息收集
        │
        └─► Phase 6: 用户画像生成 (三层分离报告)
```

### ⚠️ 核心原则: 推断必须有据

**报告三层分离**:
1. **确认事实** - 直接来自数据源，无推断
2. **有据推断** - 有明确证据链支撑
3. **待验证线索** - 需进一步调查确认

**禁止**: 无证据的推测性结论

---

## Phase 1: 邮箱服务商分析

### 1.1 解析邮箱结构

```
username@domain.com
   │         │
   │         └── 域名分析
   └── 用户名提取
```

### 1.2 常见邮箱服务商情报价值

| 服务商 | 域名 | 特点 | 可提取信息 |
|--------|------|------|-----------|
| **QQ 邮箱** | qq.com | 用户名=QQ号 | QQ空间、QQ头像 |
| **163 邮箱** | 163.com | 中国用户 | 网易系产品 |
| **Gmail** | gmail.com | 国际化 | Google 生态 |
| **ProtonMail** | proton.me, protonmail.com | 隐私意识高 | 加密邮箱 |
| **Outlook** | outlook.com, hotmail.com | 微软生态 | Office365 |
| **企业邮箱** | 自定义域名 | 可关联域名分析 | 公司信息 |

### 1.3 QQ 邮箱特殊处理

```bash
# QQ 号提取
echo "710526925@qq.com" | grep -oP '^\d+'
# 输出: 710526925

# QQ 头像
https://q1.qlogo.cn/g?b=qq&nk={QQ号}&s=640

# QQ 空间
https://user.qzone.qq.com/{QQ号}
```

### 1.4 QQ 号年份推测

| 位数 | 注册年份 | 稀有度 |
|------|----------|--------|
| 5 位 | 1999-2000 | 极稀有 |
| 6 位 | 2000-2003 | 稀有 |
| 7 位 | 2003-2006 | 较早 |
| 8 位 | 2006-2008 | 普通 |
| 9 位 | 2008-2012 | 普通 |
| 10 位 | 2012+ | 新用户 |

---

## Phase 2: 平台注册检测 (holehe)

### 2.1 运行 holehe

```bash
# 使用内置 holehe (推荐)
python3 scripts/holehe_run.py target@example.com
```

### 2.2 输出解读

| 符号 | 含义 |
|------|------|
| `[+]` | ✅ 已注册 |
| `[-]` | ❌ 未注册 |
| `[x]` | ⚠️ 被限流，无法确定 |

### 2.3 重点关注平台

| 平台 | 信息价值 |
|------|----------|
| **Gravatar** | 头像、昵称、简介 |
| **GitHub** | 技术背景、项目、邮箱 |
| **Twitter** | 社交关系、发言 |
| **LinkedIn** | 职业信息 |
| **Discord** | 社群参与 |
| **ProtonMail** | 隐私意识指标 |

### 2.4 holehe 额外信息

某些平台会返回额外信息：
- **ProtonMail**: 账号创建时间
- **Gravatar**: 昵称、头像 URL

---

## Phase 3: 用户名提取与变体生成

### 3.1 从邮箱提取用户名

```python
email = "john.doe123@gmail.com"
username = email.split('@')[0]  # john.doe123
```

### 3.2 用户名长度风险评估 ⭐

**执行 blackbird 前必须评估用户名长度风险**:

| 长度 | 风险等级 | 重名概率 | 处理策略 |
|------|----------|----------|----------|
| 1-3 字符 | 🔴 极高 | >95% | blackbird 结果仅供参考，必须逐一验证归属 |
| 4-5 字符 | 🟠 高 | ~70% | 优先验证有元数据的账号 |
| 6-8 字符 | 🟡 中 | ~30% | 交叉验证高价值平台 |
| ≥9 字符 | 🟢 低 | <10% | 可采信大部分结果 |

**短用户名处理规则**:
- 用户名 ≤5 字符时，blackbird 发现的账号**默认归类为"待验证线索"**
- 不得直接用于画像推断，除非通过 Phase 4.5 验证

### 3.3 生成用户名变体

| 原始 | 变体 | 规则 |
|------|------|------|
| `john.doe123` | `johndoe123` | 移除点 |
| `john.doe123` | `john_doe123` | 点→下划线 |
| `john.doe123` | `john-doe123` | 点→连字符 |
| `john.doe123` | `johndoe` | 移除数字 |
| `j1ufan9` | `jiufan9` | Leet speak 还原 |

### 3.3 Leet Speak 对照表

| Leet | 原字符 |
|------|--------|
| 0 | o |
| 1 | i, l |
| 3 | e |
| 4 | a |
| 5 | s |
| 7 | t |
| 8 | b |
| 9 | g |

---

## Phase 4: 用户名搜索 (blackbird)

### 4.1 运行 blackbird

```bash
# 使用内置 blackbird (推荐)

# 单个用户名
python3 scripts/blackbird_run.py -u johndoe --json --no-update

# 多个用户名
python3 scripts/blackbird_run.py -u johndoe john_doe johndoe123 --json --no-update

# 邮箱搜索 (站点较少)
python3 scripts/blackbird_run.py -e target@example.com --json --no-update
```

### 4.2 输出位置

```
tools/blackbird/results/{username}_{date}_blackbird/
└── {username}_{date}_blackbird.json
```

### 4.3 元数据提取

Blackbird 可自动提取某些平台的元数据：

| 平台 | 可提取信息 |
|------|-----------|
| **Duolingo** | 昵称、学习语言、头像 |
| **GitHub** | 仓库、粉丝、简介 |
| **StreamElements** | 昵称 |

---

## Phase 4.5: 账号归属验证 ⭐

**目的**: 判断 blackbird 发现的账号是否属于目标人物

### 4.5.1 验证必要性判断

```
用户名长度评估
      │
      ├── ≤5 字符 → 🔴 必须验证
      │
      ├── 6-8 字符 → 🟡 建议验证高价值账号
      │
      └── ≥9 字符 → 🟢 可选验证
```

### 4.5.2 验证方法

| 方法 | 操作 | 置信度提升 |
|------|------|-----------|
| **邮箱匹配** | GitHub 提交邮箱 = 目标邮箱 | ✅ 高 (可确认) |
| **Gravatar 匹配** | 目标邮箱 MD5 查询有结果 | ✅ 高 (可确认) |
| **交叉链接** | 账号简介互相指向 | ✅ 高 |
| **元数据一致** | 昵称、头像、地理位置一致 | ⚠️ 中 |
| **行业相关** | 账号内容与目标行业匹配 | ⚠️ 中 |
| **仅用户名匹配** | 无其他证据 | ❌ 低 (待验证) |

### 4.5.3 GitHub 验证 (高价值)

```bash
# 检查提交邮箱
curl -s "https://api.github.com/users/{username}/events/public" | \
  grep -o '"email":"[^"]*"' | sort -u

# 如果提交邮箱 = 目标邮箱 → 确认归属
```

### 4.5.4 Gravatar 验证 (直接关联)

```bash
# 通过目标邮箱 MD5 查询
EMAIL_HASH=$(echo -n "target@example.com" | md5sum | cut -d' ' -f1)
curl -s "https://gravatar.com/${EMAIL_HASH}.json"

# 有结果 → 确认目标使用 Gravatar，可获取昵称/头像
```

### 4.5.5 输出: 置信度分级

将 blackbird 结果分为三类:

| 分类 | 标准 | 报告归属 |
|------|------|----------|
| ✅ **已验证** | 邮箱匹配/交叉链接 | 确认事实 |
| ⚠️ **高可能** | 多维度元数据一致 | 有据推断 |
| ❓ **待验证** | 仅用户名匹配 | 待验证线索 |

### 4.5.6 验证记录模板

```markdown
### 账号验证记录

| 平台 | 用户名 | 验证方法 | 结果 | 置信度 |
|------|--------|----------|------|--------|
| GitHub | rko | 提交邮箱检查 | 邮箱不匹配 | ❌ 排除 |
| 247CTF | rko | 无验证手段 | - | ❓ 待验证 |
| Duolingo | rko | 元数据 | 名字 Remo，无关联 | ❓ 待验证 |
```

---

## Phase 5: 深度信息收集

### 5.1 GitHub 详情

```bash
# 用户信息
curl https://api.github.com/users/{username}

# 仓库列表
curl https://api.github.com/users/{username}/repos?sort=updated

# 关注点
- 创建时间
- 公开仓库数
- 个人博客
- Fork 的安全工具
```

### 5.2 Gravatar 信息

```bash
# 通过邮箱 MD5 查询
EMAIL_HASH=$(echo -n "target@example.com" | md5sum | cut -d' ' -f1)
curl "https://gravatar.com/${EMAIL_HASH}.json"
```

### 5.3 社交平台深入

| 平台 | 深入方法 |
|------|----------|
| Twitter | 查看发推历史、关注列表 |
| GitHub | 分析仓库、提交邮箱 |
| 知乎 | 查看回答、关注话题 |
| LinkedIn | 职业履历、教育背景 |

---

## Phase 6: 用户画像生成 (三层分离)

### 6.1 报告三层结构 ⭐

**第一层: 确认事实** (直接来自数据源)
```markdown
| 事实 | 数据来源 | 原始数据 |
|------|----------|----------|
| 邮箱使用 Microsoft 365 | holehe [+] | office365.com |
| 域名属于 XX 公司 | ICP 备案 | 京ICP备XXXX号 |
```

**第二层: 有据推断** (必须有证据链)
```markdown
| 推断 | 证据链 | 置信度 |
|------|--------|--------|
| 目标是安全从业者 | 1. 公司官网写明从事安全<br>2. 产品是安全检测 | ✅ 高 |
| 目标有技术背景 | 1. 公司技术团队占比70%<br>2. 企业邮箱非职能角色 | ⚠️ 中 |
```

**第三层: 待验证线索** (无法确认归属)
```markdown
| 线索 | 问题 | 验证建议 |
|------|------|----------|
| 247CTF 存在同名账号 | 用户名仅3字符 | 检查个人主页 |
| Duolingo 显示名 Remo | 无关联证据 | 需其他验证 |
```

### 6.2 证据链模板

每条推断必须包含:

```markdown
**推断**: [具体结论]

**证据链**:
1. [来源1]: [具体内容]
2. [来源2]: [具体内容]

**反证/风险**: [可能的反面证据]

**置信度**: ✅高 / ⚠️中 / ❓低

---
置信度标准:
- ✅ 高: ≥2个独立数据源交叉验证
- ⚠️ 中: 1个可靠来源 + 合理推断
- ❓ 低: 仅用户名匹配或单一弱证据
```

### 6.3 画像维度

| 维度 | 数据来源 | 证据要求 |
|------|----------|----------|
| **地域** | 邮箱服务商、ICP、语言 | 中 |
| **组织** | 域名备案、官网 | 高 (直接来源) |
| **职业** | LinkedIn、公司介绍 | 中-高 |
| **技术能力** | GitHub (需验证归属) | 需验证 |
| **隐私意识** | 邮箱类型、账号暴露 | 低 |

### 6.4 禁止的推断模式

| ❌ 错误示例 | 问题 | ✅ 正确做法 |
|------------|------|------------|
| "可能是创始人" | 无证据 | 标注为"待验证"或不写 |
| "技术能力高 (CTF)" | CTF 账号未验证归属 | 移至"待验证线索" |
| "活跃于安全社区" | 仅基于用户名匹配 | 需验证后才能结论 |

### 6.5 隐私意识评估

| 指标 | 低隐私 | 高隐私 |
|------|--------|--------|
| 邮箱 | QQ/163 | ProtonMail |
| 平台数 | 多 | 少 |
| 信息完整度 | 高 | 低 |
| 安全工具 | 无 | 有 |

### 6.6 风险评估 (针对安全调查)

| 指标 | 说明 | 证据要求 |
|------|------|----------|
| 🔴 高风险 | Fork 红队工具、活跃 CTF | 必须验证账号归属 |
| 🟡 中风险 | 技术背景、安全相关 | 需有据推断 |
| 🟢 低风险 | 普通用户 | 可基于整体判断 |

---

## 快速调查命令

```bash
# 一键调查脚本 (在 skill 目录下执行)
EMAIL="target@example.com"
USERNAME=$(echo $EMAIL | cut -d'@' -f1)

# Step 1: holehe 邮箱注册检测
python3 scripts/holehe_run.py $EMAIL

# Step 2: blackbird 用户名搜索
python3 scripts/blackbird_run.py -u $USERNAME --json --no-update

# Step 3: 如果是 QQ 邮箱
if [[ $EMAIL == *"@qq.com" ]]; then
    QQ=$(echo $EMAIL | grep -oP '^\d+')
    echo "QQ 头像: https://q1.qlogo.cn/g?b=qq&nk=${QQ}&s=640"
    echo "QQ 空间: https://user.qzone.qq.com/${QQ}"
fi
```

---

## 输出报告格式

按 `references/report-format.md` 生成报告，包含：

1. **目标信息** - 邮箱、用户名、服务商
2. **平台发现** - holehe + blackbird 结果汇总
3. **关键发现** - 重要账号、元数据
4. **用户画像** - 地域、职业、兴趣、风险
5. **关联图谱** - 用户名变体关系
6. **后续建议** - 深入调查方向

---

## 工具对比

| 工具 | 检测方式 | 站点数 | 速度 | 静默性 |
|------|----------|--------|------|--------|
| **holehe** | 忘记密码 API | 120+ | 快 (~10s) | 高 |
| **blackbird** | 个人主页探测 | 600+ | 慢 (~3min) | 高 |

**最佳实践**: 先用 holehe 快速扫描，再用 blackbird 深度搜索

---

## 关联技能

### 输入来源 (这些技能可产出邮箱)

| 来源技能 | 产出环节 | 邮箱类型 |
|----------|----------|----------|
| `phishing-analysis` | 邮件头解析 | 发件人/收件人邮箱 |
| `auth-log-analysis` | 登录日志分析 | 用户账户邮箱 |
| `traffic-analysis` | SMTP/HTTP 流量 | 通信邮箱 |
| `asset-discovery` | WHOIS/子域名 | 注册人/管理员邮箱 |
| `domain-analysis` | ICP/WHOIS 查询 | 备案联系邮箱 |
| `windows-ir` | 用户账户分析 | 系统用户邮箱 |

### 输出调用 (本技能发现后可调用)

| 发现内容 | 调用技能 |
|----------|----------|
| 企业邮箱域名 | `domain-analysis` |
| GitHub 安全工具 | `binary-reverse-engineering` |
| 可疑 IP | `ip-analysis` |
| 钓鱼相关 | `phishing-analysis` |

---

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 报告格式规范
- [references/email-providers.md](references/email-providers.md) - 邮箱服务商情报
- [references/platform-metadata.md](references/platform-metadata.md) - 平台元数据提取

## MITRE ATT&CK 技术映射表

邮箱 OSINT 覆盖侦察和初始访问阶段的多种技术。

| 战术 | 技术ID | 技术名称 | OSINT 场景 |
|------|--------|----------|------------|
| **Reconnaissance** | T1589.001 | Credentials | 邮箱作为凭据泄露检测的起点 |
| **Reconnaissance** | T1589.002 | Email Addresses | 通过邮箱收集目标个人信息 |
| **Reconnaissance** | T1590.003 | DNS Records | 邮箱域名 DNS/MX 记录分析 |
| **Reconnaissance** | T1590.005 | Registrant Information | WHOIS 查询邮箱注册人信息 |
| **Reconnaissance** | T1592.004 | Client Configurations | 邮箱客户端指纹分析 |
| **Reconnaissance** | T1593.001 | Code Repositories | GitHub 提交记录中的邮箱关联 |
| **Reconnaissance** | T1594 | Search Victim-Owned Websites | 搜索目标个人/企业网站 |
| **Initial Access** | T1566.001 | Spearphishing Attachment | 目标邮箱用于钓鱼攻击入口 |
| **Initial Access** | T1566.002 | Spearphishing Link | 邮箱中的钓鱼链接分析 |
| **Initial Access** | T1078.004 | Valid Accounts: Cloud Accounts | 邮箱关联的云服务账号 |
| **Credential Access** | T1110.001 | Brute Force: Password Guessing | 邮箱暴力破解检测 |
| **Credential Access** | T1552.001 | Unsecured Credentials: Files | 泄露数据库中的邮箱-密码对 |
| **Discovery** | T1087.001 | Account Discovery: List | 通过邮箱发现关联账号 |
| **Defense Evasion** | T1036.005 | Masquerading: Match Legitimate Name | 仿冒邮箱地址检测 |
| **Command and Control** | T1071.001 | Web Protocols | OSINT 工具的 HTTP API 调用 |

### ATT&CK 缓解措施参考

| Mitigation ID | 名称 | 与邮箱 OSINT 的关系 |
|---------------|------|---------------------|
| M1035 | Data Access Management | 限制邮箱信息在公共平台的暴露 |
| M1056 | Pre-compromise | 邮箱隐私保护措施降低 OSINT 风险 |
| M1018 | Account Management | 邮箱账号生命周期管理 |
| M1027 | Password Policies | 强密码策略防止邮箱凭据泄露 |

---

## OWASP Top 10 + CWE 映射表

| OWASP 2021 | CWE | 与邮箱 OSINT 的关联 |
|-----------|------|---------------------|
| **A01** Broken Access Control | CWE-200 | 信息暴露：邮箱在公开页面中过度暴露 |
| **A02** Cryptographic Failures | CWE-312 | 明文存储邮箱导致泄露 |
| **A04** Insecure Design | CWE-209 | 错误信息中泄露邮箱存在性（holehe 原理） |
| **A05** Security Misconfiguration | CWE-16 | API 未限制邮箱枚举（忘记密码接口） |
| **A07** Auth Failures | CWE-307 | 暴力破解邮箱账号 |
| **A08** Software/Data Integrity | CWE-345 | 邮箱地址可被仿冒（发件人伪造） |
| **A10** SSRF | CWE-918 | 通过邮箱 API SSRF 获取内部信息 |

---

## CVE 参考表（邮箱相关漏洞利用）

| CVE | 漏洞名称 | 与邮箱 OSINT 的关系 |
|-----|----------|---------------------|
| CVE-2021-26855 | Exchange ProxyLogon | 邮箱服务器漏洞导致邮箱数据泄露 |
| CVE-2021-34473 | Exchange ProxyShell | 邮箱服务器 SSRF + RCE |
| CVE-2022-41040 | Exchange NotProxyShell | 邮箱服务器访问控制绕过 |
| CVE-2023-23397 | Outlook Elevation | 特制邮件泄露 NTLM Hash |
| CVE-2024-21413 | Outlook Moniker Link | 邮件预览即可触发 RCE |

---

## Sigma 检测规则

### Sigma 规则 1: 异常邮箱登录行为检测

```yaml
title: Suspicious Email Account Login Pattern
id: 9c3b4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: >
  检测异常的邮箱登录行为，包括陌生地理位置登录、非工作时间登录、
  多次失败后的成功登录。基于邮箱 OSINT 调查中发现的关联账号进行监控。
author: SecSkill Evolution System
references:
  - https://attack.mitre.org/techniques/T1078/004/
  - https://attack.mitre.org/techniques/T1110/001/
tags:
  - attack.initial_access
  - attack.t1078.004
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: email
  service: login
detection:
  unusual_location:
    source_ip_country:
      - '!expected_country'
  off_hours_login:
    login_time:
      start: '23:00'
      end: '06:00'
  brute_force_success:
    failed_attempts: '>=5'
    timeframe: 10m
    success_after_failures: true
  condition: unusual_location or off_hours_login or brute_force_success
falsepositives:
  - 出差/远程办公
  - VPN 连接
  - 时区差异
level: medium
```

### Sigma 规则 2: 邮箱地址枚举行为检测

```yaml
title: Email Enumeration via Password Reset API
type: detect
id: a4c5d6e7-f8a9-4b0c-8d1e-2f3a4b5c6d7e
status: experimental
description: >
  检测通过忘记密码/密码重置接口枚举邮箱地址的行为。
  攻击者利用 API 响应差异判断邮箱是否存在（holehe 原理的防御检测）。
author: SecSkill Evolution System
references:
  - https://attack.mitre.org/techniques/T1589/002/
  - https://attack.mitre.org/techniques/T1110/001/
tags:
  - attack.reconnaissance
  - attack.t1589.002
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: web
  service: api
detection:
  reset_endpoint:
    uri|contains:
      - '/forgot-password'
      - '/reset-password'
      - '/account/recovery'
      - '/api/v1/password/forgot'
  high_frequency:
    timeframe: 5m
    condition: reset_endpoint | count() by source_ip >= 10
  mixed_responses:
    timeframe: 5m
    condition: reset_endpoint | count_distinct(response_status) by source_ip >= 2
  condition: high_frequency or mixed_responses
falsepositives:
  - 用户批量密码重置
  - 自动化测试
  - SSO 服务健康检查
level: medium
```

---

## YARA 规则

### YARA 规则: 邮箱凭据泄露检测

```yara
rule Leaked_Email_Credentials {
  meta:
    description = "检测泄露数据中的邮箱-密码对"
    author = "SecSkill Evolution System"
    date = "2026-06-21"
    reference = "https://attack.mitre.org/techniques/T1552/001/"
  strings:
    // 邮箱:密码 格式
    $email_pass = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[:|;|,|\t][^\s]{4,}/
    // 常见密码模式
    $weak_pass = /(password|123456|qwerty|admin|welcome)/i
    // API 密钥模式
    $api_key = /(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z_-]{35})/
  condition:
    $email_pass and ($weak_pass or $api_key)
}

rule Phishing_Email_Patterns {
  meta:
    description = "检测钓鱼邮件中的社工模式"
    author = "SecSkill Evolution System"
    date = "2026-06-21"
    reference = "https://attack.mitre.org/techniques/T1566/001/"
  strings:
    // 紧迫感词汇
    $urgency = /(urgent|immediate|verify your account|suspended|warning)/i
    // 仿冒域名
    $lookalike = /(arnazon|g00gle|paypa1|microsoft|appleid)/i
    // 钓鱼链接特征
    $phish_url = /(bit\.ly|tinyurl|t\.co|rebrand\.ly)/i
    // 附件危险类型
    $dangerous_ext = /\.(exe|scr|js|vbs|hta|bat|cmd|ps1)$/i
  condition:
    any of ($urgency, $lookalike, $phish_url) and $dangerous_ext
}
```

---

## 合规标准参考表

| 标准 | 相关章节 | 邮箱 OSINT 的角色 |
|------|---------|-------------------|
| **GDPR** | Art.4(1) | 邮箱属于个人数据，调查需合法依据 |
| **GDPR** | Art.6 | 邮箱处理的合法性基础（同意/合法利益） |
| **PIPL** (中国个保法) | 第十三条 | 处理个人信息的合法性要求 |
| **ISO 27001** | A.5.33 | 信息处理设施中的个人信息保护 |
| **ISO 27001** | A.5.12 | 邮箱账号管理安全要求 |
| **NIST SP 800-63B** | 全文 | 数字身份指南中的邮箱作为身份验证 |
| **PCI DSS v4.0** | 8.3 | 强身份验证中的邮箱验证 |
| **等保 2.0** | 第八章 | 个人信息保护中的邮箱数据处理 |

---

## IOC 采集指引

### 高优先级 IOC

| 类型 | 采集方法 | 用途 |
|------|---------|------|
| **关联邮箱** | holehe + blackbird 发现的注册邮箱 | 扩大调查范围 |
| **用户名变体** | 从邮箱提取 + Leet speak 还原 | 跨平台关联 |
| **社交账号** | blackbird + 平台 API | 目标画像构建 |
| **手机号** | 平台元数据提取（如 Telegram） | 多维度身份验证 |
| **地理信息** | 平台元数据 + 邮箱服务商 | 目标定位 |

### 中优先级 IOC

| 类型 | 采集方法 | 用途 |
|------|---------|------|
| **头像 URL** | Gravatar + 社交平台 | 目标识别 |
| **GitHub 仓库** | GitHub API | 技术能力评估 |
| **注册时间** | 平台 API | 活动时间线 |
| **IP 地址** | 登录日志 + 平台元数据 | 地理定位 |
| **设备信息** | 平台元数据 | 设备指纹 |

### IOC 安全标记

- `defanged` — 邮箱使用 [at] 消毒标记
- `TLP:CLEAR` — 可自由分享
- `TLP:AMBER` — 仅限受信任方
- `TLP:RED` — 仅限接收方

---

## 跨技能工作流

### 工作流 1: 钓鱼攻击溯源
```
钓鱼邮件 → phishing-analysis → email-osint (发件人调查)
     ↓                              ↓
  url-analysis              domain-analysis → ip-analysis
                                  ↓
                            ttp-extractor → pdf-report
```

### 工作流 2: 人物情报全链路
```
目标邮箱 → email-osint (邮箱+用户名搜索)
     ↓
     ├→ redteam-recon-person (个人画像)
     ├→ redteam-recon-enterprise (企业侦察)
     ├→ brand-impersonation (品牌仿冒检测)
     └→ ttp-extractor → pdf-report
```

### 工作流 3: 凭据泄露调查
```
泄露数据库 → email-osint (邮箱搜索)
     ↓
     ├→ auth-log-analysis (异常登录检测)
     ├→ asset-discovery (关联资产)
     └→ traffic-analysis (C2 流量关联)
