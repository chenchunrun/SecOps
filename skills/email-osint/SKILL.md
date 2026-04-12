---
name: email-osint
description: 邮箱情报调查与关联分析。当用户要求"邮箱调查"、"邮箱搜索"、"查邮箱"、"邮箱关联"、"社交账号发现"、"用户名搜索"、"数字足迹"、"OSINT调查"、"人肉搜索"时使用此技能。
metadata:
  version: 1.2.0
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
