---
name: redteam-intrusion-social
description: 社工钓鱼作战。社会工程学攻击策划和钓鱼内容构造。当用户要求"钓鱼攻击"、"社工攻击"、"钓鱼邮件"、"BEC攻击"、"钓鱼页面"、"社会工程"时使用此技能。仅限授权红队测试使用。
metadata:
  version: 1.0.0
  builtin: true
  category: redteam-intrusion
---

> ⚠️ **RED TEAM AUTHORIZATION REQUIRED**
>
> This skill falls under the `redteam:execute` capability gate.
>
> **Before executing ANY step in this skill, you MUST:**
> 1. State the skill name and a one-line summary of what you are about to do.
> 2. Ask the user to explicitly confirm authorization by typing **"已授权 / AUTHORIZED"**.
> 3. Ask the user to confirm the authorized scope (target, timeframe, rules of engagement).
> 4. Record the confirmation in your response before proceeding.
>
> **Do NOT proceed if:**
> - The user has not typed the authorization confirmation.
> - The target is outside the stated scope.
> - Any step would cause irreversible changes without a rollback plan.
>
> Violation of this gate is logged as a `security_alert` audit event.

---



# 社工钓鱼作战

社会工程学攻击策划和钓鱼内容构造，用于授权红队演练。

## 适用场景

**仅限授权测试**:
- 企业钓鱼演练
- 安全意识测试
- 红队社工攻击
- 安全培训素材

## 攻击类型

### 1. 钓鱼邮件

| 类型 | 目标 | 成功率 |
|------|------|-------|
| 鱼叉式钓鱼 | 特定个人 | 高 |
| BEC攻击 | 财务人员 | 高 |
| 凭证收割 | 全员 | 中 |
| 恶意附件 | 技术人员 | 中 |

### 2. 语音钓鱼 (Vishing)

| 场景 | 话术要点 |
|------|---------|
| IT支持 | "您的账号需要验证" |
| 供应商 | "发票需要确认" |
| 高管助理 | "紧急会议变更" |

### 3. 短信钓鱼 (Smishing)

| 场景 | 诱导方式 |
|------|---------|
| 快递通知 | "包裹无法投递" |
| 银行警告 | "异常交易提醒" |
| 验证码 | "您的验证码是..." |

## 心理学原则

### 西奥迪尼六原则

| 原则 | 应用 | 示例 |
|------|------|------|
| 互惠 | 先给予再请求 | "免费资源分享" |
| 承诺一致 | 小请求升级 | "先看一下这个" |
| 社会认同 | 他人也在做 | "其他同事已完成" |
| 喜好 | 建立好感 | 共同兴趣话题 |
| 权威 | 冒充权威 | "IT部门通知" |
| 稀缺 | 制造紧迫 | "限时24小时" |

## 钓鱼邮件构造

### 邮件模板框架

```
发件人: [可信发件人]
主题: [引起注意的主题]

[称呼]

[背景说明 - 建立合理性]

[行动要求 - 明确指令]

[紧迫性 - 时间压力]

[签名 - 增强可信度]
```

### 高效主题示例

| 场景 | 主题 |
|------|------|
| IT安全 | "【紧急】您的账号将在24小时后停用" |
| 人事 | "年度绩效评估结果已发布" |
| 财务 | "报销审批：您提交的费用需要补充材料" |
| 合规 | "合规培训未完成提醒" |
| 高管 | "CEO分享：Q4战略调整" |

### 恶意附件策略

| 文件类型 | 伪装 | 触发方式 |
|---------|------|---------|
| Office宏 | 发票.xlsm | 启用宏 |
| PDF | 合同.pdf | 打开即执行 |
| LNK | 资料.lnk | 双击打开 |
| ISO/IMG | 工具包.iso | 挂载打开 |

## 钓鱼页面设计

### 设计原则

1. **高度仿真** - 与真实页面一致
2. **SSL证书** - 必须有HTTPS
3. **相似域名** - typosquatting
4. **移动适配** - 响应式设计

### 域名策略

| 技术 | 示例 | 说明 |
|------|------|------|
| 同形字 | examp1e.com | 数字替代 |
| 拼写变体 | exampel.com | 常见拼写错误 |
| 子域名 | login.example.fake.com | 利用子域名 |
| 顶级域 | example.co | 不同TLD |

### 页面类型

| 类型 | 目标 | 收集信息 |
|------|------|---------|
| 登录页面 | 凭证 | 用户名+密码 |
| OAuth | Token | 授权码 |
| 表单 | 信息 | 个人/公司信息 |
| 下载页 | 载荷 | 诱导下载 |

## 技术实现

### 发信基础设施

```bash
# 域名配置
# 1. 注册相似域名
# 2. 配置SPF记录
v=spf1 include:_spf.domain.com ~all

# 3. 配置DKIM
# 4. 配置DMARC
v=DMARC1; p=none; rua=mailto:dmarc@domain.com
```

### 钓鱼平台

| 工具 | 用途 | 特点 |
|------|------|------|
| Gophish | 邮件钓鱼 | 开源、全功能 |
| Evilginx2 | 中间人钓鱼 | 绕过2FA |
| SocialFish | 社交钓鱼 | 简单易用 |
| King Phisher | 企业级 | 完整报告 |

### GoPhish配置示例

```bash
# 启动GoPhish
./gophish

# 访问管理界面
https://localhost:3333

# 配置步骤:
# 1. 创建发送配置 (Sending Profile)
# 2. 创建邮件模板 (Email Template)
# 3. 创建钓鱼页面 (Landing Page)
# 4. 创建目标组 (Users & Groups)
# 5. 启动活动 (Campaign)
```

## 规避技术

### 邮件网关绕过

| 检测 | 绕过方法 |
|------|---------|
| SPF检查 | 配置正确的SPF |
| 链接扫描 | 使用重定向 |
| 附件扫描 | 密码保护ZIP |
| 内容检测 | 图片替代文字 |

### 安全软件规避

| 检测 | 绕过方法 |
|------|---------|
| 沙箱分析 | 延迟执行 |
| 行为检测 | 用户交互触发 |
| 签名检测 | 混淆处理 |

## 输出规范

### 社工作战计划

```markdown
# 社工作战计划

## 目标概况
- 目标组织: [组织名]
- 目标人员: [人数/角色]
- 演练目标: 凭证收割 / 载荷投递

## 场景设计
- 伪装身份: [IT支持/供应商等]
- 钓鱼主题: [主题]
- 紧迫因素: [时间限制]

## 技术方案
- 发信域名: [域名]
- 钓鱼页面: [URL]
- 载荷类型: [如有]

## 邮件模板
[完整邮件内容]

## 时间计划
- 发送时间: [选择高响应时段]
- 持续时间: [活动周期]

## 成功指标
- 打开率目标: X%
- 点击率目标: X%
- 凭证收割目标: X%
```

## 法律边界

**必须遵守**:
- 书面授权
- 范围限定
- 数据保护
- 及时报告

**禁止行为**:
- 超出授权范围
- 保留敏感凭证
- 对外部目标攻击
- 造成实际损害

## 与其他技能的关联

| 场景 | 调用技能 | 说明 |
|------|---------|------|
| 目标画像 | `/redteam-recon-person` | 个人情报 |
| 载荷制作 | `/redteam-lateral-evasion` | 免杀处理 |
| 邮件分析 | `/phishing-analysis` | 反向验证 |