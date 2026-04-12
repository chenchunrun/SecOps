---
name: researching-vulnerabilities
description: 漏洞情报与影响评估。当用户提供 CVE 编号、漏洞名称，询问"这个漏洞对我有影响吗"、"有没有 PoC"、"是否在野利用"时使用此技能。
metadata:
  version: 2.0.0
  builtin: true
---

# 漏洞情报与影响评估

从漏洞编号出发，收集威胁情报、评估 Exploit 状态、结合资产测绘判断实际影响，输出处置建议。

## 核心定位

```
用户输入: CVE-XXXX / 漏洞名称 / 受影响产品
           │
           ├─► 威胁情报: 在野利用？勒索软件整合？
           │
           ├─► Exploit状态: 公开PoC？利用难度？
           │
           ├─► 资产影响: 我的资产受影响吗？(测绘关联)
           │
           └─► 处置建议: 优先级 + 缓解措施
```

**不是**: 简单的漏洞查询工具
**而是**: 漏洞情报驱动的影响评估

---

## 工作流

```
Phase 1: 漏洞信息确认
    │
Phase 2: 威胁情报收集 (WebSearch)
    │
Phase 3: Exploit 状态评估
    │
Phase 4: 资产影响评估 (cybersec_cloud_mcp_cyberspace-search)
    │
Phase 5: 风险评估与处置建议
```

---

## Phase 1: 漏洞信息确认

### 1.1 输入解析

| 输入类型 | 示例 | 处理 |
|----------|------|------|
| CVE 编号 | CVE-2024-21762 | 直接使用 |
| 漏洞名称 | Log4Shell | 转换为 CVE-2021-44228 |
| 产品+版本 | FortiOS 7.4.2 | 查询相关 CVE |

### 1.2 确认基础信息

向用户确认或通过搜索获取：

| 字段 | 必需 | 说明 |
|------|------|------|
| CVE 编号 | ✓ | 唯一标识 |
| 受影响产品 | ✓ | 产品名称 |
| 影响版本 | ✓ | 版本范围 |
| 用户资产范围 | 推荐 | 域名/IP/组织名 |

### 1.3 快速 CVSS 获取

```
WebSearch: "CVE-XXXX" CVSS site:nvd.nist.gov
```

---

## Phase 2: 威胁情报收集

**目标**: 判断漏洞的真实威胁程度

### 2.1 在野利用检查 (ITW - In The Wild)

```
WebSearch: "CVE-XXXX" (exploit OR attack OR "in the wild" OR 攻击 OR 利用)
```

关注点：
- 是否有真实攻击事件报道
- 哪些攻击组织在使用
- 攻击目标行业/地区

### 2.2 CISA KEV 检查

```
WebSearch: "CVE-XXXX" site:cisa.gov/known-exploited-vulnerabilities
```

| KEV 状态 | 含义 | 优先级 |
|----------|------|--------|
| ✅ 命中 | 美国政府确认在野利用 | P0 紧急 |
| ❌ 未命中 | 不代表安全 | 继续评估 |

### 2.3 勒索软件整合检查

```
WebSearch: "CVE-XXXX" (ransomware OR 勒索 OR LockBit OR BlackCat OR Conti)
```

**勒索软件整合 = P0 紧急**

### 2.4 APT 关联检查

```
WebSearch: "CVE-XXXX" (APT OR "threat actor" OR 攻击组织)
```

### 2.5 情报汇总表

| 维度 | 状态 | 来源 |
|------|------|------|
| 在野利用 | ✅/❌ | [来源链接] |
| CISA KEV | ✅/❌ | CISA |
| 勒索软件 | ✅/❌ | [来源] |
| APT 关联 | ✅/❌ | [来源] |

---

## Phase 3: Exploit 状态评估

**目标**: 判断利用门槛和公开程度

### 3.1 GitHub PoC 搜索

```
WebSearch: "CVE-XXXX" PoC site:github.com
```

评估维度：
- Star 数量 (流行度)
- 发布时间 (时效性)
- 是否可直接利用

### 3.2 Exploit-DB 检查

```
WebSearch: "CVE-XXXX" site:exploit-db.com
```

### 3.3 Nuclei 模板检查

```
WebSearch: "CVE-XXXX" site:github.com/projectdiscovery/nuclei-templates
```

有 Nuclei 模板 = 可批量扫描 = 风险升高

### 3.4 Metasploit 模块检查

```
WebSearch: "CVE-XXXX" site:rapid7.com/db
```

### 3.5 利用难度评估

| 因素 | 低门槛 🔴 | 高门槛 🟢 |
|------|----------|----------|
| 认证要求 | 无需认证 | 需高权限 |
| 交互要求 | 无需交互 | 需用户点击 |
| 利用稳定性 | 稳定可靠 | 概率性/易崩溃 |
| 工具化程度 | 一键利用 | 需手工调试 |

### 3.6 Exploit 汇总表

| 来源 | 状态 | 链接 | 备注 |
|------|------|------|------|
| GitHub PoC | ✅/❌ | [链接] | Star数/可用性 |
| Exploit-DB | ✅/❌ | [链接] | |
| Nuclei | ✅/❌ | [链接] | 可批量扫描 |
| Metasploit | ✅/❌ | [链接] | |

---

## Phase 4: 资产影响评估 ⭐

**目标**: 判断用户资产是否实际受影响

### 4.1 构建测绘查询

根据漏洞影响产品，构建 `cybersec_cloud_mcp_cyberspace-search` 查询语法：

| 漏洞产品 | 测绘语法示例 |
|----------|-------------|
| FortiOS | `app="Fortinet-FortiGate" && port="443"` |
| Apache Log4j | `app="Apache-Log4j"` |
| Confluence | `app="Atlassian-Confluence"` |
| Exchange | `app="Microsoft-Exchange"` |

### 4.2 限定用户资产范围

如果用户提供了资产范围：

```
# 按组织
app="FortiGate" && org="用户公司名"

# 按域名
app="FortiGate" && domain="example.com"

# 按 IP 段
app="FortiGate" && ip="192.168.1.0/24"
```

### 4.3 调用测绘技能

```
建议调用: cybersec_cloud_mcp_cyberspace-search
查询语法: [构建的语法]
目的: 统计受影响资产数量
```

### 4.4 资产影响汇总

| 项目 | 结果 |
|------|------|
| 测绘查询 | `[语法]` |
| 发现资产 | X 台 |
| 暴露端口 | 443, 8443 |
| 影响判定 | ✅ 受影响 / ❌ 未发现 |

---

## Phase 5: 风险评估与处置

### 5.1 综合风险评分

| 因素 | 权重 | 状态 | 得分 |
|------|------|------|------|
| CVSS 基础分 | 基础 | X.X | - |
| 在野利用 | +3 | ✅/❌ | |
| 公开 Exploit | +2 | ✅/❌ | |
| 资产暴露 | +2 | ✅/❌ | |
| 勒索软件整合 | +3 | ✅/❌ | |

### 5.2 优先级判定

| 优先级 | 条件 | SLA |
|--------|------|-----|
| **P0 紧急** | 在野利用 OR 勒索软件 OR (CVSS≥9 + PoC + 资产暴露) | 24h |
| **P1 高危** | CVSS≥9 OR (CVSS≥7 + PoC) | 72h |
| **P2 中危** | CVSS 7-8.9 无PoC OR (CVSS 4-6.9 + PoC) | 1周 |
| **P3 低危** | CVSS<7 无PoC 无暴露 | 计划内 |

### 5.3 处置建议

```markdown
## 立即行动 (P0/P1)
1. [ ] 隔离受影响资产
2. [ ] 应用临时缓解措施
3. [ ] 通知相关团队

## 修复措施
- 升级版本: X.X.X → Y.Y.Y
- 补丁链接: [厂商公告]
- 缓解措施: [临时方案]

## 验证方法
- 版本检查命令
- 漏洞扫描验证
```

---

## 报告模板

详见 [references/report-format.md](references/report-format.md)

---

## 关联技能

### 本技能调用

| 阶段 | 调用技能 | 用途 |
|------|----------|------|
| Phase 4 | `cybersec_cloud_mcp_cyberspace-search` | 资产测绘查询 |
| Phase 4 | `asset-discovery` | 获取用户资产范围 |
| 后续 | `sca-analyzer` | 代码依赖漏洞检查 |

### 输入来源

| 来源技能 | 场景 |
|----------|------|
| `phishing-analysis` | 钓鱼邮件利用的漏洞 |
| `traffic-analysis` | 流量中发现的漏洞利用 |
| `windows-ir` | 应急响应中发现的漏洞 |

---

## 示例

**输入**: "CVE-2024-21762 对我们有影响吗？我们用 FortiGate"

**输出**:

```markdown
# CVE-2024-21762 影响评估报告

**漏洞**: FortiOS 越界写入导致 RCE
**CVSS**: 9.8 Critical

## 威胁情报
| 维度 | 状态 | 说明 |
|------|------|------|
| 在野利用 | ✅ | 2024-02 多起攻击事件 |
| CISA KEV | ✅ | 2024-02-09 加入 |
| 勒索软件 | ⚠️ | 未确认但高风险 |

## Exploit 状态
| 来源 | 状态 |
|------|------|
| GitHub PoC | ✅ 多个可用 |
| Nuclei | ✅ 有模板 |

## 资产影响
- 测绘查询: `app="Fortinet-FortiGate" && org="YourCompany"`
- 发现资产: **3 台**
- 暴露端口: 443, 10443

## 风险评估
**优先级: P0 紧急** (在野利用 + 资产暴露)

## 处置建议
1. **立即**: 限制管理接口访问
2. **24h内**: 升级到 7.4.3 / 7.2.7 / 7.0.14
3. **验证**: `get system status` 检查版本
```

---

## 参考文件

- [references/report-format.md](references/report-format.md) - 报告模板
- [references/product-fingerprints.md](references/product-fingerprints.md) - 产品测绘指纹

---

## AI 建议

- 发现漏洞影响特定产品时，建议调用 `cybersec_cloud_mcp_cyberspace-search` 进行资产测绘
- 发现漏洞涉及开源组件时，建议调用 `sca-analyzer` 检查代码依赖
