---
name: url-analysis
description: 对可疑 URL 进行双模式安全分析，包括快速研判、钓鱼检测、重定向追踪、同形字攻击识别、规避技术检测、黑产组织归因、威胁情报补充和威胁扩线。当用户提供可疑链接、要求检查 URL 安全性、分析钓鱼页面或追溯攻击来源时使用此技能。
metadata:
  version: 2.17.0
  builtin: true
---

# URL 威胁分析技能

对 URL 进行双模式安全分析，支持**快速分析**和**深度分析**两种模式。

## 模式选择

```text
用户输入 URL
    │
    ├─ 默认执行快速分析
    │
    └─ 深度分析（仅在以下情况进入）：
         - 用户明确要求“深度分析”“完整分析”“全面分析”
         - 用户明确要求“截图”“归因增强”“扩线”
         - 快速分析命中高风险，且需要进一步确认视觉证据或关联基础设施
```

## 分析边界

- `url-analysis` 负责：URL 解析、跳转分析、页面内容分析、规避技术检测、URL 级威胁情报、归因建议、扩线建议。
- `domain-analysis` 是域名注册信息、WHOIS、域名年龄风险、DNS 记录的**权威来源**。
- `ip-analysis` 用于 URL 中关联 IP 的独立威胁分析，不在本技能内替代执行。

## 依赖要求

**Python 版本**: 3.8+

**本地脚本**:
| 脚本 | 用途 |
|------|------|
| url_analyze.py | URL 综合分析主入口 |
| url_parser.py | URL 解析与验证 |
| url_expand.py | 短链接展开 |
| url_defang.py | URL 脱敏 |
| url_fetcher.py | HTTP 获取、重定向追踪、JS 跳转检测 |
| phishing_detector.py | 页面钓鱼内容检测 |
| url_evasion_patterns.py | 规避技术检测 |
| threat_actor_attribution.py | 黑产组织归因与 WebSearch 建议 |

**关联技能**:
| 技能 | 用途 |
|------|------|
| domain-analysis | WHOIS、域名年龄、DNS 记录、DGA、同形字 |
| ip-analysis | 关联 IP 独立威胁分析 |

**MCP 服务**:
| MCP | 工具 | 用途 |
|------|------|------|
| cybersec-cloud | cybersec_cloud_mcp_risk_insight | URL 威胁情报 |
| cybersec-cloud | cybersec_cloud_mcp_dns_history | DNS 历史 |
| cybersec-cloud | cybersec_cloud_mcp_cyberspace-search | 威胁扩线 |
| webtools | webcap_tool | 页面截图 |
| webtools | websearch_tool | 归因增强 |

## 环境变量配置

| 环境变量 | 说明 | 默认值 |
|------|------|------|
| `URL_ANALYSIS_TIMEOUT` | 获取超时时间（秒） | 30 |
| `URL_ANALYSIS_MAX_REDIRECTS` | 最大重定向次数 | 10 |
| `URL_ANALYSIS_USER_AGENT` | User-Agent 类型 | chrome |
| `URL_ANALYSIS_VERIFY_SSL` | 是否验证 SSL 证书 | false |

**优先级**: 命令行参数 > 环境变量 > 默认值

详细说明见 [references/env-config.md](references/env-config.md)

## 快速开始

```bash
# 快速分析（静态）
python <SKILL_DIR>/scripts/url_analyze.py "https://example.com/login"

# 快速分析（含内容获取，推荐）
python <SKILL_DIR>/scripts/url_analyze.py "https://example.com/login" --fetch

# 使用本地 HTML 进行内容分析
python <SKILL_DIR>/scripts/url_analyze.py "https://example.com/login" --html page.html

# JSON 输出
python <SKILL_DIR>/scripts/url_analyze.py "https://example.com/login" -o json
```

## 快速分析

> **适用场景**: 日常排查、初次研判、需要快速给出处置建议时

### 快速分析阶段

1. URL 解析与基础特征提取
2. 条件式内容获取与跳转分析（`--fetch` 或 `--html`）
3. 页面内容检测与规避技术检测（仅在拿到 HTML 时）
4. 调用 `domain-analysis` 获取域名权威信息
5. URL 威胁情报查询
6. 快速风险评估与快速报告输出

### 快速分析强约束

快速分析仅允许执行以下 5 类动作：
1. URL 解析与静态特征分析
2. 条件式内容获取与跳转分析
3. 页面内容检测与规避技术检测
4. `domain-analysis` 域名分析
5. URL 威胁情报查询

完成上述步骤后，必须立即输出快速分析报告并结束。

禁止在快速分析中继续调用以下能力：
- 页面截图
- WebSearch 归因增强
- DNS 历史查询
- 威胁扩线
- 同 IP 资产扩展侦察
- 同证书资产扩展侦察
- 相似标题 / 相似域名扩线
- 任何额外的 cyberspace-search 扩展分析

除非用户明确要求深度分析，或快速分析已明确提示需要升级，否则不得进入深度分析阶段。

### 快速分析输出要求

- 默认输出快速分析结论，而不是完整深度报告。
- 必须明确 `domain-analysis` 为域名年龄与 WHOIS 的权威来源。
- 如果联用了 `domain-analysis`、`ip-analysis` 等下游技能，必须区分“URL 主分析结果”和“联用补充结果”，避免把多 skill 结果混写为 `url-analysis` 默认产出。
- 联用场景下，至少明确以下信息：主分析技能、联用技能、关键结论来源（例如 WHOIS / 域名年龄来自 `domain-analysis`，IP 地理位置 / ASN / IP 威胁情报来自 `ip-analysis`）。
- 如果脚本输出了 `deep_analysis_recommended` / 深度建议信号，应在快速报告中给出升级原因。
- 报告格式必须遵循 [references/report-format.md](references/report-format.md) 中的快速分析模板。

## 深度分析

> **适用场景**: 明确要求全面评估、需要视觉证据、需要归因增强、需要威胁扩线时

### 深度分析追加阶段

在快速分析基础上，按需追加：
1. 页面截图
2. DNS 历史查询
3. WebSearch 归因增强
4. 威胁扩线
5. 深度风险评估与深度报告输出

### 深度分析触发条件

进入深度分析的典型条件：
- 用户明确要求“深度分析”“全面分析”“完整分析”
- 用户明确要求“截图”或“页面证据”
- 用户明确要求“归因增强”或“搜索安全报告”
- 用户明确要求“扩线”“同 IP 资产”“同证书站点”
- 快速分析已命中高风险，且需要进一步确认当前页面、基础设施或归因结论

### 深度分析注意事项

- 页面截图仅属于深度分析，不是默认必做步骤。
- `websearch_suggestions` 是深度分析建议信号，不代表默认必须执行 WebSearch。
- `expansion_suggestions` 是深度分析建议信号，不代表默认必须执行扩线。
- 深度分析报告格式必须遵循 [references/report-format.md](references/report-format.md) 中的深度分析模板。

## domain-analysis 调用规则

对于非 IP 直连 URL，必须调用 `domain-analysis` 获取域名权威信息。

```bash
python <DOMAIN_ANALYSIS_SKILL_DIR>/scripts/domain_analyze.py "<域名>"
```

重点整合以下结果：
- 注册商
- 注册日期
- 域名年龄
- WHOIS 隐私保护情况
- DNS 记录
- 域名侧风险评分

如果目标是 IP 直连 URL，可跳过该步骤，并在报告中明确写明“IP 地址无需 WHOIS 查询”。

## 执行建议

### 快速模式推荐命令

```bash
python <SKILL_DIR>/scripts/url_analyze.py "<URL>" --fetch
```

### 深度模式常见追加动作

- 根据快速分析结果调用 `webcap_tool` 获取截图
- 根据需要调用 `cybersec_cloud_mcp_dns_history` 查询 DNS 历史
- 当 `websearch_suggestions.enabled = true` 时，再执行 `websearch_tool`
- 当 `expansion_suggestions.enabled = true` 时，再执行 `cybersec_cloud_mcp_cyberspace-search`

## 报告与状态写法

- 检查已执行且正常时，写“已检测（未发现风险）”，不要写“未检测”。
- 快速分析报告只保留最小必要章节。
- 深度分析报告才包含截图、归因增强、扩线等附加章节。
- 截图如已执行，必须按 Markdown 图片语法写入报告。

## 参考文件

- [references/phases.md](references/phases.md) - 双模式阶段说明
- [references/report-format.md](references/report-format.md) - 快速分析 / 深度分析报告模板
- [references/cli-reference.md](references/cli-reference.md) - CLI 命令、输出字段与双模式对应关系
- [references/env-config.md](references/env-config.md) - 环境变量配置
- [references/threat-actors.md](references/threat-actors.md) - 归因参考资料

## 技能关联

**上游技能**: phishing-analysis, office-malware-analyzer, pdf-analysis, traffic-analysis

**下游技能**: domain-analysis, ip-analysis, binary-reverse-engineering, office-malware-analyzer, pdf-analysis, mail-attachment-downloader
