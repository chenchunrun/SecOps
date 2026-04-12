# 命令行参考

本文档说明 `url-analysis` 的命令、输出字段与双模式语义。

## 目录

- [工具命令速查](#工具命令速查)
- [模式与命令对应关系](#模式与命令对应关系)
- [命令行参数详解](#命令行参数详解)
- [脚本输出字段说明](#脚本输出字段说明)
- [双模式检查清单](#双模式检查清单)

---

## 工具命令速查

| 任务 | 命令 |
|------|------|
| 快速分析（静态） | `python <SKILL_DIR>/scripts/url_analyze.py "<URL>"` |
| 快速分析（含内容获取，推荐） | `python <SKILL_DIR>/scripts/url_analyze.py "<URL>" --fetch` |
| 使用本地 HTML 分析 | `python <SKILL_DIR>/scripts/url_analyze.py "<URL>" --html page.html` |
| JSON 输出 | `python <SKILL_DIR>/scripts/url_analyze.py "<URL>" -o json` |
| 解析 URL | `python <SKILL_DIR>/scripts/url_parser.py "<URL>"` |
| 展开短链接 | `python <SKILL_DIR>/scripts/url_expand.py "<URL>"` |
| URL 脱敏 | `python <SKILL_DIR>/scripts/url_defang.py "<URL>"` |

---

## 模式与命令对应关系

| 命令 / 输出 | 模式语义 |
|-------------|----------|
| `url_analyze.py <URL>` | 默认快速分析，不自动进入深度分析 |
| `url_analyze.py <URL> --fetch` | 仍属于快速分析，只是补充内容获取与跳转分析 |
| `url_analyze.py <URL> --html page.html` | 仍属于快速分析，只是基于已有 HTML 做内容检测 |
| `websearch_suggestions.enabled = true` | 表示建议在深度分析中执行 WebSearch，不代表默认必做 |
| `expansion_suggestions.enabled = true` | 表示建议在深度分析中执行扩线，不代表默认必做 |
| `deep_analysis_recommended = true` | 明确表示快速分析建议升级 |

**重要**：
- `--fetch` 不是深度分析开关。
- 脚本本身只产出快速分析核心结果和深度分析建议信号。
- 页面截图、DNS 历史、WebSearch、威胁扩线属于深度分析追加动作。

---

## 命令行参数详解

```text
url_analyze.py [URL] [OPTIONS]

位置参数:
  url                        要分析的 URL

选项:
  -f, --file FILE            从文件读取 URL 列表
  -o, --output {text,json}   输出格式（默认: text）
  --fetch                    自动获取 URL 内容并分析
  --html FILE                指定 HTML 文件进行内容检测
  --follow                   追踪重定向
  --timeout SECONDS          获取超时时间（默认: 30，可通过环境变量覆盖）
```

**环境变量优先级**：命令行参数 > 环境变量 > 默认值

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `URL_ANALYSIS_TIMEOUT` | HTTP 获取超时时间（秒） | 30 |
| `URL_ANALYSIS_MAX_REDIRECTS` | 最大重定向次数 | 10 |
| `URL_ANALYSIS_USER_AGENT` | User-Agent 类型 | chrome |
| `URL_ANALYSIS_VERIFY_SSL` | 是否验证 SSL | false |

---

## 脚本输出字段说明

### 快速分析核心结果

以下字段用于支撑快速分析结论：

| 字段 | 说明 |
|------|------|
| `components` | URL 组件解析结果 |
| `defanged_url` | 脱敏 URL |
| `fetch_info` | 内容获取结果 |
| `redirect_chain` | 跳转链 |
| `redirect_chain_analysis` | 跳转链风险分析 |
| `phishing_detection` | 钓鱼内容检测结果 |
| `evasion_analysis` | 规避技术检测结果 |
| `attribution` | 初步规则归因结果 |
| `risk_score` | 风险分数 |
| `risk_level` | 风险等级 |
| `risk_factors` | 风险因子列表 |
| `recommendations` | 处置建议 |

### 深度分析建议信号

以下字段不表示已经执行深度分析，只表示“适合升级”：

| 字段 | 说明 |
|------|------|
| `deep_analysis_recommended` | 是否建议升级深度分析 |
| `deep_analysis_reasons` | 建议升级原因列表 |
| `websearch_suggestions` | WebSearch 归因增强建议 |
| `expansion_suggestions` | 威胁扩线建议 |

### `domain-analysis` 权威来源说明

对于非 IP 直连 URL，脚本会提示必须调用：

```bash
python <DOMAIN_ANALYSIS_SKILL_DIR>/scripts/domain_analyze.py "<域名>"
```

`url-analysis` 不负责替代输出：
- 域名 WHOIS
- 域名年龄
- 域名侧 DNS 权威信息

这些结果必须从 `domain-analysis` 获取并整合到最终报告。

---

## 双模式检查清单

### 快速模式最小检查项

在输出快速分析报告之前，必须确认：

- [ ] URL 解析已完成
- [ ] 静态特征分析已完成
- [ ] 若使用 `--fetch` / `--html`，则内容检测与跳转分析已完成
- [ ] 对非 IP URL 已提示调用 `domain-analysis`
- [ ] URL 威胁情报已查询或已明确标记待查询
- [ ] 已输出 `risk_score`、`risk_level`
- [ ] 已输出 `deep_analysis_recommended` 与升级原因（如适用）

### 深度模式完整检查项

只有在用户明确要求深度分析，或快速分析明确建议升级时，才继续检查：

- [ ] 页面截图已获取并按 `![描述](URL)` 写入报告
- [ ] DNS 历史已查询（如需要）
- [ ] 已根据 `websearch_suggestions` 执行 WebSearch（如需要）
- [ ] 已根据 `expansion_suggestions` 执行威胁扩线（如需要）
- [ ] 深度报告已明确哪些动作是本次追加执行的

---

## 常见错误（避免）

| 错误行为 | 正确做法 |
|----------|----------|
| 只要 `websearch_suggestions.enabled = true` 就立刻执行 WebSearch | 先输出快速分析，再把它作为深度分析建议 |
| 只要 `expansion_suggestions.enabled = true` 就立刻扩线 | 先输出快速分析，再由用户要求或升级场景触发 |
| 把 `--fetch` 当成深度分析 | `--fetch` 仍属于快速分析增强 |
| 省略 `domain-analysis` | 非 IP URL 必须调用 `domain-analysis` 获取域名年龄 / WHOIS |
| 报告中把“未执行”写成“未发现风险” | 必须准确区分“未执行”和“已检测（未发现风险）” |
