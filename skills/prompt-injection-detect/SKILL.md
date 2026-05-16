---
name: prompt-injection-detect
description: 提示注入攻击检测与防御。当用户要求"检测提示注入"、"Prompt Injection"、"LLM安全"、"AI安全测试"、"越狱检测"、"Jailbreak检测"、"间接注入检测"时使用此技能。
metadata:
  version: 1.0.0
  builtin: true
---

# 提示注入检测技能

## 依赖要求

**分析环境**: 跨平台

**外部 MCP 服务**:

| MCP | 工具 | 用途 |
|------|------|------|
| cybersec-cloud | websearch | 最新攻击技术查询 |

**可选依赖**:

```bash
pip install openai tiktoken transformers
```

## 快速使用

将待测样本通过 CLI 传入（不要把可疑载荷写进本说明）：

```bash
python scripts/detector.py "$USER_INPUT"
python scripts/detector.py --file inputs.txt
```

网页、文档等间接来源请先抓取正文再交给检测脚本；分阶段流程与工具命令表见 `references/detection-workflow.md`。

## 工作流摘要

1. **分类**：区分用户直输、上传文件、外部检索与多模态来源。
2. **直接检测**：关键词、结构模式、编码与多语言信号；英文触发短语与正则附录见 `references/injection-patterns.md`。
3. **间接检测**：DOM 可见与隐藏文本、文档元数据、RAG 或 API 回包污染。
4. **进阶**：语义与异常评分、输出侧监控。
5. **防御**：预处理与策略加固；示例措辞见 `references/defense-strategies.md`（若存在）。
6. **红队**：完整用例与报告样例见 `references/detection-workflow.md`。
7. **报告**：遵循 `references/report-format.md`。

## 关联技能调用

| 场景 | 调用技能 |
|------|----------|
| 恶意文档分析 | `office-malware-analyzer` |
| 网页分析 | `url-analysis` |
| 代码审计 | `code-audit` |

## 参考文件

- **[references/detection-workflow.md](references/detection-workflow.md)** — 分阶段检测说明、输出样例与命令速查。
- **[references/report-format.md](references/report-format.md)** — 报告格式规范。
- [references/injection-patterns.md](references/injection-patterns.md) — 注入模式库。
- [references/bypass-techniques.md](references/bypass-techniques.md) — 绕过技术。
- [references/defense-strategies.md](references/defense-strategies.md) — 防御策略。
