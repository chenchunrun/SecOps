# 环境变量配置

脚本支持通过环境变量配置默认参数，便于在不同环境中灵活调整。

## 配置项

| 环境变量 | 说明 | 默认值 | 类型 |
|---------|------|--------|------|
| `URL_ANALYSIS_TIMEOUT` | HTTP 请求超时时间（秒） | 30 | 整数 |
| `URL_ANALYSIS_MAX_REDIRECTS` | 最大重定向次数 | 10 | 整数 |
| `URL_ANALYSIS_USER_AGENT` | User-Agent 类型 | chrome | 字符串 |
| `URL_ANALYSIS_VERIFY_SSL` | 是否验证 SSL 证书 | false | 布尔值 |

## User-Agent 可选值

- `chrome` - Chrome 浏览器（默认）
- `firefox` - Firefox 浏览器
- `safari` - Safari 浏览器
- `googlebot` - Google 爬虫
- `curl` - curl 命令行工具

## 优先级

```
命令行参数 > 环境变量 > 默认值
```

## 使用场景

### 场景 1: 分析响应较慢的网站

```bash
export URL_ANALYSIS_TIMEOUT=60
python scripts/url_analyze.py "http://slow-site.com" --fetch
```

### 场景 2: 命令行临时覆盖

```bash
# 环境变量设为 30，但命令行指定 10，最终使用 10
export URL_ANALYSIS_TIMEOUT=30
python scripts/url_analyze.py "http://example.com" --fetch --timeout 10
```

### 场景 3: CI/CD 环境

```bash
URL_ANALYSIS_TIMEOUT=120 URL_ANALYSIS_VERIFY_SSL=true \
  python scripts/url_analyze.py "$URL" --fetch
```

### 场景 4: 配置文件方式（推荐）

```bash
# ~/.bashrc 或 ~/.zshrc
export URL_ANALYSIS_TIMEOUT=60
export URL_ANALYSIS_MAX_REDIRECTS=15
export URL_ANALYSIS_USER_AGENT=firefox
```

## 布尔值格式

`URL_ANALYSIS_VERIFY_SSL` 支持以下值：

| 真值 | 假值 |
|------|------|
| `true`, `1`, `yes`, `on` | `false`, `0`, `no`, `off` |

## 错误处理

- 无效的整数值会输出警告并使用默认值
- 未设置的环境变量使用内置默认值
- 空字符串视为未设置

```bash
# 示例：无效值会触发警告
export URL_ANALYSIS_TIMEOUT=abc
python scripts/url_analyze.py "http://example.com" --fetch
# 警告: 环境变量 URL_ANALYSIS_TIMEOUT=abc 不是有效整数，使用默认值 30
```

## 调试

检查当前配置：

```bash
echo "TIMEOUT: ${URL_ANALYSIS_TIMEOUT:-30}"
echo "MAX_REDIRECTS: ${URL_ANALYSIS_MAX_REDIRECTS:-10}"
echo "USER_AGENT: ${URL_ANALYSIS_USER_AGENT:-chrome}"
echo "VERIFY_SSL: ${URL_ANALYSIS_VERIFY_SSL:-false}"
```

查看帮助信息（显示当前生效的默认值）：

```bash
python scripts/url_analyze.py --help
```
