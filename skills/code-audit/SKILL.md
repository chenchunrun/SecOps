---
name: code-audit
description: 源代码安全审计。当用户要求"代码审计"、"安全审计"、"漏洞扫描"、"代码安全检查"、"SAST分析"时使用此技能。支持 Python、Java、JavaScript、PHP、Go、C/C++ 等主流语言。检测 OWASP Top 10、CWE Top 25 等常见漏洞，输出包含风险评级、CWE 映射和修复建议的审计报告。
metadata:
  version: 1.0.0
  builtin: true
---

# 代码安全审计

静态分析源代码，识别安全漏洞，评估风险等级，生成可操作的修复报告。

## 支持语言

| 语言 | 检测能力 | 推荐工具 |
|------|---------|---------|
| Python | 完整 | Bandit, Semgrep |
| JavaScript/TS | 完整 | ESLint, Semgrep |
| Java | 完整 | Semgrep, SpotBugs |
| PHP | 完整 | Semgrep, PHPStan |
| Go | 完整 | gosec, Semgrep |
| C/C++ | 基础 | cppcheck, Semgrep |
| Ruby | 基础 | Brakeman |
| C# | 基础 | Semgrep |

## 审计工作流

### Phase 1: 代码收集

确认审计范围：
- 单文件 / 目录 / Git 仓库
- 语言类型（自动检测或用户指定）
- 重点关注区域（认证、输入处理、数据库操作等）

### Phase 2: 自动化扫描

```bash
# Python
bandit -r ./src -f json -o bandit_report.json

# JavaScript
npx eslint --ext .js,.ts ./src --format json

# 通用（推荐）
semgrep --config=auto ./src --json > semgrep_report.json
```

### Phase 3: 人工复审

重点检查：
1. **认证与授权** - 登录、会话、权限控制
2. **输入验证** - 用户输入处理、参数校验
3. **敏感数据** - 密钥、密码、API Token
4. **数据库操作** - SQL 查询、ORM 使用
5. **文件操作** - 路径处理、文件上传
6. **命令执行** - 系统调用、Shell 命令
7. **加密实现** - 算法选择、随机数生成

### Phase 4: 风险评级

| 等级 | 条件 | 处理优先级 |
|------|------|-----------|
| 严重 | RCE、SQL注入、认证绕过 | 立即修复 |
| 高危 | XSS、SSRF、敏感信息泄露 | 24小时内 |
| 中危 | CSRF、路径遍历、弱加密 | 1周内 |
| 低危 | 信息泄露、配置问题 | 下个版本 |

### Phase 5: 报告生成

按 `references/report-format.md` 格式输出报告。

## 常见漏洞检测

### 注入类漏洞

#### SQL 注入
```python
# 危险模式
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# 安全写法
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

#### 命令注入
```python
# 危险模式
os.system(f"ping {user_input}")

# 安全写法
subprocess.run(["ping", user_input], shell=False)
```

#### XSS
```javascript
// 危险模式
element.innerHTML = userInput;

// 安全写法
element.textContent = userInput;
```

### 认证与会话

#### 硬编码凭据
```python
# 危险 - 检测模式
password = "admin123"
api_key = "sk-xxxx"
secret = "my_secret_key"
```

#### 弱密码策略
```python
# 检查密码强度验证
if len(password) < 8:  # 不够 - 应检查复杂度
    raise ValueError("密码太短")
```

### 敏感数据

#### 日志泄露
```python
# 危险模式
logger.info(f"User login: {username}, password: {password}")

# 安全写法
logger.info(f"User login: {username}")
```

#### 不安全传输
```python
# 危险模式
requests.get("http://api.example.com/data")

# 安全写法
requests.get("https://api.example.com/data", verify=True)
```

### 文件操作

#### 路径遍历
```python
# 危险模式
file_path = os.path.join("/uploads", user_filename)

# 安全写法
safe_name = secure_filename(user_filename)
file_path = os.path.join("/uploads", safe_name)
if not file_path.startswith("/uploads"):
    raise SecurityError("路径遍历攻击")
```

## 依赖要求

**Python 版本**: 3.8+

**推荐工具**:

| 工具 | 安装命令 | 用途 |
|------|---------|------|
| Semgrep | `pip install semgrep` | 通用静态分析 |
| Bandit | `pip install bandit` | Python 安全扫描 |

```bash
pip install semgrep bandit
```

**可选工具**:

| 工具 | 安装 | 用途 |
|------|------|------|
| ESLint | `npm install -g eslint` | JavaScript 扫描 |
| gosec | `go install github.com/securego/gosec/v2/cmd/gosec@latest` | Go 扫描 |
| cppcheck | `brew install cppcheck` | C/C++ 扫描 |

## 检测规则

### OWASP Top 10 (2021)

| 编号 | 类别 | 检测模式 |
|------|------|---------|
| A01 | 访问控制失效 | 权限检查缺失、IDOR |
| A02 | 加密失败 | 弱算法、明文存储 |
| A03 | 注入 | SQL/命令/LDAP/XPath |
| A04 | 不安全设计 | 业务逻辑漏洞 |
| A05 | 安全配置错误 | DEBUG模式、默认凭据 |
| A06 | 脆弱组件 | 已知漏洞依赖 |
| A07 | 认证失败 | 弱密码、会话固定 |
| A08 | 数据完整性失败 | 反序列化、CI/CD |
| A09 | 日志监控失败 | 敏感数据日志 |
| A10 | SSRF | 未验证的URL请求 |

### CWE Top 25 (2023)

详见 [references/cwe-patterns.md](references/cwe-patterns.md)

## 快速检测命令

```bash
# Python 项目
bandit -r ./src -ll -ii

# JavaScript 项目
npx eslint ./src --ext .js,.ts

# 通用扫描
semgrep --config=p/security-audit ./src

# 依赖漏洞检查
pip-audit  # Python
npm audit  # JavaScript
```

## 输出规范

报告必须包含：

1. **审计概要** - 范围、时间、发现统计
2. **风险总览** - 按等级分类的漏洞数量
3. **漏洞详情** - 每个漏洞的完整信息
   - 位置（文件:行号）
   - 风险等级
   - CWE 编号
   - 漏洞描述
   - 修复建议
   - 代码示例
4. **修复优先级** - 按风险排序的修复清单
5. **安全建议** - 通用加固建议

## 与其他技能的关联

| 发现内容 | 调用技能 | 说明 |
|---------|---------|------|
| 硬编码 URL | `/url-analysis` | 分析嵌入的 URL |
| 硬编码 IP | `/ip-analysis` | 分析嵌入的 IP |
| 可疑依赖 | `/researching-vulnerabilities` | 查询依赖漏洞 |

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 报告格式规范（必读）
- [references/cwe-patterns.md](references/cwe-patterns.md) - CWE 检测模式
- [references/language-specific.md](references/language-specific.md) - 语言特定检测
- [references/fix-examples.md](references/fix-examples.md) - 修复代码示例
