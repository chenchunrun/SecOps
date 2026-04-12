# 语言特定安全检测

## Python

### 危险函数
| 函数 | 风险 | 替代方案 |
|------|------|---------|
| `eval()` | 代码注入 | `ast.literal_eval()` |
| `exec()` | 代码注入 | 避免使用 |
| `pickle.loads()` | 反序列化 | `json.loads()` |
| `yaml.load()` | 反序列化 | `yaml.safe_load()` |
| `os.system()` | 命令注入 | `subprocess.run(..., shell=False)` |
| `input()` (Python 2) | 代码注入 | `raw_input()` |

### 检测命令
```bash
bandit -r ./src -ll -ii
semgrep --config=p/python ./src
```

### 常见问题
```python
# 1. 不安全的反序列化
import pickle
data = pickle.loads(user_data)  # 危险

# 2. 调试代码残留
import pdb; pdb.set_trace()  # 生产环境禁止
DEBUG = True  # 应为 False

# 3. 异常信息泄露
except Exception as e:
    return str(e)  # 泄露内部信息
```

## JavaScript/TypeScript

### 危险模式
| 模式 | 风险 | 替代方案 |
|------|------|---------|
| `eval()` | 代码注入 | `JSON.parse()` |
| `innerHTML` | XSS | `textContent` |
| `document.write()` | XSS | DOM 操作 |
| `$.html()` | XSS | `$.text()` |
| `new Function()` | 代码注入 | 避免使用 |

### 检测命令
```bash
npx eslint ./src --ext .js,.ts
semgrep --config=p/javascript ./src
```

### 常见问题
```javascript
// 1. 原型污染
Object.assign(target, userInput);  // 危险

// 2. 正则 ReDoS
const regex = /^(a+)+$/;  // 指数级回溯
regex.test(userInput);

// 3. 不安全的 URL 跳转
window.location = userInput;  // 开放重定向
```

## Java

### 危险类/方法
| 类/方法 | 风险 | 替代方案 |
|---------|------|---------|
| `Runtime.exec()` | 命令注入 | ProcessBuilder + 验证 |
| `ObjectInputStream` | 反序列化 | JSON/安全库 |
| `Statement.execute()` | SQL注入 | PreparedStatement |
| `XPathExpression` | XPath注入 | 参数化查询 |

### 检测命令
```bash
semgrep --config=p/java ./src
# 或使用 SpotBugs
```

### 常见问题
```java
// 1. SQL 注入
String query = "SELECT * FROM users WHERE id = " + userId;
stmt.execute(query);  // 危险

// 2. XXE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// 缺少: dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

// 3. 不安全的随机数
Random rand = new Random();  // 用于安全场景时危险
// 应使用: SecureRandom
```

## PHP

### 危险函数
| 函数 | 风险 | 替代方案 |
|------|------|---------|
| `eval()` | 代码注入 | 避免使用 |
| `system()`, `exec()` | 命令注入 | `escapeshellarg()` |
| `include($var)` | 文件包含 | 白名单验证 |
| `unserialize()` | 反序列化 | `json_decode()` |
| `mysql_query()` | SQL注入 | PDO 预处理 |

### 检测命令
```bash
semgrep --config=p/php ./src
```

### 常见问题
```php
// 1. 文件包含
include($_GET['page'] . '.php');  // LFI/RFI

// 2. 类型混淆
if ($password == $user_input) {}  // 使用 ===

// 3. 输出未转义
echo $user_input;  // 应使用 htmlspecialchars()
```

## Go

### 危险模式
| 模式 | 风险 | 替代方案 |
|------|------|---------|
| `fmt.Sprintf` + SQL | SQL注入 | 参数化查询 |
| `exec.Command` | 命令注入 | 验证输入 |
| `html/template` 误用 | XSS | 正确使用模板 |

### 检测命令
```bash
gosec ./...
semgrep --config=p/golang ./
```

### 常见问题
```go
// 1. SQL 注入
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
db.Query(query)  // 危险

// 2. 路径遍历
http.ServeFile(w, r, filepath.Join(baseDir, r.URL.Path))

// 3. 不安全的 TLS
&tls.Config{InsecureSkipVerify: true}  // 危险
```

## C/C++

### 危险函数
| 函数 | 风险 | 替代方案 |
|------|------|---------|
| `strcpy()` | 缓冲区溢出 | `strncpy()` |
| `sprintf()` | 缓冲区溢出 | `snprintf()` |
| `gets()` | 缓冲区溢出 | `fgets()` |
| `scanf("%s")` | 缓冲区溢出 | 指定宽度 |

### 检测命令
```bash
cppcheck --enable=all ./src
semgrep --config=p/c ./src
```

### 常见问题
```c
// 1. 缓冲区溢出
char buf[64];
strcpy(buf, user_input);  // 无边界检查

// 2. 格式化字符串
printf(user_input);  // 应使用 printf("%s", user_input);

// 3. 整数溢出
int size = user_size * sizeof(int);  // 可能溢出
malloc(size);
```
