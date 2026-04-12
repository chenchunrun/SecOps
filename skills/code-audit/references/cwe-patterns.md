# CWE 检测模式

## CWE Top 25 (2023)

### 1. CWE-787: 越界写入
**语言**: C/C++
```c
// 危险模式
char buf[10];
strcpy(buf, user_input);  // 无边界检查

// 安全模式
strncpy(buf, user_input, sizeof(buf) - 1);
buf[sizeof(buf) - 1] = '\0';
```

### 2. CWE-79: XSS
**语言**: JavaScript, PHP, Java
```javascript
// 危险模式
element.innerHTML = userInput;
document.write(userInput);

// 安全模式
element.textContent = userInput;
```

### 3. CWE-89: SQL 注入
**语言**: 全部
```python
# 危险模式
query = f"SELECT * FROM users WHERE name = '{name}'"
cursor.execute(query)

# 安全模式
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
```

### 4. CWE-416: 释放后使用
**语言**: C/C++
```c
// 危险模式
free(ptr);
printf("%s", ptr);  // UAF

// 安全模式
free(ptr);
ptr = NULL;
```

### 5. CWE-78: 命令注入
**语言**: 全部
```python
# 危险模式
os.system(f"ping {host}")
subprocess.call(cmd, shell=True)

# 安全模式
subprocess.run(["ping", host], shell=False)
```

### 6. CWE-20: 输入验证不当
**语言**: 全部
```python
# 危险模式
def process(data):
    return eval(data)  # 直接执行用户输入

# 安全模式
def process(data):
    if not validate_input(data):
        raise ValueError("Invalid input")
    return safe_process(data)
```

### 7. CWE-125: 越界读取
**语言**: C/C++
```c
// 危险模式
int arr[10];
return arr[index];  // index 未验证

// 安全模式
if (index >= 0 && index < 10) {
    return arr[index];
}
```

### 8. CWE-22: 路径遍历
**语言**: 全部
```python
# 危险模式
file_path = os.path.join(base_dir, user_filename)
open(file_path)

# 安全模式
safe_path = os.path.realpath(os.path.join(base_dir, user_filename))
if not safe_path.startswith(os.path.realpath(base_dir)):
    raise SecurityError("Path traversal detected")
```

### 9. CWE-352: CSRF
**语言**: Web 框架
```python
# 危险模式 - 无 CSRF 保护
@app.route('/transfer', methods=['POST'])
def transfer():
    # 直接处理请求

# 安全模式
@app.route('/transfer', methods=['POST'])
@csrf.protect
def transfer():
    # CSRF token 验证
```

### 10. CWE-434: 危险文件上传
**语言**: 全部
```python
# 危险模式
filename = request.files['file'].filename
file.save(os.path.join(UPLOAD_DIR, filename))

# 安全模式
filename = secure_filename(request.files['file'].filename)
if allowed_file(filename):
    file.save(os.path.join(UPLOAD_DIR, filename))
```

## 敏感数据检测

### 硬编码凭据
```regex
# 正则模式
password\s*=\s*["'][^"']+["']
api_key\s*=\s*["'][^"']+["']
secret\s*=\s*["'][^"']+["']
token\s*=\s*["'][A-Za-z0-9_-]{20,}["']
```

### AWS 密钥
```regex
AKIA[0-9A-Z]{16}
```

### 私钥
```regex
-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----
```

### JWT Token
```regex
eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*
```

## 加密问题

### 弱哈希算法
```python
# 危险
hashlib.md5(password)
hashlib.sha1(password)

# 安全
import bcrypt
bcrypt.hashpw(password, bcrypt.gensalt())
```

### 弱加密算法
```python
# 危险
from Crypto.Cipher import DES  # 过时算法

# 安全
from Crypto.Cipher import AES
```

### 不安全随机数
```python
# 危险 - 用于安全场景
import random
token = random.randint(0, 999999)

# 安全
import secrets
token = secrets.token_hex(32)
```

## 认证问题

### 硬编码密码检查
```python
# 危险
if password == "admin123":
    login()
```

### 不安全的密码比较
```python
# 危险 - 时序攻击
if user_password == stored_password:

# 安全
import hmac
if hmac.compare_digest(user_password, stored_password):
```

## Semgrep 规则示例

```yaml
rules:
  - id: sql-injection
    patterns:
      - pattern: |
          $QUERY = f"... {$VAR} ..."
          $CURSOR.execute($QUERY)
    message: "可能的 SQL 注入"
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-89"
```
