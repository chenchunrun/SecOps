# 漏洞修复代码示例

## SQL 注入修复

### Python
```python
# 危险
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# 修复 - 参数化查询
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# 修复 - ORM (SQLAlchemy)
User.query.filter_by(id=user_id).first()
```

### Java
```java
// 危险
String query = "SELECT * FROM users WHERE id = " + userId;
stmt.executeQuery(query);

// 修复 - PreparedStatement
PreparedStatement pstmt = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?");
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();
```

### PHP
```php
// 危险
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
mysqli_query($conn, $query);

// 修复 - PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
```

## XSS 修复

### JavaScript
```javascript
// 危险
element.innerHTML = userInput;

// 修复 - textContent
element.textContent = userInput;

// 修复 - 需要 HTML 时使用 DOMPurify
element.innerHTML = DOMPurify.sanitize(userInput);
```

### Python (Jinja2)
```python
# 危险 - 禁用自动转义
{{ user_input | safe }}

# 修复 - 默认转义
{{ user_input }}

# 修复 - 显式转义
{{ user_input | e }}
```

### PHP
```php
// 危险
echo $user_input;

// 修复
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
```

## 命令注入修复

### Python
```python
# 危险
os.system(f"ping {host}")
subprocess.call(cmd, shell=True)

# 修复 - 使用列表参数
subprocess.run(["ping", "-c", "4", host], shell=False)

# 修复 - 输入验证
import re
if not re.match(r'^[\w.-]+$', host):
    raise ValueError("Invalid hostname")
```

### Java
```java
// 危险
Runtime.getRuntime().exec("ping " + host);

// 修复
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
// 加上输入验证
if (!host.matches("^[\\w.-]+$")) {
    throw new IllegalArgumentException("Invalid hostname");
}
```

## 路径遍历修复

### Python
```python
# 危险
file_path = os.path.join(base_dir, user_filename)
open(file_path)

# 修复
from werkzeug.utils import secure_filename

safe_filename = secure_filename(user_filename)
file_path = os.path.realpath(os.path.join(base_dir, safe_filename))

# 验证路径在允许范围内
if not file_path.startswith(os.path.realpath(base_dir)):
    raise SecurityError("Path traversal detected")
```

### Java
```java
// 危险
File file = new File(baseDir, userFilename);

// 修复
Path basePath = Paths.get(baseDir).toRealPath();
Path filePath = basePath.resolve(userFilename).normalize().toRealPath();

if (!filePath.startsWith(basePath)) {
    throw new SecurityException("Path traversal detected");
}
```

## 硬编码凭据修复

```python
# 危险
password = "admin123"
api_key = "sk-xxxxx"

# 修复 - 环境变量
import os
password = os.environ.get('DB_PASSWORD')
api_key = os.environ.get('API_KEY')

# 修复 - 配置文件（不提交到代码库）
from config import settings
password = settings.DB_PASSWORD
```

## 不安全反序列化修复

### Python
```python
# 危险
import pickle
data = pickle.loads(user_input)

# 修复 - 使用 JSON
import json
data = json.loads(user_input)

# 修复 - 如必须用 pickle，验证来源
import hmac
if hmac.compare_digest(signature, expected_sig):
    data = pickle.loads(user_input)
```

### Java
```java
// 危险
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();

// 修复 - 使用 JSON
ObjectMapper mapper = new ObjectMapper();
MyClass obj = mapper.readValue(input, MyClass.class);
```

## 弱加密修复

```python
# 危险 - MD5/SHA1 用于密码
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()

# 修复 - 使用 bcrypt
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# 验证密码
if bcrypt.checkpw(password.encode(), stored_hash):
    # 验证成功
```

## SSRF 修复

```python
# 危险
import requests
response = requests.get(user_url)

# 修复 - URL 白名单验证
from urllib.parse import urlparse

ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']

parsed = urlparse(user_url)
if parsed.hostname not in ALLOWED_HOSTS:
    raise SecurityError("Host not allowed")
if parsed.scheme not in ['http', 'https']:
    raise SecurityError("Scheme not allowed")

response = requests.get(user_url)
```

## 不安全随机数修复

```python
# 危险 - 用于安全场景
import random
token = random.randint(0, 999999)
session_id = ''.join(random.choices(string.ascii_letters, k=32))

# 修复 - 使用 secrets 模块
import secrets
token = secrets.randbelow(1000000)
session_id = secrets.token_hex(32)
api_key = secrets.token_urlsafe(32)
```

## CSRF 修复

### Flask
```python
# 危险 - 无 CSRF 保护
@app.route('/transfer', methods=['POST'])
def transfer():
    # 处理请求

# 修复 - 添加 CSRF 保护
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

@app.route('/transfer', methods=['POST'])
def transfer():
    # 自动验证 CSRF token
```

### Django
```python
# 确保中间件启用
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
]

# 模板中使用
<form method="post">
    {% csrf_token %}
</form>
```
