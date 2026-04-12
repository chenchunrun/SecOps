# 网络空间搜索语法参考

## cyberspace-search 查询语法

### 基础查询

| 语法 | 说明 | 示例 |
|------|------|------|
| `hostname="domain"` | 精确域名 | `hostname="www.example.com"` |
| `hostname="*.domain"` | 通配符域名 | `hostname="*.example.com"` |
| `ip="x.x.x.x"` | 精确 IP | `ip="1.2.3.4"` |
| `cidr="x.x.x.x/24"` | IP 段 | `cidr="1.2.3.0/24"` |
| `port="80"` | 端口 | `port="443"` |
| `title="keyword"` | 页面标题 | `title="管理后台"` |
| `body="keyword"` | 页面内容 | `body="Powered by"` |
| `header="keyword"` | HTTP 头 | `header="nginx"` |

### 服务识别

| 语法 | 说明 |
|------|------|
| `service="http"` | HTTP 服务 |
| `service="https"` | HTTPS 服务 |
| `service="ssh"` | SSH 服务 |
| `service="mysql"` | MySQL 服务 |
| `service="redis"` | Redis 服务 |
| `service="mongodb"` | MongoDB 服务 |

### 证书搜索

| 语法 | 说明 |
|------|------|
| `cert.subject="example.com"` | 证书主题 |
| `cert.issuer="Let's Encrypt"` | 证书颁发者 |
| `cert.is_valid=true` | 有效证书 |

### 组合查询

```
# 查找企业所有子域名
hostname="*.example.com"

# 查找特定 IP 段的 Web 服务
cidr="1.2.3.0/24" && port="80,443"

# 查找管理后台
hostname="*.example.com" && (title="admin" || title="管理")

# 查找数据库暴露
hostname="*.example.com" && port="3306,5432,27017,6379"

# 排除 CDN
hostname="*.example.com" && -header="cloudflare"
```

### 逻辑运算符

| 运算符 | 说明 | 示例 |
|--------|------|------|
| `&&` | 与 | `a && b` |
| `||` | 或 | `a || b` |
| `-` | 非 | `-keyword` |
| `()` | 分组 | `(a || b) && c` |

### 常用资产发现查询模板

#### 子域名枚举
```
hostname="*.{domain}"
```

#### Web 资产
```
hostname="*.{domain}" && port="80,443,8080,8443"
```

#### 敏感端口
```
hostname="*.{domain}" && port="22,23,3389,5900"
```

#### 数据库暴露
```
hostname="*.{domain}" && port="3306,5432,1433,27017,6379,9200"
```

#### 开发测试环境
```
hostname="*.{domain}" && (title="test" || title="dev" || title="staging")
```

#### 管理后台
```
hostname="*.{domain}" && (title="admin" || title="login" || title="管理" || title="后台")
```

#### API 端点
```
hostname="*.{domain}" && (title="swagger" || title="api" || body="openapi")
```

#### 云资产
```
hostname="*.{domain}" && (header="AmazonS3" || header="x-oss" || header="x-cos")
```

## 高级技巧

### 1. ICP 备案关联

先查询 ICP 备案，获取备案号，再搜索同一备案下的其他域名：
```
icp="{备案号}"
```

### 2. 证书关联

通过证书 SAN 发现关联域名：
```
cert.subject="{organization}"
```

### 3. ASN 关联

通过 ASN 发现同一组织的 IP 资产：
```
asn="AS{number}"
```

### 4. Favicon 关联

通过网站图标哈希发现相同系统：
```
icon_hash="{hash}"
```

### 5. 组件指纹

通过特定组件发现资产：
```
body="{unique_fingerprint}" && -hostname="{official_domain}"
```

## 输出字段

| 字段 | 说明 |
|------|------|
| `ip` | IP 地址 |
| `port` | 端口 |
| `hostname` | 域名 |
| `title` | 页面标题 |
| `server` | 服务器类型 |
| `icp` | ICP 备案号 |
| `cert` | 证书信息 |
| `asn` | ASN 编号 |
| `geo` | 地理位置 |
