# 脱敏示例

## 示例 1：安全事件报告

### 原文
```markdown
# 安全事件报告

## 事件概述
2024年1月15日，我司安全团队发现来自 203.0.113.50 的异常访问。
攻击者尝试暴力破解 admin@company.com 的邮箱账户。

## 攻击详情
- 攻击源 IP: 203.0.113.50
- 目标服务器: 192.168.1.100 (内部邮件服务器)
- 被攻击账户: admin@company.com, ceo@company.com
- 攻击时间: 2024-01-15 14:30:00 - 15:45:00

## 受影响资产
| 资产 | IP | 负责人 |
|------|-----|--------|
| 邮件服务器 | 192.168.1.100 | 张三 |
| 备份服务器 | 192.168.1.101 | 李四 |

## 攻击者信息
经溯源分析，攻击者使用的 C2 服务器为 evil-c2.example.org，
关联域名包括 phishing.badsite.com。

联系人：安全负责人 王五，电话 13800138000
```

### 脱敏后
```markdown
# 安全事件报告

## 事件概述
2024年1月15日，我司安全团队发现来自 [PUBLIC_IP_1] 的异常访问。
攻击者尝试暴力破解 [EMAIL_1] 的邮箱账户。

## 攻击详情
- 攻击源 IP: [PUBLIC_IP_1]
- 目标服务器: [PRIVATE_IP_1] (内部邮件服务器)
- 被攻击账户: [EMAIL_1], [EMAIL_2]
- 攻击时间: 2024-01-15 14:30:00 - 15:45:00

## 受影响资产
| 资产 | IP | 负责人 |
|------|-----|--------|
| 邮件服务器 | [PRIVATE_IP_1] | [PERSON_1] |
| 备份服务器 | [PRIVATE_IP_2] | [PERSON_2] |

## 攻击者信息
经溯源分析，攻击者使用的 C2 服务器为 [DOMAIN_1]，
关联域名包括 [DOMAIN_2]。

联系人：安全负责人 [PERSON_3]，电话 [PHONE_1]

<!-- DESENSITIZE_MAPPINGS
[PUBLIC_IP_1] = 203.0.113.50
[PRIVATE_IP_1] = 192.168.1.100
[PRIVATE_IP_2] = 192.168.1.101
[EMAIL_1] = admin@company.com
[EMAIL_2] = ceo@company.com
[DOMAIN_1] = evil-c2.example.org
[DOMAIN_2] = phishing.badsite.com
[PERSON_1] = 张三
[PERSON_2] = 李四
[PERSON_3] = 王五
[PHONE_1] = 13800138000
-->
```

---

## 示例 2：服务器日志

### 原文
```
2024-01-15 10:23:45 INFO  Connection from 192.168.1.50 to db.internal.corp.com:3306
2024-01-15 10:23:46 INFO  User admin@corp.com logged in from 10.0.0.25
2024-01-15 10:24:01 WARN  Failed login attempt for user root, password=admin123
2024-01-15 10:24:15 ERROR Connection refused from 45.33.32.156 (blacklisted)
2024-01-15 10:25:00 INFO  API call to https://api.partner.com/v1/users with key sk-proj-abc123xyz789
```

### 脱敏后
```
2024-01-15 10:23:45 INFO  Connection from [PRIVATE_IP_1] to [DOMAIN_1]:3306
2024-01-15 10:23:46 INFO  User [EMAIL_1] logged in from [PRIVATE_IP_2]
2024-01-15 10:24:01 WARN  Failed login attempt for user root, password=admin123
2024-01-15 10:24:15 ERROR Connection refused from [PUBLIC_IP_1] (blacklisted)
2024-01-15 10:25:00 INFO  API call to https://[DOMAIN_2]/v1/users with key [APIKEY_1]

<!-- DESENSITIZE_MAPPINGS
[PRIVATE_IP_1] = 192.168.1.50
[PRIVATE_IP_2] = 10.0.0.25
[PUBLIC_IP_1] = 45.33.32.156
[DOMAIN_1] = db.internal.corp.com
[DOMAIN_2] = api.partner.com
[EMAIL_1] = admin@corp.com
[APIKEY_1] = sk-proj-abc123xyz789
-->
```

**注意**: `password=admin123` 保留，因为 `admin123` 是弱口令，对安全分析有价值。

---

## 示例 3：配置文件 (YAML)

### 原文
```yaml
database:
  host: db.mycompany.internal
  port: 5432
  username: dbadmin
  password: Sup3rS3cr3t!

api:
  endpoint: https://api.mycompany.com/v2
  key: sk-live-abcdef123456789

notification:
  email: alerts@mycompany.com
  phone: +86-13912345678

server:
  bind: 0.0.0.0
  port: 8080
```

### 脱敏后
```yaml
database:
  host: [DOMAIN_1]
  port: 5432
  username: dbadmin
  password: [CREDENTIAL_1]

api:
  endpoint: https://[DOMAIN_2]/v2
  key: [APIKEY_1]

notification:
  email: [EMAIL_1]
  phone: [PHONE_1]

server:
  bind: 0.0.0.0
  port: 8080

# DESENSITIZE_MAPPINGS
# [DOMAIN_1] = db.mycompany.internal
# [DOMAIN_2] = api.mycompany.com
# [CREDENTIAL_1] = Sup3rS3cr3t!
# [APIKEY_1] = sk-live-abcdef123456789
# [EMAIL_1] = alerts@mycompany.com
# [PHONE_1] = +86-13912345678
```

**注意**:
- `port: 5432` 和 `port: 8080` 保留（端口号）
- `0.0.0.0` 保留（通用绑定地址）
- `username: dbadmin` 保留（通用用户名，非敏感）

---

## 示例 4：JSON 数据

### 原文
```json
{
  "user": {
    "name": "张三",
    "email": "zhangsan@example.com",
    "phone": "13800138000",
    "idcard": "110101199001011234"
  },
  "payment": {
    "card_number": "6222021234567890123",
    "bank": "中国工商银行"
  },
  "location": {
    "ip": "116.228.89.xxx",
    "address": "上海市浦东新区张江高科技园区"
  }
}
```

### 脱敏后
```json
{
  "user": {
    "name": "[PERSON_1]",
    "email": "[EMAIL_1]",
    "phone": "[PHONE_1]",
    "idcard": "[IDCARD_1]"
  },
  "payment": {
    "card_number": "[BANKCARD_1]",
    "bank": "[ORG_1]"
  },
  "location": {
    "ip": "[PUBLIC_IP_1]",
    "address": "[ADDRESS_1]"
  }
}

// DESENSITIZE_MAPPINGS
// [PERSON_1] = 张三
// [EMAIL_1] = zhangsan@example.com
// [PHONE_1] = 13800138000
// [IDCARD_1] = 110101199001011234
// [BANKCARD_1] = 6222021234567890123
// [ORG_1] = 中国工商银行
// [PUBLIC_IP_1] = 116.228.89.xxx
// [ADDRESS_1] = 上海市浦东新区张江高科技园区
```

---

## 示例 5：网络拓扑保留

### 场景
需要保留内网拓扑关系，用于网络安全分析。

### 原文
```
网络拓扑:
- 网关: 192.168.1.1
- Web服务器: 192.168.1.10, 192.168.1.11
- 数据库: 192.168.1.20
- 攻击者从 192.168.1.10 横向移动到 192.168.1.20
```

### 脱敏后（保留拓扑）
```
网络拓扑:
- 网关: [PRIVATE_IP_1]
- Web服务器: [PRIVATE_IP_2], [PRIVATE_IP_3]
- 数据库: [PRIVATE_IP_4]
- 攻击者从 [PRIVATE_IP_2] 横向移动到 [PRIVATE_IP_4]

<!-- DESENSITIZE_MAPPINGS (拓扑保留)
[PRIVATE_IP_1] = 192.168.1.1 (网关，.1)
[PRIVATE_IP_2] = 192.168.1.10 (同网段)
[PRIVATE_IP_3] = 192.168.1.11 (同网段)
[PRIVATE_IP_4] = 192.168.1.20 (同网段)
说明: 所有 IP 属于同一 /24 子网
-->
```

---

## 不脱敏示例

### 这些内容不应该脱敏

```
# 版本信息 - 不脱敏
Python 3.9.7
nginx/1.21.4
MySQL 8.0.27

# 端口号 - 不脱敏
Listen on port 443
Connect to :3306

# 公共服务 - 通常不脱敏
ping google.com
curl https://github.com/user/repo

# 环回地址 - 不脱敏
localhost
127.0.0.1

# 时间戳 - 不脱敏
2024-01-15T10:30:00Z
1705312200
```
