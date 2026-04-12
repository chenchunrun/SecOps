# 风险评估标准

## 端口风险评级

### 🔴 高危端口

| 端口 | 服务 | 风险说明 | 评级 |
|------|------|----------|------|
| 21 | FTP | 明文传输，凭证泄露 | high |
| 22 | SSH | 暴力破解，未授权访问 | high |
| 23 | Telnet | 明文传输，已废弃协议 | critical |
| 445 | SMB | 漏洞利用（永恒之蓝） | critical |
| 1433 | MSSQL | 数据库暴露 | high |
| 3306 | MySQL | 数据库暴露 | high |
| 3389 | RDP | 暴力破解，漏洞利用 | high |
| 5432 | PostgreSQL | 数据库暴露 | high |
| 5900 | VNC | 远程桌面暴露 | high |
| 6379 | Redis | 未授权访问，数据泄露 | critical |
| 9200 | Elasticsearch | 数据泄露 | critical |
| 27017 | MongoDB | 未授权访问，数据泄露 | critical |

### 🟡 中危端口

| 端口 | 服务 | 风险说明 | 评级 |
|------|------|----------|------|
| 25 | SMTP | 邮件服务暴露 | medium |
| 110 | POP3 | 邮件服务暴露 | medium |
| 143 | IMAP | 邮件服务暴露 | medium |
| 389 | LDAP | 目录服务暴露 | medium |
| 8080 | HTTP-ALT | Web 管理接口 | medium |
| 8443 | HTTPS-ALT | Web 管理接口 | medium |

### 🟢 低危端口

| 端口 | 服务 | 说明 | 评级 |
|------|------|------|------|
| 80 | HTTP | 标准 Web 服务 | low |
| 443 | HTTPS | 标准加密 Web 服务 | safe |

## 子域名风险评级

### 高危模式

| 关键词 | 风险说明 | 评级 |
|--------|----------|------|
| admin, 管理, 后台, console | 管理入口暴露 | high |
| api, gateway | API 接口暴露 | high |
| dev, test, staging, uat | 测试环境，安全配置弱 | high |
| git, svn, gitlab, jenkins | DevOps 系统，源码泄露 | critical |
| db, database, mysql, mongo | 数据库管理 | high |
| backup, bak, old | 备份文件暴露 | high |
| internal, intranet | 内网系统误暴露 | high |

### 中危模式

| 关键词 | 风险说明 | 评级 |
|--------|----------|------|
| vpn, sslvpn | 远程访问入口 | medium |
| mail, owa, webmail | 邮件系统 | medium |
| oa, erp, crm | 业务系统 | medium |
| monitor, grafana, zabbix | 监控系统 | medium |

## 综合风险评分

### 评分公式

```
风险评分 = 端口风险 × 0.4 + 服务风险 × 0.3 + 暴露程度 × 0.3
```

### 暴露程度判断

| 情况 | 暴露程度 |
|------|----------|
| 仅内网可访问 | 0.2 |
| 需认证访问 | 0.4 |
| 公网可访问，有基本防护 | 0.6 |
| 公网直接访问，无防护 | 1.0 |

### 风险等级划分

| 评分范围 | 等级 | 说明 |
|----------|------|------|
| 0 - 0.2 | safe | 安全 |
| 0.2 - 0.4 | low | 低风险 |
| 0.4 - 0.6 | medium | 中风险 |
| 0.6 - 0.8 | high | 高风险 |
| 0.8 - 1.0 | critical | 严重 |

## 变更风险评估

| 变更类型 | 默认严重程度 | 说明 |
|----------|--------------|------|
| added | info | 新资产发现 |
| removed | low | 资产移除（可能是误删或迁移） |
| portOpened | medium-high | 新端口开放（根据端口类型调整） |
| portClosed | info | 端口关闭 |
| ipChanged | medium | IP 变更（可能是迁移或劫持） |
| certExpiring | high | SSL 证书即将过期 |
| riskIncreased | high | 资产风险等级上升 |

## 自动评估规则

### 端口开放评估
```python
if port in [22, 3389]:
    severity = "high"
elif port in [23, 445, 6379, 9200, 27017]:
    severity = "critical"
elif port in [3306, 5432, 1433]:
    severity = "high"
elif port in [8080, 8443]:
    severity = "medium"
else:
    severity = "info"
```

### 子域名评估
```python
high_risk_patterns = ['admin', 'dev', 'test', 'api', 'git', 'jenkins', 'internal']
if any(pattern in subdomain.lower() for pattern in high_risk_patterns):
    risk_level = "high"
```
