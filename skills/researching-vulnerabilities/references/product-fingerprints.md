# 产品测绘指纹

用于 Phase 4 资产影响评估，构建 cyberspace-search 查询语法。

## 网络设备

| 产品 | 测绘语法 | 常见端口 |
|------|----------|----------|
| FortiGate | `app="Fortinet-FortiGate"` | 443, 10443 |
| FortiOS SSL-VPN | `app="Fortinet-SSL-VPN"` | 443, 10443 |
| Palo Alto | `app="Palo-Alto-GlobalProtect"` | 443 |
| Cisco ASA | `app="Cisco-ASA-SSL-VPN"` | 443 |
| Juniper | `app="Juniper-Junos"` | 443 |
| SonicWall | `app="SonicWall"` | 443 |

## Web 服务器/中间件

| 产品 | 测绘语法 | 常见端口 |
|------|----------|----------|
| Apache | `server="Apache"` | 80, 443 |
| Nginx | `server="nginx"` | 80, 443 |
| Tomcat | `app="Apache-Tomcat"` | 8080, 8443 |
| WebLogic | `app="Oracle-WebLogic"` | 7001, 7002 |
| JBoss/WildFly | `app="JBoss"` | 8080, 9990 |
| IIS | `server="Microsoft-IIS"` | 80, 443 |

## 企业应用

| 产品 | 测绘语法 | 常见端口 |
|------|----------|----------|
| Confluence | `app="Atlassian-Confluence"` | 8090, 443 |
| Jira | `app="Atlassian-JIRA"` | 8080, 443 |
| GitLab | `app="GitLab"` | 80, 443 |
| Jenkins | `app="Jenkins"` | 8080 |
| Nexus | `app="Sonatype-Nexus"` | 8081 |
| SonarQube | `app="SonarQube"` | 9000 |

## 邮件系统

| 产品 | 测绘语法 | 常见端口 |
|------|----------|----------|
| Exchange | `app="Microsoft-Exchange"` | 443, 25 |
| Exchange OWA | `app="Microsoft-Exchange-OWA"` | 443 |
| Zimbra | `app="Zimbra"` | 443, 8443 |
| Roundcube | `app="Roundcube"` | 80, 443 |

## 远程访问

| 产品 | 测绘语法 | 常见端口 |
|------|----------|----------|
| Citrix ADC | `app="Citrix-NetScaler"` | 443 |
| Citrix Gateway | `app="Citrix-Gateway"` | 443 |
| VMware Horizon | `app="VMware-Horizon"` | 443 |
| Pulse Secure | `app="Pulse-Secure"` | 443 |
| Ivanti Connect | `app="Ivanti-Connect-Secure"` | 443 |

## 数据库

| 产品 | 测绘语法 | 常见端口 |
|------|----------|----------|
| MySQL | `protocol="mysql"` | 3306 |
| PostgreSQL | `protocol="postgresql"` | 5432 |
| MongoDB | `protocol="mongodb"` | 27017 |
| Redis | `protocol="redis"` | 6379 |
| Elasticsearch | `app="Elasticsearch"` | 9200 |
| MSSQL | `protocol="mssql"` | 1433 |

## 容器/云

| 产品 | 测绘语法 | 常见端口 |
|------|----------|----------|
| Docker API | `port="2375" OR port="2376"` | 2375, 2376 |
| Kubernetes API | `port="6443"` | 6443, 8443 |
| etcd | `port="2379"` | 2379 |

## 开源组件

| 产品 | 测绘语法 | 说明 |
|------|----------|------|
| Log4j | `app="Apache-Log4j"` | Java 日志组件 |
| Spring Boot | `app="Spring-Boot"` | Java 框架 |
| Struts2 | `app="Apache-Struts2"` | Java 框架 |
| Drupal | `app="Drupal"` | CMS |
| WordPress | `app="WordPress"` | CMS |

## 国产软件

| 产品 | 测绘语法 | 说明 |
|------|----------|------|
| 泛微 OA | `app="泛微-OA"` OR `app="Weaver-OA"` | 协同办公 |
| 致远 OA | `app="Seeyon"` | 协同办公 |
| 用友 NC | `app="Yonyou-NC"` | ERP |
| 金蝶 | `app="Kingdee"` | ERP |
| 蓝凌 | `app="Landray"` | OA |
| 通达 OA | `app="Tongda-OA"` | 协同办公 |
| 帆软报表 | `app="FineReport"` | BI |

---

## 查询技巧

### 限定资产范围

```
# 按组织
app="FortiGate" && org="公司名"

# 按域名
app="FortiGate" && domain="example.com"

# 按 IP 段
app="FortiGate" && ip="192.168.1.0/24"

# 按国家
app="FortiGate" && country="CN"
```

### 组合查询

```
# 特定版本
app="Confluence" && body="版本号"

# 排除已修复
app="FortiGate" && port="443" && !body="7.4.3"
```

### 版本识别

部分产品可通过响应内容识别版本:
```
app="FortiGate" && body="FortiOS 7.4"
app="Confluence" && body="confluence-7"
```
