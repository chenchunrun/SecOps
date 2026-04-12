# ZoomEye 搜索语法完整参考

## 概述

ZoomEye（钟馗之眼）是网络空间搜索引擎，支持两种搜索类型：
- **主机搜索**：扫描设备指纹（IP、端口、服务、操作系统等）
- **Web 搜索**：扫描 Web 指纹（应用、框架、CMS、标题等）

## 基础搜索语法

### 组件与服务

| 语法 | 说明 | 示例 |
|------|------|------|
| `app` | 组件/应用名称 | `app:nginx`, `app:apache`, `app:mysql` |
| `ver` | 组件版本（需配合 app） | `app:apache ver:2.4`, `app:nginx ver:1.18` |
| `service` | 服务类型 | `service:http`, `service:ssh`, `service:ftp` |
| `device` | 设备类型 | `device:router`, `device:camera`, `device:printer` |

### 端口与协议

| 语法 | 说明 | 示例 |
|------|------|------|
| `port` | 单个端口 | `port:22`, `port:80`, `port:443` |
| `port` | 多个端口（逗号分隔） | `port:80,443,8080` |
| `port` | 端口范围 | `port:8000-9000` |

### 操作系统

| 语法 | 说明 | 示例 |
|------|------|------|
| `os` | 操作系统名称 | `os:Linux`, `os:Windows`, `os:CentOS` |

### IP 与网段

| 语法 | 说明 | 示例 |
|------|------|------|
| `ip` | 单个 IP | `ip:8.8.8.8` |
| `ip` | IP 范围 | `ip:192.168.1.1-192.168.1.255` |
| `cidr` | CIDR 网段 | `cidr:10.0.0.0/8`, `cidr:192.168.0.0/16` |

### 地理位置

| 语法 | 说明 | 示例 |
|------|------|------|
| `country` | 国家代码（ISO 3166-1） | `country:CN`, `country:US`, `country:JP` |
| `city` | 城市名称 | `city:Beijing`, `city:Shanghai` |
| `subdivisions` | 省/州/地区 | `subdivisions:Guangdong`, `subdivisions:California` |

### 域名与主机

| 语法 | 说明 | 示例 |
|------|------|------|
| `site` | 域名/站点 | `site:example.com`, `site:gov.cn` |
| `hostname` | 主机名 | `hostname:mail`, `hostname:vpn` |

### ASN 与组织

| 语法 | 说明 | 示例 |
|------|------|------|
| `asn` | AS 号码 | `asn:4134`, `asn:4837` |
| `org` | 组织名称 | `org:alibaba`, `org:tencent` |

## Web 搜索专用语法

| 语法 | 说明 | 示例 |
|------|------|------|
| `title` | 网页标题 | `title:管理`, `title:admin`, `title:登录` |
| `header` | HTTP 响应头 | `header:Server:nginx`, `header:X-Powered-By` |
| `keywords` | 网页关键词 | `keywords:后台管理` |
| `desc` | 网页描述 | `desc:管理系统` |

## 高级搜索语法

### Banner 搜索

| 语法 | 说明 | 示例 |
|------|------|------|
| `banner` | Banner 内容关键词 | `banner:Welcome`, `banner:unauthorized` |

### 证书搜索

| 语法 | 说明 | 示例 |
|------|------|------|
| `ssl` | SSL 证书信息 | `ssl:Let's Encrypt` |
| `ssl.cert.subject.cn` | 证书 CN | `ssl.cert.subject.cn:*.example.com` |
| `ssl.cert.issuer.cn` | 颁发者 CN | `ssl.cert.issuer.cn:DigiCert` |

### 时间范围

| 语法 | 说明 | 示例 |
|------|------|------|
| `after` | 指定日期之后 | `after:2024-01-01` |
| `before` | 指定日期之前 | `before:2024-06-01` |

## 逻辑运算符

| 运算符 | 说明 | 示例 |
|--------|------|------|
| 空格 | AND（与） | `app:nginx port:443` |
| `+` | 必须包含 | `+app:nginx +country:CN` |
| `-` | 排除（非） | `app:nginx -country:US` |
| `OR` | 或 | `app:nginx OR app:apache` |
| `()` | 分组 | `(app:nginx OR app:apache) country:CN` |

### 运算符优先级

1. 括号 `()` 最高
2. NOT/排除 `-`
3. AND（空格）
4. OR

## 通配符

| 符号 | 说明 | 示例 |
|------|------|------|
| `*` | 任意字符 | `hostname:mail*`, `site:*.gov.cn` |

## 常用国家代码

| 代码 | 国家/地区 |
|------|-----------|
| CN | 中国 |
| US | 美国 |
| JP | 日本 |
| KR | 韩国 |
| DE | 德国 |
| GB | 英国 |
| FR | 法国 |
| RU | 俄罗斯 |
| SG | 新加坡 |
| HK | 香港 |
| TW | 台湾 |

## 常用端口参考

### 远程管理

| 端口 | 服务 |
|------|------|
| 22 | SSH |
| 23 | Telnet |
| 3389 | RDP (远程桌面) |
| 5900 | VNC |

### Web 服务

| 端口 | 服务 |
|------|------|
| 80 | HTTP |
| 443 | HTTPS |
| 8080 | HTTP Proxy/Alt |
| 8443 | HTTPS Alt |

### 数据库

| 端口 | 服务 |
|------|------|
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 1433 | MSSQL |
| 1521 | Oracle |
| 27017 | MongoDB |
| 6379 | Redis |
| 9200 | Elasticsearch |

### 邮件服务

| 端口 | 服务 |
|------|------|
| 25 | SMTP |
| 110 | POP3 |
| 143 | IMAP |
| 465 | SMTPS |
| 993 | IMAPS |

### 文件服务

| 端口 | 服务 |
|------|------|
| 21 | FTP |
| 69 | TFTP |
| 445 | SMB |
| 873 | Rsync |

### 工控协议

| 端口 | 服务 |
|------|------|
| 502 | Modbus |
| 102 | S7comm (Siemens) |
| 44818 | EtherNet/IP |
| 47808 | BACnet |
| 20000 | DNP3 |

## 常见组件名称

### Web 服务器

```
app:nginx
app:apache
app:iis
app:tomcat
app:lighttpd
```

### 数据库

```
app:mysql
app:mongodb
app:redis
app:elasticsearch
app:postgresql
app:oracle
app:mssql
```

### CMS/框架

```
app:wordpress
app:drupal
app:joomla
app:discuz
app:phpcms
app:dedecms
app:thinkphp
app:struts2
app:spring
app:django
app:flask
app:laravel
```

### 网络设备

```
app:cisco
app:huawei
app:mikrotik
app:juniper
app:fortinet
```

### 安全设备

```
app:hikvision
app:dahua
app:paloalto
app:checkpoint
app:f5
```

## 查询示例集合

### 基础搜索

```bash
# 搜索 nginx 服务器
app:nginx

# 搜索 22 端口
port:22

# 搜索中国的资产
country:CN

# 搜索特定 IP
ip:1.2.3.4
```

### 组合搜索

```bash
# 中国的 nginx 服务器
app:nginx country:CN

# 开放 MySQL 的 Linux 服务器
app:mysql os:Linux

# 特定版本的 Apache
app:apache ver:2.4.49
```

### 企业资产

```bash
# 按域名搜索
site:example.com

# 按 IP 段搜索
cidr:203.0.113.0/24

# 按组织名搜索
org:example
```

### 漏洞资产

```bash
# Log4j 漏洞版本
app:log4j ver:2.14

# 老旧 Apache
app:apache ver:2.2

# Exchange 服务器
app:exchange
```

### IoT 设备

```bash
# 摄像头
device:camera

# 海康威视
app:hikvision

# 大华
app:dahua

# 路由器
device:router
```

### 敏感服务

```bash
# 暴露的 Redis
app:redis port:6379

# 暴露的 MongoDB
app:mongodb port:27017

# 暴露的 Elasticsearch
app:elasticsearch port:9200
```

### Web 应用

```bash
# 管理后台
title:管理 OR title:admin OR title:后台

# 登录页面
title:登录 OR title:login

# phpMyAdmin
app:phpmyadmin
```

### 排除搜索

```bash
# 搜索非美国的 nginx
app:nginx -country:US

# 排除特定端口
app:apache -port:443
```

### 复杂组合

```bash
# 中国境内暴露的数据库服务
(app:mysql OR app:mongodb OR app:redis) country:CN

# 特定网段的 Web 服务
cidr:10.0.0.0/8 (port:80 OR port:443 OR port:8080)
```

## 注意事项

1. **大小写不敏感**：`app:nginx` 等同于 `app:NGINX`
2. **引号使用**：包含空格的值需要用引号，如 `title:"admin login"`
3. **中文搜索**：支持中文关键词，如 `title:管理系统`
5. **结果准确性**：搜索结果基于历史扫描数据，可能存在时效性差异
