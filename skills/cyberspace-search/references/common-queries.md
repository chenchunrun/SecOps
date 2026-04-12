# 常用查询模板集合

## 企业资产测绘

### 按域名搜索

```bash
# 主域名
site:example.com

# 包含子域名
site:*.example.com

# 多域名组合
site:example.com OR site:example.org
```

### 按 IP 段搜索

```bash
# CIDR 网段
cidr:203.0.113.0/24

# IP 范围
ip:203.0.113.1-203.0.113.254

# 多网段
cidr:10.0.0.0/8 OR cidr:172.16.0.0/12
```

### 按组织搜索

```bash
# 组织名称
org:alibaba

# ASN 编号
asn:4837
```

## 漏洞资产发现

### Apache 相关

```bash
# CVE-2021-41773 (路径遍历)
app:apache ver:2.4.49

# CVE-2021-42013 (路径遍历)
app:apache ver:2.4.50

# 老旧版本
app:apache ver:2.2
```

### Log4j 相关

```bash
# Log4Shell (CVE-2021-44228)
app:log4j ver:2.0-2.14

# 受影响的 Java 应用
app:solr OR app:elasticsearch OR app:struts2
```

### Exchange 相关

```bash
# ProxyLogon/ProxyShell
app:exchange

# 特定版本
app:exchange ver:2013 OR app:exchange ver:2016
```

### 其他高危组件

```bash
# Struts2 (多个 RCE)
app:struts2

# ThinkPHP (RCE)
app:thinkphp

# Weblogic
app:weblogic

# Confluence
app:confluence
```

## 敏感服务发现

### 数据库服务

```bash
# MySQL 公网暴露
app:mysql port:3306 country:CN

# MongoDB 无认证
app:mongodb port:27017

# Redis 公网暴露
app:redis port:6379

# Elasticsearch 公网暴露
app:elasticsearch port:9200

# 组合搜索
(app:mysql OR app:mongodb OR app:redis OR app:elasticsearch) country:CN
```

### 远程管理服务

```bash
# SSH
port:22 country:CN

# RDP
port:3389 os:Windows

# Telnet (高风险)
port:23

# VNC
port:5900
```

### 文件服务

```bash
# FTP 匿名访问
port:21 banner:Anonymous

# SMB
port:445

# NFS
port:2049
```

## IoT 设备发现

### 摄像头

```bash
# 海康威视
app:hikvision

# 大华
app:dahua

# 通用摄像头
device:camera

# RTSP 流
port:554
```

### 路由器

```bash
# 通用路由器
device:router

# 特定品牌
app:mikrotik OR app:cisco OR app:huawei

# 管理端口
port:8080 title:router
```

### 打印机

```bash
# 网络打印机
device:printer

# JetDirect
port:9100
```

### 工控设备

```bash
# Modbus
port:502

# S7comm (Siemens)
port:102

# BACnet
port:47808

# DNP3
port:20000

# EtherNet/IP
port:44818
```

## Web 应用指纹

### CMS 系统

```bash
# WordPress
app:wordpress

# Drupal
app:drupal

# Joomla
app:joomla

# 国产 CMS
app:dedecms OR app:phpcms OR app:discuz
```

### 后台管理

```bash
# 通用后台
title:管理 OR title:admin OR title:后台

# 登录页面
title:登录 OR title:login

# 特定框架后台
app:django title:admin
```

### 特定框架

```bash
# PHP 框架
app:thinkphp OR app:laravel

# Java 框架
app:struts2 OR app:spring

# Python 框架
app:django OR app:flask
```

### 开发/调试页面

```bash
# phpinfo
title:phpinfo

# 调试模式
title:debug OR header:X-Debug

# 默认页面
title:Welcome OR title:test page
```

## 安全设备

```bash
# 防火墙管理界面
app:fortinet OR app:paloalto OR app:checkpoint

# VPN 设备
app:cisco-vpn OR app:openvpn

# WAF
app:cloudflare OR app:akamai
```

## 云服务

```bash
# AWS
org:amazon

# Azure
org:microsoft

# 阿里云
org:alibaba

# 腾讯云
org:tencent
```

## 按地理位置

### 中国分省

```bash
# 北京
country:CN city:Beijing

# 上海
country:CN city:Shanghai

# 广东省
country:CN subdivisions:Guangdong
```

### 特定国家

```bash
# 美国
country:US

# 日本
country:JP

# 韩国
country:KR

# 俄罗斯
country:RU
```

## 排除搜索

```bash
# 排除特定国家
app:nginx -country:US

# 排除特定端口
app:apache -port:443

# 排除特定组织
cidr:10.0.0.0/8 -org:cloudflare
```

## 复杂组合示例

```bash
# 中国境内暴露的数据库
(app:mysql OR app:mongodb OR app:redis) country:CN port:3306,27017,6379

# 特定网段的 Web 服务
cidr:192.168.0.0/16 (port:80 OR port:443 OR port:8080)

# 老旧且暴露的 Windows 服务器
os:Windows (port:3389 OR port:445) -country:US

# 潜在蜜罐检测（多服务同时开放）
port:22 port:23 port:80 port:443 port:3389
```

## 威胁狩猎查询

### 动态DNS服务（高风险C2托管）

```bash
# DuckDNS - 最常被滥用
domain="duckdns.org"

# YDNS - Xworm常用
domain="ydns.eu"

# LinkPC - NjRAT常用
domain="linkpc.net"

# 其他高风险动态DNS
domain="ddns.net"
domain="no-ip.org"
domain="hopto.org"
domain="zapto.org"
domain="servebeer.com"
domain="serveftp.com"
```

### 恶意软件家族C2

#### RAT家族

```bash
# AsyncRAT (端口: 6606, 7707, 8808)
port="6606"
domain="duckdns.org" && port="6606"

# Xworm (端口: 7000, 7777, 8888)
port="7000" && domain="ydns.eu"

# NjRAT (端口: 5552, 1177, 5555)
port="5552"
body="njrat"

# RemCos (端口: 2404, 2405, 4782)
port="4782"
port="2404"

# AgentTesla
port="587" && body="smtp"
```

#### 红队工具

```bash
# Cobalt Strike
ssl="6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C"
port="50050"

# Metasploit Meterpreter
port="4444"

# Sliver C2
port="8888" && ssl="Sliver"
```

#### 僵尸网络

```bash
# Mirai及变种
port="23" || port="2323"
body="mirai"

# Gafgyt/BASHLITE
port="6667"
body="gafgyt"

# MooBot
port="23" || port="37215"

# XorDDoS
body="xor" && port="22"
```

### 恶意基础设施识别

```bash
# 防弹托管常见ASN
asn="48666"
asn="44094"
asn="202425"

# 可疑域名模式
domain="ddos"
domain="botnet"
domain="c2"
domain="rat"

# 多端口开放（可疑/蜜罐）
port="22" && port="23" && port="80" && port="443" && port="3389"
```

### CVE漏洞利用追踪

```bash
# Ivanti Connect Secure
app="ivanti" && port="443"

# MOVEit Transfer
app="moveit"

# Exchange Server
app="exchange"

# Log4j受影响服务
app="solr" || app="elasticsearch" || app="struts2"
```

### 同IP域名关联

```bash
# 搜索特定IP绑定的所有域名
ip="1.2.3.4"

# 判断是否防弹托管：域名数量>100为可疑
```

## MCP工具语法对照

**重要**: 当前MCP工具使用的语法与ZoomEye略有不同

| 用途 | MCP语法 | ZoomEye语法 |
|------|---------|------------|
| IP查询 | `ip="1.2.3.4"` | `ip:1.2.3.4` |
| 域名查询 | `domain="example.com"` | `site:example.com` |
| **子域名搜索** | `hostname="*.example.com"` | `hostname:*.example.com` |
| 端口查询 | `port="443"` | `port:443` |
| Body匹配 | `body="keyword"` | `banner:keyword` |
| 标题匹配 | `title="admin"` | `title:admin` |
| SSL证书 | `ssl="xxx"` | `ssl:xxx` |
| 逻辑与 | `&&` | 空格 |
| 逻辑或 | `\|\|` | `OR` |

### CIDR 网段搜索（重要更正！）

```bash
# ✅ 正确语法 - 使用 cidr= 加引号
cidr="45.74.17.165/24"     # C段搜索
cidr="178.16.55.0/24"      # C段搜索
cidr="10.0.0.0/16"         # B段搜索

# ❌ 错误语法
cidr:192.168.1.0/24        # 冒号语法不支持
ip="192.168.1.0/24"        # ip字段不支持CIDR
```

### 不支持的语法

| 语法 | 状态 | 替代方案 |
|------|------|---------|
| `cidr:x.x.x.0/24` | ❌ 冒号语法不支持 | 改用 `cidr="x.x.x.0/24"` |
| `ip="x.x.x.0/24"` | ❌ ip字段不支持CIDR | 改用 `cidr="x.x.x.0/24"` |
| 组件版本 `app:xxx ver:x.x` | ⚠️ 部分支持 | 用body匹配banner |
| 时间范围 `after:2024-01-01` | ❌ 不支持 | - |
