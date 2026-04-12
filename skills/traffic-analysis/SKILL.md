---
name: traffic-analysis
description: 当用户要求"分析 PCAP"、"流量分析"、"网络抓包分析"、"检测恶意流量"、"提取网络 IOC"、"分析网络通信"、"C2 检测"、"威胁狩猎"、"事件响应"、"取证分析"时使用此技能。
metadata:
  version: 1.2.0
  builtin: true
---

# 网络流量分析

## 依赖要求

**Python 版本**: 3.8+

**工具发现优先级**（从高到低）：

1. `CYBERSEC_TSHARK_PATH` / `CYBERSEC_CAPINFOS_PATH` 环境变量（应用注入）
2. `shutil.which()` PATH 查找
3. Windows 标准路径：`C:\Program Files\Wireshark\`

**分析引擎优先级**：

| 引擎 | 优先级 | 功能 | 安装方式 |
|------|--------|------|---------|
| tshark | 主引擎 | 完整功能（协议分布/TCP会话/DNS/HTTP/TLS/IOC） | Wireshark 附带 |
| scapy | 兜底引擎 | 基础功能（协议/IP/端口/DNS/TLS SNI/HTTP），无 TCP 会话统计 | `pip install scapy` |

**其他工具**:
| 工具 | 用途 | 发现方式 |
|------|------|---------|
| capinfos | 文件元信息 | wireshark 附带，同 tshark 路径 |
| rg | 内容搜索 | `brew install ripgrep` / PATH |

**安装方式**：
- **Windows（推荐）**：通过应用安装包安装 Wireshark，应用自动注入环境变量
- **macOS**：`brew install wireshark`
- **Linux**：`sudo apt install wireshark`
- **scapy 兜底**：`pip install scapy`（tshark 不可用时自动降级）

## 使用方法

```bash
# 环境检测
python3 <SKILL_DIR>/scripts/check_env.py

# 快速概览（自动选择引擎：tshark > scapy 兜底）
python3 <SKILL_DIR>/scripts/pcap_analyze.py <file.pcap>

# JSON 输出
python3 <SKILL_DIR>/scripts/pcap_analyze.py -j <file.pcap>

# 纯 scapy 兜底（tshark 不可用时手动调用）
python3 <SKILL_DIR>/scripts/pcap_scapy_fallback.py <file.pcap>
```

**自动降级逻辑**：`pcap_analyze.py` 在检测到 tshark 不可用时，自动调用 scapy 进行分析，无需手动切换。

---

## 分析工作流

### Phase 1: 确认目标与概览
```bash
capinfos file.pcap                    # 文件信息
tshark -r file.pcap -q -z io,phs      # 协议分布
tshark -r file.pcap -q -z conv,tcp    # TCP 会话
```

| 目标 | 关注点 | 方法 |
|------|--------|------|
| **恶意软件分析** | C2 通信、外泄、感染链 | 协议分析 + 行为模式 |
| **威胁狩猎** | 异常模式、未知威胁 | 统计分析 + 基线对比 |
| **事件响应** | 时间线、攻击范围 | 时序分析 + 关联 |
| **CTF/取证** | 隐藏数据、flag | 内容搜索 + 文件提取 |

### Phase 2: 快速概览

**获取基本信息：**
```bash
# 文件信息
capinfos file.pcap

# 协议分布
tshark -r file.pcap -q -z io,phs

# 会话统计
tshark -r file.pcap -q -z conv,tcp
```

**关键问题：**
- 时间范围？持续多久？
- 主要协议？TCP/UDP/其他？
- 多少个唯一 IP？内网还是外网？

### Phase 3: 根据目标深入分析

#### 目标 A：恶意软件/C2 分析

**1. 识别 C2 通信模式**
```bash
# 长连接 (C2 常见)
tshark -r file.pcap -q -z conv,tcp | sort -t'|' -k5 -rn | head

# 周期性连接 (Beaconing)
tshark -r file.pcap -Y "tcp.flags.syn==1" -T fields -e frame.time_relative -e ip.dst | sort -n

# 非标准端口的 HTTP/TLS
tshark -r file.pcap -Y "http and tcp.port != 80" -T fields -e ip.dst -e tcp.dstport
tshark -r file.pcap -Y "tls and tcp.port != 443" -T fields -e ip.dst -e tcp.dstport
```

**2. 检查数据外泄**
```bash
# 大量上传 (外泄特征)
tshark -r file.pcap -q -z conv,tcp | awk -F'|' '{if($4>$5) print}'

# FTP 上传
tshark -r file.pcap -Y "ftp.request.command == STOR" -T fields -e ftp.request.arg

# DNS 隧道 (超长查询)
tshark -r file.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | awk 'length>50'
```

**3. 提取文件**
```bash
# tshark 导出 HTTP 对象
tshark -r file.pcap --export-objects http,./exported/

# 导出 FTP 文件
tshark -r file.pcap --export-objects ftp,./exported/

# 导出 SMB 文件
tshark -r file.pcap --export-objects smb,./exported/
```

#### 目标 B：威胁狩猎

**1. 统计异常检测**
```bash
# 连接频率异常 (同一目标大量连接)
tshark -r file.pcap -T fields -e ip.dst | sort | uniq -c | sort -rn | head

# 端口扫描特征 (同一源访问多端口)
tshark -r file.pcap -T fields -e ip.src -e tcp.dstport | sort | uniq | cut -f1 | uniq -c | sort -rn

# 失败连接 (RST/无响应)
tshark -r file.pcap -Y "tcp.flags.rst==1" -T fields -e ip.dst | sort | uniq -c | sort -rn
```

**2. 协议异常检测**
```bash
# 非标准端口 HTTP
tshark -r file.pcap -Y "http and tcp.port != 80 and tcp.port != 8080" -T fields -e ip.dst -e tcp.dstport

# 非标准端口 TLS
tshark -r file.pcap -Y "tls and tcp.port != 443" -T fields -e ip.dst -e tcp.dstport

# DNS 异常 (TXT 记录常用于隧道)
tshark -r file.pcap -Y "dns.qry.type == 16" -T fields -e dns.qry.name
```

#### 目标 C：事件响应

**1. 建立时间线**
```bash
# 首个和最后一个包时间
capinfos -a -e file.pcap

# 按时间排序关键事件
tshark -r file.pcap -Y "http.request or dns.qry.name or tls.handshake" \
  -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info | head -50
```

**2. 确定感染源**
```bash
# 首个外部连接
tshark -r file.pcap -Y "ip.dst != 10.0.0.0/8 and ip.dst != 172.16.0.0/12 and ip.dst != 192.168.0.0/16" \
  -T fields -e frame.time -e ip.src -e ip.dst -c 10
```

**3. 横向移动检测**
```bash
# 内网 SMB/RDP
tshark -r file.pcap -Y "tcp.port==445 or tcp.port==3389" -T fields -e ip.src -e ip.dst | sort -u
```

#### 目标 D：CTF/取证

**1. 搜索关键字**
```bash
# 在 PCAP 中搜索字符串 (使用 rg)
rg -a "flag" file.pcap
rg -a "password|secret|key" file.pcap
rg -a -o "[A-Za-z0-9+/]{20,}={0,2}" file.pcap  # Base64

# tshark 过滤包含特定内容的包
tshark -r file.pcap -Y "frame contains \"flag\""
```

**2. 提取隐藏数据**
```bash
# HTTP 文件
tshark -r file.pcap --export-objects http,./http_files/

# FTP 文件
tshark -r file.pcap --export-objects ftp,./ftp_files/

# 原始 TCP 流
tshark -r file.pcap -z follow,tcp,raw,0 | xxd -r -p > stream0.bin
```

**3. 协议异常**
```bash
# ICMP 隧道
tshark -r file.pcap -Y "icmp" -T fields -e data

# DNS TXT 记录 (常藏数据)
tshark -r file.pcap -Y "dns.txt" -T fields -e dns.txt
```

### Phase 4: IOC 提取与报告

提取 IOC 后按 `references/report-format.md` 输出报告。

---

## 通用异常识别

### 流量模式异常

| 模式 | 正常 | 异常 |
|------|------|------|
| **连接时长** | 短暂请求响应 | 长时间保持连接 |
| **数据方向** | 请求小/响应大 | 请求大/响应小 (外泄) |
| **时间分布** | 工作时间为主 | 凌晨/周末活跃 |
| **连接频率** | 随机间隔 | 固定周期 (信标) |
| **端口使用** | 标准端口 | 高位随机端口 |

### 协议异常

| 协议 | 正常 | 异常 |
|------|------|------|
| **DNS** | 短域名、常见 TLD | 超长域名、奇怪 TLD |
| **HTTP** | GET/POST 常规路径 | 奇怪 URI、大量 POST |
| **TLS** | 知名 CA、常规 SNI | 自签名、IP 直连 |
| **ICMP** | 小数据包 | 大数据包 (隧道) |

---

## IOC 提取清单

分析完成后，提取以下 IOC：

```bash
# IP 地址 (排除内网)
tshark -r file.pcap -T fields -e ip.dst | sort -u | grep -v "^10\.\|^172\.1[6-9]\.\|^172\.2\|^172\.3[01]\.\|^192\.168\."

# 域名 (DNS + TLS SNI)
tshark -r file.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | sort -u
tshark -r file.pcap -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name | sort -u

# URL
tshark -r file.pcap -Y "http.request" -T fields -e http.host -e http.request.uri | sort -u

# User-Agent
tshark -r file.pcap -Y "http.user_agent" -T fields -e http.user_agent | sort -u

# JA3 指纹
tshark -r file.pcap -Y "tls.handshake.type==1" -T fields -e tls.handshake.ja3 | sort -u

# 文件哈希 (提取后计算)
tshark -r file.pcap --export-objects http,./out/ && shasum -a 256 ./out/*
```

---

## 工具速查

| 任务 | 命令 |
|------|------|
| 文件信息 | `capinfos file.pcap` |
| 协议分布 | `tshark -r file.pcap -q -z io,phs` |
| TCP 会话 | `tshark -r file.pcap -q -z conv,tcp` |
| DNS 查询 | `tshark -r file.pcap -Y "dns.qry.name" -T fields -e dns.qry.name` |
| HTTP 请求 | `tshark -r file.pcap -Y "http.request" -T fields -e http.host -e http.request.uri` |
| TLS SNI | `tshark -r file.pcap -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name` |
| 跟踪 TCP 流 | `tshark -r file.pcap -z follow,tcp,ascii,0` |
| 导出文件 | `tshark -r file.pcap --export-objects http,./out/` |
| 内容搜索 | `rg -a "keyword" file.pcap` |

---

## 与其他技能的关联

**分析过程中发现 IOC 时的处理：**

| 提取到的 IOC | 调用的技能 | 说明 |
|-------------|-----------|------|
| C2 IP | `ip-analysis` | 分析回连 IP 威胁情报 |
| C2 域名 | `domain-analysis` | 分析 DNS 查询中的恶意域名 |
| HTTP URL | `url-analysis` | 分析恶意下载链接 |
| Office 文件 | `office-malware-analyzer` | 分析下载的 Office 文档 |
| 可执行文件 | `binary-reverse-engineering` | 分析下载的恶意程序 |

**上游技能**（可能调用本技能）：
- `binary-reverse-engineering` - 动态分析需要抓包
- `ip-analysis` - 分析 IP 关联的流量

**调用时机：**
1. 提取到外部 IP 后，对每个 IP 调用 `ip-analysis`
2. 提取 DNS 查询的域名后，调用 `domain-analysis`
3. 提取 HTTP URL 后，调用 `url-analysis`
4. 导出文件后，根据类型调用对应分析技能
5. 发现可疑可执行文件时，调用 `binary-reverse-engineering`

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 📋 报告格式规范（必读）

---

## AI 建议

发现邮箱地址时，可建议用户使用 `email-osint` 技能进行深入调查。
