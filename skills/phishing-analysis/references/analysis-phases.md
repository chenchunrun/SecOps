# 钓鱼邮件分析阶段详解

## 第一阶段：邮件头分析

**认证结果检查：**
- SPF（发件人策略框架）- 检查 `Received-SPF` 头
- DKIM（域名密钥识别邮件）- 检查 `DKIM-Signature` 和 `Authentication-Results`
- DMARC（基于域的消息认证）- 检查对齐状态
- ARC（认证接收链）- 验证转发邮件的认证状态

**SPF 结果代码解读：**
| 结果 | 含义 |
|------|------|
| Pass | 发件源已验证为合法 |
| Fail | 未授权的发件源（硬失败） |
| SoftFail | 可能伪造但不确定 |
| Neutral | 无法判断 |
| None | 无SPF记录 |

**路由分析：**
- 从下往上追踪 `Received` 头（最旧的在最下面）
- 识别源IP并与声称的发件域对比
- 检查可疑的中继服务器或匿名化服务

**需标记的头部异常：**
- `Reply-To` 与 `From` 地址不一致
- `Return-Path` 不匹配
- 缺失或格式错误的 `Message-ID`
- 异常的 `X-Mailer` 或 `User-Agent` 值
- `Date` 头中的时区不一致

---

## 第二阶段：内容分析

**社会工程学指标：**
- 紧迫性语言（"需要立即操作"、"账户已暂停"、"24小时内"）
- 权威冒充（CEO、IT部门、法务、政府机构）
- 恐惧/奖励触发器
- 与声称发件人身份不符的语法错误
- 通用问候语vs个性化内容

**AI生成钓鱼的新特征（2024-2025趋势）：**
- 语法和用词质量显著提升，传统错误检测失效
- 高度个性化的内容（基于社交媒体信息）
- 使用文件共享服务的钓鱼攻击增长350%

**视觉欺骗：**
- Logo/品牌不一致
- 显示文本与实际链接中的相似域名
- 隐藏的Unicode字符（同形字攻击）

---

## 第三阶段：链接分析

**URL检查：**
```
显示: secure-login.company.com
实际: secure-login.company.com.attacker.xyz
```

**常见钓鱼URL模式：**
- 子域滥用：`legitimate.com.malicious.xyz`
- 打字错误域名：`micr0soft.com`、`paypa1.com`
- 同形字攻击：`pаypal.com`（使用西里尔字母'а'）
- 长URL中合法域名埋在路径深处
- 基于IP的URL：`http://192.168.1.1/login`
- Data URI：`data:text/html;base64,...`

**IDN同形字攻击检测：**
```
合法: apple.com
伪造: аpple.com (使用西里尔字母 'а')
Punycode: xn--pple-43d.com
```

检测方法：
1. 检查域名是否包含非ASCII字符
2. 解码Punycode（`xn--`前缀）查看真实字符
3. 使用Unicode混淆表（UTS #39）检测可混淆字符

**高风险TLD（免费/廉价域名）：**
`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.work`, `.click`

---

## 第四阶段：附件分析

**文件类型验证：**
- 对比文件扩展名与魔术字节
- 识别双扩展名：`invoice.pdf.exe`
- 检查启用宏的Office文档（.docm, .xlsm）

**高风险文件类型：**
- 可执行文件：.exe, .scr, .bat, .cmd, .ps1, .vbs, .js, .hta, .msi
- 包含可执行文件的压缩包：.zip, .rar, .7z
- 带宏的Office文档：.docm, .xlsm, .pptm
- ISO/IMG磁盘映像
- LNK快捷方式
- HTML走私文件（HTML Smuggling）

**安全分析步骤：**
1. 计算文件哈希（MD5, SHA256）
2. 查询VirusTotal、Hybrid Analysis
3. 在不执行的情况下提取元数据
4. 如存在宏代码则进行分析（使用olevba）

---

## 第五阶段：IOC提取

提取以下威胁指标用于威胁情报：

| IOC类型 | 示例 |
|---------|------|
| IP地址 | 发件人IP、链接目标IP |
| 域名 | 发件人域名、链接域名 |
| URL | 完整恶意URL |
| 邮箱地址 | From、Reply-To、内嵌邮箱 |
| 文件哈希 | 附件的MD5、SHA1、SHA256 |
| 文件名 | 附件名称 |
| 邮件主题 | 用于模式匹配 |

**IOC共享格式：**
- STIX（结构化威胁信息表达）
- TAXII（可信自动化威胁情报交换）
- OpenIOC
- CSV/JSON
