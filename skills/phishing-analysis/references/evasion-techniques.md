# 钓鱼邮件规避技术检测

攻击者使用多种技术来绕过安全扫描和人工检查。

## 规避技术概览

| 技术 | 描述 | 检测方法 |
|------|------|----------|
| 零字体混淆 | 使用`font-size:0`隐藏文本 | 检测`font.*0.*px`模式 |
| 隐藏元素 | 使用`display:none`或`visibility:hidden` | 检测CSS隐藏属性 |
| 追踪ID嵌入 | 在主题/正文中嵌入十六进制追踪码 | 检测长十六进制串 |
| 空白字符插入 | 使用零宽字符分割关键词 | 检测`\u200b`等字符 |
| HTML注释分割 | 用注释分割敏感词 | 检测`<!--...-->`模式 |
| Base64编码 | 编码恶意内容绕过关键词扫描 | 解码检查隐藏内容 |

## 零字体混淆

攻击者用来分割关键词，绕过扫描：

```html
密<span style="font:0px">tracking123</span>码
<!-- 看起来是"密码"，但扫描器看到的是"密tracking123码" -->
```

## 追踪ID模式

**十六进制格式**
```
主题: 【福利】国庆节假期通知 d22b738d3d49230e
                              ↑ 16位十六进制追踪ID
```

**时间戳格式**
```
主题: 重要通知 @1739186157305#
                ↑ 时间戳追踪ID（@数字#格式）
```

**参数格式**
```
链接: https://xxx.com/track?id=abc123xyz456
```

**隐藏元素中**
```html
<span style="display:none">bd33ee207512b5b2</span>
```

## 合法邮件服务滥用

攻击者常利用合法邮件服务发送钓鱼邮件以绕过安全检测。

| 服务 | 特征头 | 滥用风险指标 |
|------|--------|-------------|
| SendGrid | `X-SG-EID`, `X-SG-ID` | From 域名与服务客户不匹配 |
| Mailchimp | `X-MC-User` | 营销邮件包含凭据请求 |
| Shopify | `X-Shopify-Shop-Domain` | 订单通知但店铺域名可疑 |
| 飞书 | `X-Lms-Pvf` | Message-ID 为 feishu.cn 但 From 不匹配 |
| Amazon SES | `X-SES-Outgoing` | 声称是 Amazon 官方但发件人可疑 |

检测要点：
1. 检查邮件头中的服务商特征头
2. 验证 From 域名是否与服务用户一致
3. 正文极短但有附件 → 高度可疑

## 恶意软件投递邮件特征

| 特征 | 说明 |
|------|------|
| 极短邮件正文 | 仅一句话如"密码是123456" |
| 正文提供解压密码 | "附件密码：20250612" |
| 无问候语/签名 | 缺乏正常商务邮件特征 |
| 密码格式为日期 | 20250612、2025-06-12 |
| 仅包含密码的正文 | 典型恶意投递模式 |
| 要求下载运行 | "请下载并运行附件" |

## 使用脚本检测

```bash
python scripts/evasion_detector.py email.eml
python scripts/evasion_detector.py email.eml --format json
```

## 配置文件

检测规则配置在 `config/detection_rules.toml` 中：
- `[legitimate_services]` - 合法服务滥用检测
- `[evasion_techniques]` - 规避技术检测模式
- `[malware_delivery]` - 恶意投递检测
