# 二维码钓鱼（Quishing）分析专题

二维码钓鱼（Quishing）是2024-2025年增长最快的攻击向量之一。

## 攻击者使用二维码的原因

- 绕过传统URL扫描和邮件安全网关
- 用户无法预览目标URL
- 移动设备安全防护较弱
- 难以在安全沙箱中自动化分析

## 常见二维码攻击场景

- 伪装成多因素认证（MFA）请求
- 假冒IT部门的密码重置
- 虚假的文档共享链接
- 停车罚单、快递通知等场景

## 分析步骤

1. 从邮件中提取所有图片（附件和内嵌）
2. 扫描图片检测二维码
3. 解码二维码内容（URL、文本、vCard等）
4. 对提取的URL应用标准URL分析流程

## 二维码内容类型

| 类型 | 示例 | 说明 |
|------|------|------|
| URL | `https://evil.com` | 直接导向钓鱼页面 |
| 短链接 | `bit.ly/xxx` | 隐藏真实目标 |
| WiFi | `WIFI:S:FreeWiFi;...` | 可能是恶意热点 |
| vCard | 联系人信息 | 可能包含恶意URL |
| 电话 | `tel:+1900xxx` | 可能是付费号码 |
| 文本 | 任意文本 | 可能包含敏感信息请求 |

## 使用脚本

```bash
# 分析图片中的二维码
python scripts/qr_analyzer.py image.png

# 分析邮件中所有二维码
python scripts/qr_analyzer.py email.eml --format json

# 检查依赖状态
python scripts/qr_analyzer.py --status
```

## 支持的后端

脚本支持多种二维码解码后端：

| 后端 | 安装 | 说明 |
|------|------|------|
| pyzbar | `pip install pyzbar` + libzbar | 最快 |
| qreader | `pip install qreader` | 纯 Python |
| cv2 | `pip install opencv-python` | OpenCV |
