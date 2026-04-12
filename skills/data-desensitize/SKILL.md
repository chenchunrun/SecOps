---
name: data-desensitize
description: 对文档、日志、代码中的敏感信息进行智能识别和脱敏处理，生成可安全分享的版本。当用户要求"数据脱敏"、"脱敏处理"、"PII 脱敏"、"日志脱敏"、"敏感信息替换"、"隐私数据处理"时使用此技能。
metadata:
  version: 1.0.0
  builtin: true
---

# 数据脱敏 (Data Desensitize)

## 核心任务

对文档/日志/代码中的敏感信息进行智能识别和替换，生成可安全分享的脱敏版本，同时保留文档的可读性和上下文关系。

## 脱敏流程

```
1. 读取原始文档
2. 识别敏感信息（见 references/sensitive-types.md）
3. 生成一致性替换（相同值 → 相同占位符）
4. 输出脱敏文档 + 映射表
```

## 敏感信息类型

| 类型 | 标识符 | 示例 |
|------|--------|------|
| 公网 IP | `[PUBLIC_IP_N]` | 8.8.8.8 → [PUBLIC_IP_1] |
| 内网 IP | `[PRIVATE_IP_N]` | 192.168.1.100 → [PRIVATE_IP_1] |
| 域名 | `[DOMAIN_N]` | example.com → [DOMAIN_1] |
| 邮箱 | `[EMAIL_N]` | user@corp.com → [EMAIL_1] |
| 手机号 | `[PHONE_N]` | 13800138000 → [PHONE_1] |
| 身份证 | `[IDCARD_N]` | 110101199001011234 → [IDCARD_1] |
| 银行卡 | `[BANKCARD_N]` | 6222021234567890123 → [BANKCARD_1] |
| API 密钥 | `[APIKEY_N]` | sk-xxx... → [APIKEY_1] |
| 凭据/密码 | `[CREDENTIAL_N]` | password=xxx → [CREDENTIAL_1] |
| 组织名称 | `[ORG_N]` | 某某公司 → [ORG_1] |
| 人名 | `[PERSON_N]` | 张三 → [PERSON_1] |
| 产品名称 | `[PRODUCT_N]` | 某某系统 → [PRODUCT_1] |

详细定义见：[references/sensitive-types.md](references/sensitive-types.md)

## 脱敏规则

### 一致性原则
- **相同的敏感值必须映射到相同的占位符**
- 例：文档中多次出现 `192.168.1.100`，全部替换为 `[PRIVATE_IP_1]`

### 拓扑保留（可选）
- 同子网 IP 脱敏后仍保持同子网关系
- 例：`192.168.1.100` 和 `192.168.1.101` → `[PRIVATE_IP_1]` 和 `[PRIVATE_IP_2]`（暗示同网段）

### 弱口令保留（可选）
- 常见弱口令可保留用于安全分析
- 例：`123456`、`admin`、`password` 保持原样

### 上下文感知
- 根据上下文判断是否为敏感信息
- 例：`version: 1.0.0` 中的数字不是 IP

## 输出格式

### 脱敏文档
直接输出脱敏后的完整文档，保持原格式（Markdown/JSON/YAML/文本）。

### 映射表（文档末尾注释）
```
<!-- DESENSITIZE_MAPPINGS
[PUBLIC_IP_1] = 8.8.8.8
[DOMAIN_1] = example.com
[EMAIL_1] = admin@example.com
-->
```

## 使用方式

### 单文件脱敏
```
用户：请脱敏这个文件 /path/to/doc.md
```

### 批量脱敏
```
用户：脱敏 /path/to/logs/ 目录下所有 .log 文件
```

### 指定脱敏类型
```
用户：只脱敏 IP 和域名，保留其他信息
```

### 带选项脱敏
```
用户：脱敏这个文档，保留弱口令，保持网络拓扑
```

### 并发批量处理
```
用户：并发脱敏这 5 个文件（或：快速批量脱敏）
```
当用户要求并发/并行/快速批量处理时，使用 Task 工具启动多个子代理并行处理：
- 每个子代理处理一个文件
- 主代理汇总结果和全局映射表
- 确保跨文件的一致性映射

## 工作流程

1. **读取文档**：使用 Read 工具读取原始内容
2. **识别敏感信息**：按类型识别所有敏感数据
3. **生成映射**：为每个唯一敏感值分配占位符
4. **执行替换**：替换所有敏感信息
5. **输出结果**：
   - 使用 Write 工具写入脱敏文档（原文件名加 `.desensitized` 后缀或 `.md` 格式）
   - 在文档末尾添加映射表注释

## 示例

见：[references/examples.md](references/examples.md)

## 注意事项

1. **不要过度脱敏**：版本号、端口号、普通数字不是敏感信息
2. **保持可读性**：脱敏后文档仍应易于理解
3. **处理边界情况**：URL 中的域名、日志中的混合格式
4. **大文件分块**：超大文件分块处理，保持映射一致性

## 附加资源

- [敏感类型详细定义](references/sensitive-types.md)
- [脱敏示例](references/examples.md)
