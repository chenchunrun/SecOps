# DGA 检测

> 术语说明：报告中使用“命中/未发现 DGA 特征”描述结果，避免“阳性/阴性”措辞。

## 什么是 DGA

DGA (Domain Generation Algorithm) 是恶意软件用于动态生成 C2 域名的算法，通过生成大量伪随机域名来规避黑名单阻断。

## 检测命令

```bash
python scripts/domain_dga.py qxwz7k2m9p.com
```

## DGA 特征

| 特征 | 说明 | 检测方法 |
|------|------|---------|
| 高熵值 | 随机字符组合 | Shannon 熵 > 3.5 |
| 无意义 | 非词典单词 | 词典匹配 |
| 长度异常 | 过长或特定长度 | 统计分析 |
| 数字混合 | 字母数字混合 | 模式匹配 |
| 辅音堆叠 | 连续辅音 | 语言分析 |

## Shannon 熵计算

熵值范围 0-4.7（对于小写字母域名）：
- < 2.5：可能是有意义的词
- 2.5-3.5：灰色地带
- > 3.5：高度随机，可能是 DGA

## 常见 DGA 家族

| 家族 | 特征 | TLD |
|------|------|-----|
| Conficker | 特定长度 (8-11 字符) | .com/.net/.org/.info/.biz |
| Necurs | 高熵值 | .com/.net/.org |
| Suppobox | 词典组合 | 多种 |
| Cryptolocker | 时间种子 + 特定算法 | .com/.net/.org/.biz/.ru |
| Gameover Zeus | 1000+ 域名/天 | .com/.net/.org/.biz |
| Pykspa | 可读单词组合 | .com/.net |
| Qakbot | 字母数字混合 | .com/.net/.org |

## 检测示例

**高风险域名**:
```
qxwz7k2m9p.com       # 熵值: 3.8, 无意义
a8b2c4d6e0f.net      # 字母数字交替
xkjlmnpqrst.org      # 全辅音
```

**低风险域名**:
```
google.com           # 熵值: 2.1, 品牌
shopping-center.net  # 熵值: 2.8, 有意义
```

## 与威胁情报结合

DGA 检测应与威胁情报查询结合：
1. 本地 DGA 特征检测
2. MCP `risk_insight` 查询
3. 综合判断
