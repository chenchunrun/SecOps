# 同形字攻击检测

## 什么是同形字攻击

同形字攻击（Homograph Attack / IDN Homograph Attack）利用视觉上相似但编码不同的字符来伪造域名，欺骗用户。

## 检测命令

```bash
python scripts/homograph_detector.py "аpple.com"
python scripts/homograph_detector.py "micr0soft.com" --brand-check
```

## 攻击类型

| 攻击类型 | 示例 | 说明 |
|---------|------|------|
| 西里尔字母 | аpple.com (а ≠ a) | Cyrillic 'а' (U+0430) vs Latin 'a' |
| 希腊字母 | Gοοgle.com (ο ≠ o) | Greek 'ο' (U+03BF) vs Latin 'o' |
| 数字替换 | paypa1.com (1 ≠ l) | 数字 '1' vs 字母 'l' |
| 相似字符 | rn vs m | 组合字符看起来像单个字符 |
| 零宽字符 | go​ogle.com | 包含不可见的零宽空格 |

## 常见混淆字符

### 西里尔字母 → 拉丁字母
| 西里尔 | 拉丁 | Unicode |
|--------|------|---------|
| а | a | U+0430 |
| е | e | U+0435 |
| о | o | U+043E |
| р | p | U+0440 |
| с | c | U+0441 |
| у | y | U+0443 |
| х | x | U+0445 |

### 希腊字母 → 拉丁字母
| 希腊 | 拉丁 | Unicode |
|------|------|---------|
| ο | o | U+03BF |
| ν | v | U+03BD |
| α | a | U+03B1 |

### 数字 → 字母
| 数字 | 字母 |
|------|------|
| 0 | O, o |
| 1 | l, I |
| 5 | S |
| 8 | B |

## 品牌仿冒检测

高频仿冒目标：
- **金融**: paypal, chase, wellsfargo, bankofamerica
- **科技**: microsoft, apple, google, amazon, facebook
- **电商**: alibaba, amazon, ebay
- **快递**: fedex, ups, dhl

检测方法：
1. 提取域名主体部分
2. 规范化字符（替换同形字）
3. 计算与品牌列表的编辑距离
4. 编辑距离 ≤ 2 视为可疑

## Punycode 处理

国际化域名在 DNS 中使用 Punycode 编码：
```
аpple.com → xn--pple-43d.com
```

检测步骤：
1. 检查是否以 `xn--` 开头
2. 解码为 Unicode
3. 检查混合脚本（如拉丁+西里尔）
4. 报告可疑字符
