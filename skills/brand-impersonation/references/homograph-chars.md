# 同形字符对照表

## 西里尔字母 (Cyrillic)

| 拉丁字母 | 西里尔字母 | Unicode | 示例 |
|----------|-----------|---------|------|
| a | а | U+0430 | аpple.com |
| c | с | U+0441 | сisco.com |
| e | е | U+0435 | microsoftе.com |
| o | о | U+043E | gооgle.com |
| p | р | U+0440 | рaypal.com |
| x | х | U+0445 | хbox.com |
| y | у | U+0443 | уahoo.com |
| B | В | U+0412 | Вank.com |
| H | Н | U+041D | НP.com |
| K | К | U+041A | Кaspersky.com |
| M | М | U+041C | Мicrosoft.com |
| T | Т | U+0422 | Тwitter.com |

## 希腊字母 (Greek)

| 拉丁字母 | 希腊字母 | Unicode | 说明 |
|----------|----------|---------|------|
| A | Α | U+0391 | Alpha |
| B | Β | U+0392 | Beta |
| E | Ε | U+0395 | Epsilon |
| H | Η | U+0397 | Eta |
| I | Ι | U+0399 | Iota |
| K | Κ | U+039A | Kappa |
| M | Μ | U+039C | Mu |
| N | Ν | U+039D | Nu |
| O | Ο | U+039F | Omicron |
| P | Ρ | U+03A1 | Rho |
| T | Τ | U+03A4 | Tau |
| X | Χ | U+03A7 | Chi |
| Y | Υ | U+03A5 | Upsilon |
| Z | Ζ | U+0396 | Zeta |
| o | ο | U+03BF | omicron (小写) |

## 数字替换

| 字母 | 数字 | Unicode | 说明 |
|------|------|---------|------|
| l | 1 | U+0031 | examp1e.com |
| I | 1 | U+0031 | 1BM.com |
| o | 0 | U+0030 | micr0soft.com |
| O | 0 | U+0030 | 0racle.com |
| s | 5 | U+0035 | micro5oft.com |
| S | 5 | U+0035 | 5amsung.com |
| E | 3 | U+0033 | 3bay.com |
| A | 4 | U+0034 | 4mazon.com |
| B | 8 | U+0038 | 8ank.com |
| g | 9 | U+0039 | 9oogle.com |

## 拉丁扩展

| 基础字母 | 变体 | Unicode | 说明 |
|----------|------|---------|------|
| a | ɑ | U+0251 | Latin alpha |
| a | ạ | U+1EA1 | 带点 |
| c | ç | U+00E7 | c-cedilla |
| e | ё | U+0451 | 带分音符 |
| i | ı | U+0131 | 无点 i |
| i | ǐ | U+01D0 | 带抑扬符 |
| n | ñ | U+00F1 | n-tilde |
| o | ø | U+00F8 | o-斜杠 |
| u | ü | U+00FC | u-分音符 |

## 特殊符号

| 字符 | 替换 | Unicode | 说明 |
|------|------|---------|------|
| - | − | U+2212 | 减号 |
| - | ‐ | U+2010 | 连字符 |
| - | ⁃ | U+2043 | 项目符号连字符 |
| . | ․ | U+2024 | 单点引导符 |
| . | 。 | U+3002 | 中文句号 |
| / | ∕ | U+2215 | 除号 |

## 乌克兰语特有

| 拉丁字母 | 乌克兰字母 | Unicode |
|----------|-----------|---------|
| i | і | U+0456 |
| I | І | U+0406 |

## 常见组合攻击

### apple.com 变体
```
аpple.com (西里尔 а)
appIe.com (大写 I)
app1e.com (数字 1)
аррle.com (西里尔 а + р)
apple.сom (西里尔 с)
```

### google.com 变体
```
gооgle.com (西里尔 о)
g00gle.com (数字 0)
googIe.com (大写 I)
googlе.com (西里尔 е)
```

### paypal.com 变体
```
раypal.com (西里尔 р + а)
payраl.com (西里尔 р + а)
раyраl.com (全西里尔)
paypa1.com (数字 1)
```

## 检测方法

### Python 检测代码

```python
import unicodedata
import re

# 同形字映射表
CONFUSABLES = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o',
    'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i',
    'ǐ': 'i', 'ı': 'i', 'ɑ': 'a', 'ο': 'o',
    '1': 'l', '0': 'o', '5': 's', '3': 'e',
    # ... 完整映射
}

def detect_homograph(domain):
    """检测同形字攻击"""
    suspicious_chars = []
    normalized = ""

    for char in domain:
        if char in CONFUSABLES:
            suspicious_chars.append({
                'char': char,
                'unicode': f"U+{ord(char):04X}",
                'looks_like': CONFUSABLES[char]
            })
            normalized += CONFUSABLES[char]
        else:
            normalized += char

    return {
        'original': domain,
        'normalized': normalized,
        'is_suspicious': len(suspicious_chars) > 0,
        'suspicious_chars': suspicious_chars
    }

def is_mixed_script(domain):
    """检测混合脚本"""
    scripts = set()
    for char in domain:
        if char.isalpha():
            script = unicodedata.name(char, '').split()[0]
            scripts.add(script)

    # 正常域名应该只有 LATIN
    return len(scripts) > 1, scripts
```

### 在线工具

- [Unicode Confusables](https://util.unicode.org/UnicodeJsps/confusables.jsp)
- [Punycode Converter](https://www.punycoder.com/)

## Punycode 编码

IDN 域名会被编码为 Punycode：

| 原始 | Punycode |
|------|----------|
| аpple.com | xn--pple-43d.com |
| gооgle.com | xn--ggle-55da.com |
| microsоft.com | xn--microsft-yeb.com |

## 浏览器防护

现代浏览器会检测并显示 Punycode：
- Chrome: 显示 Punycode 而非 Unicode
- Firefox: 对混合脚本域名显示警告
- Safari: 显示安全指示器

## 参考资源

- [Unicode Confusables](https://www.unicode.org/Public/security/latest/confusables.txt)
- [IDN Homograph Attack (Wikipedia)](https://en.wikipedia.org/wiki/IDN_homograph_attack)
