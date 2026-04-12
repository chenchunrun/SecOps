# PDF 钓鱼检测

## 文本提取

```bash
# 使用内置脚本（推荐）
python3 pdf_extract.py sample.pdf --text

# 或使用 pdftotext
pdftotext sample.pdf -
```

## 钓鱼特征关键词

**紧急性/恐吓话术**:
```
紧急|立即|马上|限时|urgent|immediately|act now
账户.*冻结|账户.*暂停|account.*suspend
24小时|48小时|within .* hours
违规|违法|处罚|法律责任
```

**诱导行为**:
```
点击.*链接|click.*link|点击.*查看
扫描.*二维码|scan.*code
下载.*附件|download.*attachment
登录.*验证|verify.*account
```

**身份伪装**:
```
银行|bank|税务|公安|法院|Microsoft|Apple|Google|Amazon
快递|物流|顺丰|圆通|中通|DHL|FedEx
```

## URL 分析

```bash
# 从内置脚本获取 URL
python3 pdf_scan.py -j sample.pdf | jq '.urls'

# 或手动提取
strings sample.pdf | grep -oE 'https?://[^[:space:]<>"]+' | sort -u
```

## URL 可疑特征

| 特征 | 示例 |
|------|------|
| 指向可执行文件 | `http://x.com/file.exe` |
| 短链接 | `bit.ly/xxx`, `t.co/xxx` |
| IP 地址直连 | `http://1.2.3.4/page` |
| 可疑 TLD | `.tk`, `.ml`, `.xyz`, `.top` |
| 同形字域名 | `paypa1.com`, `micr0soft.com` |
| Data URI | `data:text/html;base64,...` |

## 图像与二维码

```bash
# 提取图像并检测二维码
python3 pdf_extract.py sample.pdf --images --qr
```

**图像分析要点**:
- 二维码检测：可能包含恶意 URL
- 品牌伪造：检查是否伪装知名公司 logo
