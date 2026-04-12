# 邮箱服务商情报参考

## 中国服务商

### QQ 邮箱 (@qq.com)

| 特征 | 说明 |
|------|------|
| **用户名格式** | 纯数字 = QQ号，字母 = 自定义 |
| **关联服务** | QQ、微信、腾讯系全产品 |
| **用户群体** | 中国主流用户 |

**情报提取**:
```bash
# QQ 头像 (多尺寸)
https://q1.qlogo.cn/g?b=qq&nk={QQ号}&s=40   # 小
https://q1.qlogo.cn/g?b=qq&nk={QQ号}&s=100  # 中
https://q1.qlogo.cn/g?b=qq&nk={QQ号}&s=640  # 大

# QQ 空间
https://user.qzone.qq.com/{QQ号}

# QQ 音乐
https://y.qq.com/n/ryqq/profile/like/song?uin={QQ号}
```

**QQ 号年龄推测**:
| 位数 | 注册年份 |
|------|----------|
| 5 位 | 1999-2000 |
| 6 位 | 2000-2003 |
| 7 位 | 2003-2006 |
| 8 位 | 2006-2008 |
| 9 位 | 2008-2012 |
| 10+ 位 | 2012+ |

---

### 163 邮箱 (@163.com, @126.com, @yeah.net)

| 特征 | 说明 |
|------|------|
| **运营商** | 网易 |
| **关联服务** | 网易云音乐、网易游戏、有道 |
| **用户群体** | 中国用户，较早期 |

**情报提取**:
```bash
# 网易云音乐 (需搜索)
https://music.163.com/#/search/m/?s={用户名}&type=1002
```

---

### 新浪邮箱 (@sina.com, @sina.cn)

| 特征 | 说明 |
|------|------|
| **关联服务** | 微博 |
| **用户群体** | 微博用户 |

---

### 阿里邮箱 (@aliyun.com)

| 特征 | 说明 |
|------|------|
| **关联服务** | 淘宝、支付宝、阿里云 |
| **用户群体** | 阿里系用户、开发者 |

---

## 国际服务商

### Gmail (@gmail.com)

| 特征 | 说明 |
|------|------|
| **运营商** | Google |
| **关联服务** | YouTube、Google Drive、Android |
| **用户群体** | 国际用户、技术人员 |

**情报提取**:
```bash
# Google 账号页 (需登录状态)
https://www.google.com/search?q="{邮箱}"

# Google Scholar (如有学术成果)
https://scholar.google.com/citations?user={用户ID}
```

---

### Outlook/Hotmail (@outlook.com, @hotmail.com, @live.com)

| 特征 | 说明 |
|------|------|
| **运营商** | Microsoft |
| **关联服务** | Office365、Xbox、Skype |
| **用户群体** | 企业用户、游戏玩家 |

---

### ProtonMail (@proton.me, @protonmail.com, @pm.me)

| 特征 | 说明 |
|------|------|
| **运营商** | Proton AG (瑞士) |
| **特点** | 端到端加密、隐私优先 |
| **用户群体** | 隐私意识强、安全从业者、记者 |

**holehe 特殊信息**:
- 可获取账号创建时间

**画像推断**:
- 使用 ProtonMail 表明用户有较高隐私意识
- 可能从事安全相关工作

---

### Tutanota (@tutanota.com, @tuta.io)

| 特征 | 说明 |
|------|------|
| **运营商** | Tutanota (德国) |
| **特点** | 端到端加密 |
| **用户群体** | 极高隐私意识 |

---

### iCloud (@icloud.com, @me.com)

| 特征 | 说明 |
|------|------|
| **运营商** | Apple |
| **关联服务** | Apple 生态 |
| **用户群体** | Apple 设备用户 |

---

## 企业/教育邮箱

### 企业邮箱 (@company.com)

**情报价值**:
- 域名 → 公司信息
- 用户名格式 → 命名规则
- 可关联 `domain-analysis` 技能

**常见格式**:
| 格式 | 示例 |
|------|------|
| 名.姓 | john.doe@company.com |
| 名首字母+姓 | jdoe@company.com |
| 姓名拼音 | zhangsan@company.com |

---

### 教育邮箱 (@xxx.edu, @xxx.edu.cn)

**情报价值**:
- 学校信息
- 可能是学生或教职工
- 常有教育优惠账号

---

## 临时邮箱识别

**常见临时邮箱域名**:
```
@10minutemail.com
@guerrillamail.com
@temp-mail.org
@mailinator.com
@yopmail.com
@throwaway.email
```

**特征**: 用户隐私意识极高或进行可疑活动

---

## 邮箱隐私等级

| 等级 | 服务商 | 说明 |
|------|--------|------|
| 🔴 极高 | ProtonMail, Tutanota | 加密邮箱 |
| 🟠 高 | Gmail (2FA) | 主流安全 |
| 🟡 中 | Outlook, iCloud | 主流 |
| 🟢 低 | QQ, 163 | 关联丰富 |
| ⚫ 可疑 | 临时邮箱 | 可能隐藏身份 |
