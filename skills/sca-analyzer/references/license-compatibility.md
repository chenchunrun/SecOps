# 开源许可证兼容性参考

## 许可证分类

### 宽松型许可证 (Permissive)

| 许可证 | SPDX ID | 说明 | 风险 |
|--------|---------|------|------|
| MIT | MIT | 最宽松，仅要求保留版权声明 | 低 |
| Apache 2.0 | Apache-2.0 | 包含专利授权，需声明修改 | 低 |
| BSD 2-Clause | BSD-2-Clause | 简化版 BSD | 低 |
| BSD 3-Clause | BSD-3-Clause | 禁止使用贡献者名称推广 | 低 |
| ISC | ISC | 类似 MIT，更简洁 | 低 |
| Unlicense | Unlicense | 公共领域 | 低 |
| CC0-1.0 | CC0-1.0 | 公共领域贡献 | 低 |

### 弱 Copyleft 许可证

| 许可证 | SPDX ID | 说明 | 风险 |
|--------|---------|------|------|
| LGPL-2.0 | LGPL-2.0-only | 库可链接，修改需开源 | 中 |
| LGPL-2.1 | LGPL-2.1-only | 库可链接，修改需开源 | 中 |
| LGPL-3.0 | LGPL-3.0-only | 增加专利条款 | 中 |
| MPL-2.0 | MPL-2.0 | 文件级 Copyleft | 中 |
| EPL-1.0 | EPL-1.0 | Eclipse 许可证 | 中 |
| EPL-2.0 | EPL-2.0 | Eclipse 许可证 v2 | 中 |

### 强 Copyleft 许可证

| 许可证 | SPDX ID | 说明 | 风险 |
|--------|---------|------|------|
| GPL-2.0 | GPL-2.0-only | 衍生作品必须开源 | 高 |
| GPL-3.0 | GPL-3.0-only | 增加专利和反规避条款 | 高 |
| AGPL-3.0 | AGPL-3.0-only | 网络使用也触发开源要求 | 高 |

### 商业限制许可证

| 许可证 | 说明 | 风险 |
|--------|------|------|
| SSPL | MongoDB 服务提供者限制 | 高 |
| Commons Clause | 禁止商业销售 | 高 |
| BSL | 时间限制商业使用 | 高 |
| Elastic License | 禁止提供托管服务 | 高 |

## 兼容性矩阵

### 可以组合使用 ✅

```
MIT ──────────┬──────────> MIT
              │
Apache-2.0 ───┼──────────> Apache-2.0
              │
BSD-3-Clause ─┘

LGPL-2.1 ─────────────────> LGPL-2.1 (动态链接)

MPL-2.0 ──────────────────> MPL-2.0 (文件隔离)
```

### 需要注意 ⚠️

```
MIT + GPL-3.0 ──────────> GPL-3.0 (整体使用 GPL)

Apache-2.0 + GPL-2.0 ───> 不兼容! (专利条款冲突)

Apache-2.0 + GPL-3.0 ───> GPL-3.0 (v3 解决了兼容性)

LGPL + 静态链接 ────────> 需要开源或提供对象文件
```

### 不兼容 ❌

| 组合 | 原因 |
|------|------|
| GPL-2.0 + Apache-2.0 | 专利条款冲突 |
| GPL + 闭源 | GPL 要求衍生作品开源 |
| AGPL + SaaS 闭源 | AGPL 网络交互也触发 |
| 任何许可证 + 专有许可 | 除非获得双重授权 |

## 按项目类型选择

### Web 应用 (闭源)

**推荐使用**:
- MIT ✅
- Apache-2.0 ✅
- BSD ✅
- ISC ✅

**谨慎使用**:
- LGPL (动态链接可以)
- MPL (文件隔离可以)

**避免使用**:
- GPL ❌
- AGPL ❌

### 开源库

**推荐使用**:
- MIT (最大兼容性)
- Apache-2.0 (包含专利保护)

### 开源项目 (希望衍生作品也开源)

**推荐使用**:
- GPL-3.0
- AGPL-3.0 (如果是 SaaS)

## 常见问题

### Q: 使用 MIT 依赖需要做什么？
保留原始版权声明和许可证文本即可。

### Q: 使用 Apache-2.0 依赖需要做什么？
1. 保留版权声明和许可证
2. 如有 NOTICE 文件，需包含
3. 标注所有修改

### Q: 使用 GPL 依赖会怎样？
整个项目必须使用 GPL 许可证开源。

### Q: LGPL 动态链接和静态链接的区别？
- 动态链接: 可以保持闭源
- 静态链接: 需要提供对象文件或开源

### Q: 什么是双重授权 (Dual Licensing)？
项目提供两种许可证选择，如 GPL + 商业许可，用户可选择其一。

## 检测工具

### 许可证扫描

```bash
# 使用 licensee (Ruby)
licensee detect /path/to/project

# 使用 license-checker (npm)
npx license-checker --json

# 使用 pip-licenses (Python)
pip-licenses --format=json

# 使用 syft
syft /path/to/project -o spdx-json
```

### 合规检查脚本

```python
# 许可证风险分类
LICENSE_RISK = {
    'MIT': 'low',
    'Apache-2.0': 'low',
    'BSD-2-Clause': 'low',
    'BSD-3-Clause': 'low',
    'ISC': 'low',
    'LGPL-2.0': 'medium',
    'LGPL-2.1': 'medium',
    'LGPL-3.0': 'medium',
    'MPL-2.0': 'medium',
    'GPL-2.0': 'high',
    'GPL-3.0': 'high',
    'AGPL-3.0': 'high',
    'UNKNOWN': 'high',
}

def check_license_compliance(licenses: list, project_type: str = 'closed') -> dict:
    """检查许可证合规性"""
    issues = []
    for lic in licenses:
        risk = LICENSE_RISK.get(lic, 'high')
        if project_type == 'closed' and lic in ['GPL-2.0', 'GPL-3.0', 'AGPL-3.0']:
            issues.append({
                'license': lic,
                'issue': 'GPL family not compatible with closed source',
                'severity': 'critical'
            })
    return {'compliant': len(issues) == 0, 'issues': issues}
```

## 参考资源

- [SPDX License List](https://spdx.org/licenses/)
- [Choose a License](https://choosealicense.com/)
- [TLDRLegal](https://tldrlegal.com/)
- [OSI Approved Licenses](https://opensource.org/licenses/)
- [FSF License List](https://www.gnu.org/licenses/license-list.html)
