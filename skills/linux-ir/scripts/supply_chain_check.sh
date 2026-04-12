#!/bin/bash
# Linux 供应链安全检测脚本
# 参考: LinuxCheck - poison_check, risk_check
# 用法: bash supply_chain_check.sh

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

print_section() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  供应链安全检测 - $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

ISSUES=0

#===============================================================================
# 1. Python pip 投毒检测 (参考 LinuxCheck)
#===============================================================================
print_section "1. Python pip 投毒检测"

# 已知恶意包列表
MALICIOUS_PACKAGES=(
    "python3-dateutil"      # 仿冒 python-dateutil
    "jeIlyfish"             # 仿冒 jellyfish (使用大写I)
    "python-sqlite"         # 恶意包
    "libpeshnern"           # 恶意包
    "libpeshka"             # 恶意包
    "libari"                # 恶意包
    "libtoolz"              # 恶意包
    "libzeffyr"             # 恶意包
    "colourfull"            # 仿冒 colorful
    "beautifulsup4"         # 仿冒 beautifulsoup4
    "cllorama"              # 仿冒 colorama
    "craborern"             # 恶意包
    "colourama"             # 仿冒 colorama
    "djanga"                # 仿冒 django
    "ffloaps"               # 恶意包
    "httplib3"              # 仿冒 httplib2
    "numpyx"                # 仿冒 numpy
    "maratlib"              # 恶意包
    "maratlib1"             # 恶意包
    "matlolib"              # 仿冒 matplotlib
    "openvc"                # 仿冒 opencv
    "opencv-python4"        # 仿冒 opencv-python
    "pipsqlite"             # 恶意包
    "pylogging"             # 恶意包
    "pysqlite2"             # 恶意包
    "pysqlite3"             # 恶意包
    "pywget"                # 恶意包
    "requests-toolbelt"     # 需要检查版本
    "setup-tools"           # 仿冒 setuptools
    "sqlitedict"            # 恶意包
    "virtualnv"             # 仿冒 virtualenv
    "virtaulenv"            # 仿冒 virtualenv
)

echo -e "${YELLOW}[pip 包检查]${NC}"
if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
    PIP_CMD=$(command -v pip3 || command -v pip)
    installed_packages=$($PIP_CMD list --format=freeze 2>/dev/null | cut -d= -f1 | tr '[:upper:]' '[:lower:]')

    found_malicious=false
    for pkg in "${MALICIOUS_PACKAGES[@]}"; do
        pkg_lower=$(echo "$pkg" | tr '[:upper:]' '[:lower:]')
        if echo "$installed_packages" | grep -qx "$pkg_lower"; then
            echo -e "${RED}[!] 发现可疑包: $pkg${NC}"
            $PIP_CMD show "$pkg" 2>/dev/null | grep -E 'Name|Version|Location'
            found_malicious=true
            ((ISSUES++))
        fi
    done

    if ! $found_malicious; then
        echo "未发现已知恶意包"
    fi

    echo -e "\n${YELLOW}[pip 包安装位置检查]${NC}"
    # 检查是否有包安装在异常位置
    $PIP_CMD list --format=freeze 2>/dev/null | head -5
    echo "... (共 $($PIP_CMD list 2>/dev/null | wc -l) 个包)"
else
    echo "pip 未安装"
fi

echo -e "\n${YELLOW}[pypi 包最近安装 (site-packages)]${NC}"
for site in /usr/lib/python*/site-packages /usr/local/lib/python*/site-packages ~/.local/lib/python*/site-packages; do
    if [[ -d "$site" ]]; then
        recent=$(find "$site" -maxdepth 1 -type d -mtime -7 2>/dev/null | head -5)
        if [[ -n "$recent" ]]; then
            echo "--- $site (最近7天) ---"
            echo "$recent"
        fi
    fi
done 2>/dev/null || echo "未发现"

#===============================================================================
# 2. npm 包检测
#===============================================================================
print_section "2. npm 包检测"

if command -v npm &>/dev/null; then
    echo -e "${YELLOW}[全局 npm 包]${NC}"
    npm list -g --depth=0 2>/dev/null | head -15 || echo "无法列出"

    echo -e "\n${YELLOW}[可疑 npm 包名]${NC}"
    npm list -g --depth=0 2>/dev/null | grep -iE 'crypto|wallet|password|stealer|logger' || echo "未发现"
else
    echo "npm 未安装"
fi

#===============================================================================
# 3. Redis 未授权访问检测 (参考 LinuxCheck)
#===============================================================================
print_section "3. Redis 安全检测"

echo -e "${YELLOW}[Redis 服务检测]${NC}"
if ss -tlnp 2>/dev/null | grep -q ':6379'; then
    echo -e "${YELLOW}[!] Redis 服务运行中 (端口 6379)${NC}"
    ss -tlnp | grep ':6379'

    # 检查是否绑定到 0.0.0.0
    if ss -tlnp | grep ':6379' | grep -q '0.0.0.0'; then
        echo -e "${RED}[!] 警告: Redis 绑定到所有接口 (0.0.0.0)${NC}"
        ((ISSUES++))
    fi

    # 检查 Redis 配置
    if command -v redis-cli &>/dev/null; then
        echo -e "\n${YELLOW}[Redis 配置检查]${NC}"
        # 尝试无密码连接
        if redis-cli ping 2>/dev/null | grep -q PONG; then
            echo -e "${RED}[!] 危险: Redis 无需密码即可访问!${NC}"
            ((ISSUES++))

            # 检查危险配置
            echo "当前 dbfilename: $(redis-cli config get dbfilename 2>/dev/null | tail -1)"
            echo "当前 dir: $(redis-cli config get dir 2>/dev/null | tail -1)"
        else
            echo "Redis 需要密码认证 (正常)"
        fi
    fi

    # 检查 Redis 配置文件
    echo -e "\n${YELLOW}[Redis 配置文件]${NC}"
    for conf in /etc/redis/redis.conf /etc/redis.conf; do
        if [[ -r "$conf" ]]; then
            echo "--- $conf ---"
            grep -E '^(bind|requirepass|protected-mode)' "$conf" 2>/dev/null || echo "未找到安全配置"
        fi
    done
else
    echo "Redis 未运行或未监听 6379 端口"
fi

#===============================================================================
# 4. JDWP 调试端口检测 (参考 LinuxCheck)
#===============================================================================
print_section "4. JDWP 调试端口检测"

echo -e "${YELLOW}[JDWP 端口 (5005/8000/8787/9999)]${NC}"
jdwp_ports=$(ss -tlnp 2>/dev/null | grep -E ':5005|:8000|:8787|:9999' || true)
if [[ -n "$jdwp_ports" ]]; then
    echo -e "${YELLOW}[!] 检测到可能的 JDWP 调试端口:${NC}"
    echo "$jdwp_ports"

    # 检查进程
    echo -e "\n${YELLOW}[相关 Java 进程]${NC}"
    ps aux 2>/dev/null | grep -E 'java.*jdwp|java.*agentlib:jdwp' | grep -v grep || echo "未发现 JDWP 参数"
else
    echo "未发现 JDWP 调试端口"
fi

echo -e "\n${YELLOW}[Java 进程调试参数检查]${NC}"
jdwp_procs=$(ps aux 2>/dev/null | grep -E 'agentlib:jdwp|Xdebug|Xrunjdwp' | grep -v grep || true)
if [[ -n "$jdwp_procs" ]]; then
    echo -e "${RED}[!] 发现启用 JDWP 的 Java 进程:${NC}"
    echo "$jdwp_procs"
    ((ISSUES++))
else
    echo "未发现"
fi

#===============================================================================
# 5. 数据库未授权访问检测
#===============================================================================
print_section "5. 数据库服务检测"

echo -e "${YELLOW}[MongoDB (27017)]${NC}"
if ss -tlnp 2>/dev/null | grep -q ':27017'; then
    echo -e "${YELLOW}[!] MongoDB 运行中${NC}"
    ss -tlnp | grep ':27017'
    if ss -tlnp | grep ':27017' | grep -q '0.0.0.0'; then
        echo -e "${RED}[!] 警告: MongoDB 绑定到所有接口${NC}"
        ((ISSUES++))
    fi
else
    echo "未运行"
fi

echo -e "\n${YELLOW}[Elasticsearch (9200)]${NC}"
if ss -tlnp 2>/dev/null | grep -q ':9200'; then
    echo -e "${YELLOW}[!] Elasticsearch 运行中${NC}"
    ss -tlnp | grep ':9200'
    if ss -tlnp | grep ':9200' | grep -q '0.0.0.0'; then
        echo -e "${RED}[!] 警告: Elasticsearch 绑定到所有接口${NC}"
        ((ISSUES++))
    fi
else
    echo "未运行"
fi

echo -e "\n${YELLOW}[Memcached (11211)]${NC}"
if ss -tlnp 2>/dev/null | grep -q ':11211'; then
    echo -e "${YELLOW}[!] Memcached 运行中${NC}"
    ss -tlnp | grep ':11211'
else
    echo "未运行"
fi

echo -e "\n${YELLOW}[MySQL (3306)]${NC}"
if ss -tlnp 2>/dev/null | grep -q ':3306'; then
    echo "MySQL 运行中"
    ss -tlnp | grep ':3306' | head -1
else
    echo "未运行"
fi

echo -e "\n${YELLOW}[PostgreSQL (5432)]${NC}"
if ss -tlnp 2>/dev/null | grep -q ':5432'; then
    echo "PostgreSQL 运行中"
    ss -tlnp | grep ':5432' | head -1
else
    echo "未运行"
fi

#===============================================================================
# 6. Docker Remote API 检测 (参考 LinuxCheck)
#===============================================================================
print_section "6. Docker Remote API 检测"

echo -e "${YELLOW}[Docker API 端口 (2375/2376)]${NC}"
if ss -tlnp 2>/dev/null | grep -qE ':2375|:2376'; then
    echo -e "${RED}[!] 检测到 Docker Remote API:${NC}"
    ss -tlnp | grep -E ':2375|:2376'
    ((ISSUES++))

    # 检查是否可以无认证访问
    if curl -s --connect-timeout 2 http://127.0.0.1:2375/version &>/dev/null; then
        echo -e "${RED}[!] 危险: Docker API 无需认证即可访问!${NC}"
    fi
else
    echo "未发现暴露的 Docker API"
fi

echo -e "\n${YELLOW}[Docker daemon.json 配置]${NC}"
if [[ -r /etc/docker/daemon.json ]]; then
    cat /etc/docker/daemon.json | head -20
else
    echo "配置文件不存在或无权限"
fi

#===============================================================================
# 7. HTTP 服务敏感信息检测
#===============================================================================
print_section "7. Web 服务检测"

echo -e "${YELLOW}[运行中的 Web 服务]${NC}"
ss -tlnp 2>/dev/null | grep -E ':80|:443|:8080|:8443|:3000|:8000' | head -10 || echo "未发现"

echo -e "\n${YELLOW}[敏感配置文件暴露检查]${NC}"
for path in /var/www /opt /srv; do
    if [[ -d "$path" ]]; then
        find "$path" -name '*.env' -o -name '.env*' -o -name 'config.php' -o -name 'database.yml' \
            -o -name 'settings.py' -o -name 'application.properties' 2>/dev/null | head -10
    fi
done || echo "未发现"

#===============================================================================
# 8. Git 凭据泄露检测
#===============================================================================
print_section "8. Git 凭据检测"

echo -e "${YELLOW}[.git 目录检测 (Web 目录)]${NC}"
find /var/www /opt /srv -name '.git' -type d 2>/dev/null | head -10 || echo "未发现"

echo -e "\n${YELLOW}[Git 凭据文件]${NC}"
find /home /root -name '.git-credentials' 2>/dev/null | while read f; do
    echo -e "${YELLOW}[!] 发现 Git 凭据: $f${NC}"
done || echo "未发现"

echo -e "\n${YELLOW}[SSH 私钥 (无密码保护)]${NC}"
for key in /home/*/.ssh/id_* /root/.ssh/id_*; do
    if [[ -f "$key" ]] && [[ ! "$key" =~ \.pub$ ]]; then
        if head -2 "$key" 2>/dev/null | grep -q "ENCRYPTED"; then
            echo "$key - 已加密"
        else
            echo -e "${YELLOW}[!] $key - 未加密${NC}"
        fi
    fi
done 2>/dev/null || echo "未发现"

#===============================================================================
# 总结
#===============================================================================
print_section "检测完成"

echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
if [[ $ISSUES -gt 0 ]]; then
    echo -e "${RED}[!] 发现 $ISSUES 项安全问题${NC}"
else
    echo -e "${GREEN}[✓] 未发现明显供应链安全问题${NC}"
fi
echo ""
echo -e "${YELLOW}供应链安全 ATT&CK 映射:${NC}"
echo "  T1195.001 - Compromise Software Dependencies"
echo "  T1195.002 - Compromise Software Supply Chain"
echo "  T1059.006 - Python"
echo "  T1552.001 - Credentials in Files"
