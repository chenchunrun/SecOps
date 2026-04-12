#!/bin/bash
# Linux 挖矿木马检测脚本
# 参考: LinuxCheck - miner_check
# 用法: bash miner_check.sh

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
echo -e "${CYAN}  挖矿木马检测 - $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

ISSUES=0

#===============================================================================
# 已知挖矿程序特征
#===============================================================================

# 挖矿进程名 (匹配进程名列)
MINER_PROCESSES=(
    "xmrig" "xmr-stak" "xmr-stak-cpu" "xmr-stak-rx"
    "minerd" "cpuminer" "cgminer" "bfgminer" "ethminer"
    "ccminer" "nheqminer" "cryptonight"
    "kdevtmpfsi" "kinsing" "kthreaddi" "kthreaddk"
    "dbused" "sysguard" "sysupdate"
    "watchdogs" "ksoftirqds" "pamdicks"
    "solr.sh" "kworkerds" "bioset"
)

# 隐藏进程名 (以点开头的恶意进程，需要精确匹配进程名列)
HIDDEN_PROCESSES=(
    ".sshd" ".rsync" ".x11" ".bing" ".cache"
)

# 需要精确匹配的进程名 (避免误匹配命令行参数)
MINER_EXACT_PROCESSES=(
    "xmr" "monero" "randomx" "networkservice"
)

# 矿池端口
POOL_PORTS=(
    3333 3334 3335 3336 3337
    4444 5555 5556 7777 7778
    8888 8899 9999
    14433 14444 45560 45700
)

# 矿池域名关键词
POOL_KEYWORDS=(
    "pool" "mining" "xmr" "monero" "nicehash"
    "f2pool" "antpool" "poolin" "slush"
    "stratum" "randomx" "cryptonight"
    "nanopool" "supportxmr" "minexmr"
    "hashvault" "herominers" "2miners"
)

#===============================================================================
# 1. 挖矿进程检测
#===============================================================================
print_section "1. 挖矿进程检测"

echo -e "${YELLOW}[已知挖矿程序名]${NC}"
found=false
# 普通匹配 (仅匹配进程名列 $11，避免匹配命令行参数)
for proc in "${MINER_PROCESSES[@]}"; do
    result=$(ps aux 2>/dev/null | awk -v proc="$proc" 'BEGIN{IGNORECASE=1} $11 ~ proc {print}' || true)
    if [[ -n "$result" ]]; then
        echo -e "${RED}[!] 发现可疑进程: $proc${NC}"
        echo "$result"
        found=true
        ISSUES=$((ISSUES + 1))
    fi
done
# 精确匹配 (仅匹配进程名列，避免匹配命令行参数，排除常见合法进程)
for proc in "${MINER_EXACT_PROCESSES[@]}"; do
    # 使用 awk 只匹配第11列(进程名)，忽略大小写，排除浏览器等合法进程
    result=$(ps aux 2>/dev/null | awk -v proc="$proc" 'BEGIN{IGNORECASE=1} $11 ~ proc && $11 !~ /QtWebEngine|chrome|chromium|electron|NetworkService.*mojom/ {print}' || true)
    if [[ -n "$result" ]]; then
        echo -e "${RED}[!] 发现可疑进程: $proc${NC}"
        echo "$result"
        found=true
        ISSUES=$((ISSUES + 1))
    fi
done
# 隐藏进程检测 (精确匹配进程名，排除包含 /usr/ 路径的合法进程)
for proc in "${HIDDEN_PROCESSES[@]}"; do
    # 只匹配以点开头的独立进程名，排除路径中包含该名称的情况
    result=$(ps aux 2>/dev/null | awk -v proc="$proc" '$11 == proc || $11 ~ "^"proc"$" {print}' || true)
    if [[ -n "$result" ]]; then
        echo -e "${RED}[!] 发现隐藏进程: $proc${NC}"
        echo "$result"
        found=true
        ISSUES=$((ISSUES + 1))
    fi
done
$found || echo "未发现已知挖矿进程"

echo -e "\n${YELLOW}[命令行特征检测]${NC}"
suspicious_cmdline=$(ps aux 2>/dev/null | grep -iE 'stratum\+|stratum://|pool\.|xmr\.|monero|cryptonight|randomx|--donate-level|--coin|--algo' | grep -v grep || true)
if [[ -n "$suspicious_cmdline" ]]; then
    echo -e "${RED}[!] 发现矿池相关命令行:${NC}"
    echo "$suspicious_cmdline"
    ISSUES=$((ISSUES + 1))
else
    echo "未发现"
fi

echo -e "\n${YELLOW}[伪装系统进程检测]${NC}"
# 检查 kworker 伪装 (正常 kworker 格式: kworker/0:1 或 kworker/u4:0)
fake_kworker=$(ps aux 2>/dev/null | awk '$11 ~ /kworker[0-9]{2,}/ || $11 ~ /kworker[^\/]/ {print}' || true)
if [[ -n "$fake_kworker" ]]; then
    echo -e "${RED}[!] 发现可疑 kworker 进程:${NC}"
    echo "$fake_kworker"
    ISSUES=$((ISSUES + 1))
else
    echo "未发现伪装进程"
fi

#===============================================================================
# 2. CPU 资源异常检测
#===============================================================================
print_section "2. CPU 资源异常检测"

echo -e "${YELLOW}[CPU 占用 TOP 10]${NC}"
ps aux --sort=-%cpu 2>/dev/null | head -11

echo -e "\n${YELLOW}[CPU 占用 > 80% 的进程]${NC}"
high_cpu=$(ps aux 2>/dev/null | awk 'NR>1 && $3>80 {print $2, $1, $3"%", $11}' || true)
if [[ -n "$high_cpu" ]]; then
    echo -e "${YELLOW}[!] 发现高 CPU 占用进程:${NC}"
    echo "$high_cpu"

    # 检查这些进程的详细信息
    echo -e "\n${YELLOW}[高 CPU 进程详情]${NC}"
    echo "$high_cpu" | awk '{print $1}' | while read pid; do
        if [[ -d "/proc/$pid" ]]; then
            echo "--- PID: $pid ---"
            echo "Exe: $(readlink /proc/$pid/exe 2>/dev/null || echo '无法读取')"
            echo "Cwd: $(readlink /proc/$pid/cwd 2>/dev/null || echo '无法读取')"
            echo "Cmdline: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' | head -c 200)"
            echo ""
        fi
    done
else
    echo "未发现"
fi

echo -e "\n${YELLOW}[系统负载]${NC}"
uptime
cat /proc/loadavg 2>/dev/null

#===============================================================================
# 3. 网络连接检测
#===============================================================================
print_section "3. 矿池连接检测"

echo -e "${YELLOW}[矿池端口连接]${NC}"
for port in "${POOL_PORTS[@]}"; do
    conn=$(ss -tunp 2>/dev/null | grep ":$port" || true)
    if [[ -n "$conn" ]]; then
        echo -e "${RED}[!] 检测到矿池端口 $port 连接:${NC}"
        echo "$conn"
        ISSUES=$((ISSUES + 1))
    fi
done
echo "检查端口: ${POOL_PORTS[*]}"

echo -e "\n${YELLOW}[stratum 协议连接]${NC}"
stratum_conn=$(ss -tunp 2>/dev/null | grep -iE 'stratum|pool|xmr|monero' || true)
if [[ -n "$stratum_conn" ]]; then
    echo -e "${RED}[!] 发现 stratum 协议连接:${NC}"
    echo "$stratum_conn"
    ISSUES=$((ISSUES + 1))
else
    echo "未发现"
fi

echo -e "\n${YELLOW}[外部连接 (非常用端口)]${NC}"
ss -tunp 2>/dev/null | grep ESTAB | grep -vE ':80|:443|:22|:53|:25|:110|:143|:993|:995|127\.|10\.|192\.168\.|172\.' | head -15 || echo "未发现"

#===============================================================================
# 4. DNS 查询检测
#===============================================================================
print_section "4. 矿池 DNS 查询检测"

echo -e "${YELLOW}[/etc/hosts 矿池域名]${NC}"
pool_hosts=$(grep -iE 'pool|mining|xmr|monero|stratum' /etc/hosts 2>/dev/null || true)
if [[ -n "$pool_hosts" ]]; then
    echo -e "${YELLOW}[!] /etc/hosts 中发现矿池相关条目:${NC}"
    echo "$pool_hosts"
else
    echo "未发现"
fi

echo -e "\n${YELLOW}[DNS 缓存/日志检查 (如可用)]${NC}"
# 检查 systemd-resolved
if command -v resolvectl &>/dev/null; then
    resolvectl statistics 2>/dev/null | head -10 || echo "无法获取 DNS 统计"
fi

#===============================================================================
# 5. 挖矿配置文件检测
#===============================================================================
print_section "5. 挖矿配置文件检测"

echo -e "${YELLOW}[常见挖矿配置文件]${NC}"
config_patterns=(
    "config.json"
    "pools.txt"
    "xmrig.json"
    "cpuminer.conf"
    "miner.conf"
    "pool_info"
)

for pattern in "${config_patterns[@]}"; do
    found_files=$(find /tmp /var/tmp /dev/shm /home /root /opt -name "$pattern" 2>/dev/null | head -5 || true)
    if [[ -n "$found_files" ]]; then
        echo -e "${YELLOW}[!] 发现 $pattern:${NC}"
        echo "$found_files"
    fi
done

echo -e "\n${YELLOW}[配置文件内容检测 (stratum/pool)]${NC}"
for dir in /tmp /var/tmp /dev/shm /home /root; do
    if [[ -d "$dir" ]]; then
        suspicious_config=$(grep -rls 'stratum\|pool\|xmr\|monero' "$dir" 2>/dev/null | head -5 || true)
        if [[ -n "$suspicious_config" ]]; then
            echo -e "${RED}[!] 发现可疑配置文件:${NC}"
            echo "$suspicious_config"
            ISSUES=$((ISSUES + 1))
        fi
    fi
done

#===============================================================================
# 6. 挖矿二进制文件检测
#===============================================================================
print_section "6. 挖矿二进制文件检测"

echo -e "${YELLOW}[临时目录可执行文件]${NC}"
for dir in /tmp /var/tmp /dev/shm; do
    execs=$(find "$dir" -type f -executable 2>/dev/null | head -10 || true)
    if [[ -n "$execs" ]]; then
        echo "--- $dir ---"
        echo "$execs"

        # 检查 ELF 文件
        echo "$execs" | while read f; do
            if file "$f" 2>/dev/null | grep -q 'ELF'; then
                size=$(stat -c%s "$f" 2>/dev/null)
                echo -e "${YELLOW}  ELF 文件: $f (大小: $size)${NC}"

                # 检查字符串中是否有矿池特征
                if strings "$f" 2>/dev/null | grep -qiE 'stratum|pool|xmr|monero|randomx'; then
                    echo -e "${RED}  [!] 发现挖矿特征字符串!${NC}"
                    ISSUES=$((ISSUES + 1))
                fi
            fi
        done
    fi
done 2>/dev/null || echo "未发现"

echo -e "\n${YELLOW}[隐藏的可执行文件]${NC}"
hidden_execs=$(find /tmp /var/tmp /dev/shm /home -name '.*' -type f -executable 2>/dev/null | head -10 || true)
if [[ -n "$hidden_execs" ]]; then
    echo -e "${YELLOW}[!] 发现隐藏可执行文件:${NC}"
    echo "$hidden_execs"
else
    echo "未发现"
fi

#===============================================================================
# 7. 定时任务挖矿检测
#===============================================================================
print_section "7. 定时任务挖矿检测"

echo -e "${YELLOW}[Crontab 挖矿特征]${NC}"
cron_miner=$(cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null | grep -vE '^#|^$' | grep -iE 'xmr|miner|pool|stratum|kdevtmpfsi|curl.*\|.*sh|wget.*\|.*bash' || true)
if [[ -n "$cron_miner" ]]; then
    echo -e "${RED}[!] 发现可疑定时任务:${NC}"
    echo "$cron_miner"
    ISSUES=$((ISSUES + 1))
else
    echo "未发现"
fi

echo -e "\n${YELLOW}[Systemd 挖矿服务]${NC}"
for svc in /etc/systemd/system/*.service; do
    [[ -f "$svc" ]] || continue
    if grep -qiE 'xmr|miner|pool|stratum|kdevtmpfsi' "$svc" 2>/dev/null; then
        echo -e "${RED}[!] 可疑服务: $svc${NC}"
        grep -E 'ExecStart|Description' "$svc"
        ISSUES=$((ISSUES + 1))
    fi
done || echo "未发现"

#===============================================================================
# 8. SSH 密钥后门检测 (挖矿常用)
#===============================================================================
print_section "8. SSH 密钥检测 (挖矿常用后门)"

echo -e "${YELLOW}[authorized_keys 检查]${NC}"
for keyfile in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    if [[ -f "$keyfile" ]]; then
        key_count=$(wc -l < "$keyfile" 2>/dev/null)
        echo "--- $keyfile ($key_count 个密钥) ---"

        # 检查可疑注释
        if grep -qiE 'miner|pool|xmr|attack' "$keyfile" 2>/dev/null; then
            echo -e "${RED}[!] 发现可疑密钥注释!${NC}"
            grep -iE 'miner|pool|xmr|attack' "$keyfile"
            ISSUES=$((ISSUES + 1))
        fi

        # 显示最近添加的密钥
        tail -2 "$keyfile" 2>/dev/null
    fi
done 2>/dev/null || echo "未发现"

#===============================================================================
# 9. 已知挖矿木马家族特征
#===============================================================================
print_section "9. 已知挖矿木马家族特征"

echo -e "${YELLOW}[TeamTNT 特征]${NC}"
teamtnt_files=(
    "/var/tmp/.a"
    "/tmp/.x25"
    "/tmp/.iorni"
    "/dev/shm/.x"
)
for f in "${teamtnt_files[@]}"; do
    if [[ -e "$f" ]]; then
        echo -e "${RED}[!] 发现 TeamTNT 特征文件: $f${NC}"
        ISSUES=$((ISSUES + 1))
    fi
done
echo "已检查 ${#teamtnt_files[@]} 个路径"

echo -e "\n${YELLOW}[Kinsing/kdevtmpfsi 特征]${NC}"
kinsing_signs=(
    "/tmp/kdevtmpfsi"
    "/tmp/kinsing"
    "/var/tmp/kinsing"
)
for f in "${kinsing_signs[@]}"; do
    if [[ -e "$f" ]]; then
        echo -e "${RED}[!] 发现 Kinsing 特征: $f${NC}"
        ISSUES=$((ISSUES + 1))
    fi
done
# 检查进程
if ps aux 2>/dev/null | grep -qE 'kdevtmpfsi|kinsing' | grep -v grep; then
    echo -e "${RED}[!] 发现 Kinsing 进程运行中!${NC}"
    ps aux | grep -E 'kdevtmpfsi|kinsing' | grep -v grep
    ISSUES=$((ISSUES + 1))
fi
echo "已检查 ${#kinsing_signs[@]} 个路径"

echo -e "\n${YELLOW}[WatchDog 特征]${NC}"
if ps aux 2>/dev/null | grep -qE 'watchdogs|ksoftirqds' | grep -v grep; then
    echo -e "${RED}[!] 发现 WatchDog 特征进程!${NC}"
    ps aux | grep -E 'watchdogs|ksoftirqds' | grep -v grep
    ISSUES=$((ISSUES + 1))
else
    echo "未发现"
fi

#===============================================================================
# 总结
#===============================================================================
print_section "检测完成"

echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
if [[ $ISSUES -gt 0 ]]; then
    echo -e "${RED}[!] 发现 $ISSUES 项挖矿相关问题${NC}"
    echo ""
    echo -e "${YELLOW}处置建议:${NC}"
    echo "  1. 终止可疑进程: kill -9 <PID>"
    echo "  2. 删除挖矿文件: rm -f /path/to/miner"
    echo "  3. 清理定时任务: crontab -r"
    echo "  4. 检查 SSH 密钥: vim ~/.ssh/authorized_keys"
    echo "  5. 检查 systemd 服务: systemctl disable <service>"
else
    echo -e "${GREEN}[✓] 未发现挖矿木马迹象${NC}"
fi
echo ""
echo -e "${YELLOW}挖矿检测 ATT&CK 映射:${NC}"
echo "  T1496     - Resource Hijacking"
echo "  T1059     - Command and Scripting Interpreter"
echo "  T1053.003 - Cron"
echo "  T1543.002 - Systemd Service"
echo "  T1098.004 - SSH Authorized Keys"
