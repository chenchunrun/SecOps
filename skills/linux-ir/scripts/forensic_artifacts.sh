#!/bin/bash
# Linux 取证数据采集脚本
# 用法: bash forensic_artifacts.sh [输出目录]

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# 输出目录
OUTPUT_DIR="${1:-/tmp/forensic_$(hostname)_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTPUT_DIR"

print_section() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Linux 取证数据采集 - $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${CYAN}  输出目录: $OUTPUT_DIR${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

#===============================================================================
# 1. 系统信息采集
#===============================================================================
print_section "1. 系统信息采集"

echo -e "${YELLOW}[系统基本信息]${NC}"
{
    echo "=== 采集时间 ==="
    date '+%Y-%m-%d %H:%M:%S %Z'
    echo ""
    echo "=== 主机名 ==="
    hostname
    echo ""
    echo "=== 系统版本 ==="
    cat /etc/os-release 2>/dev/null || cat /etc/*release 2>/dev/null
    echo ""
    echo "=== 内核版本 ==="
    uname -a
    echo ""
    echo "=== 运行时间 ==="
    uptime
    echo ""
    echo "=== 时区 ==="
    timedatectl 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "N/A"
} > "$OUTPUT_DIR/system_info.txt"
echo "  已保存: system_info.txt"

#===============================================================================
# 2. 用户与认证信息
#===============================================================================
print_section "2. 用户与认证信息"

echo -e "${YELLOW}[用户信息]${NC}"
{
    echo "=== /etc/passwd ==="
    cat /etc/passwd
    echo ""
    echo "=== /etc/group ==="
    cat /etc/group
    echo ""
    echo "=== /etc/shadow (如有权限) ==="
    cat /etc/shadow 2>/dev/null || echo "无权限"
    echo ""
    echo "=== sudoers ==="
    cat /etc/sudoers 2>/dev/null || echo "无权限"
    ls -la /etc/sudoers.d/ 2>/dev/null
    cat /etc/sudoers.d/* 2>/dev/null || true
} > "$OUTPUT_DIR/users.txt"
echo "  已保存: users.txt"

echo -e "${YELLOW}[登录历史]${NC}"
{
    echo "=== last (最近登录) ==="
    last -50 2>/dev/null || echo "无法获取"
    echo ""
    echo "=== lastb (失败登录) ==="
    lastb -50 2>/dev/null || echo "无权限或无记录"
    echo ""
    echo "=== lastlog ==="
    lastlog 2>/dev/null || echo "无法获取"
    echo ""
    echo "=== who ==="
    who 2>/dev/null
    echo ""
    echo "=== w ==="
    w 2>/dev/null
} > "$OUTPUT_DIR/login_history.txt"
echo "  已保存: login_history.txt"

echo -e "${YELLOW}[SSH Keys]${NC}"
{
    echo "=== authorized_keys ==="
    find /home /root -name 'authorized_keys' -exec echo "--- {} ---" \; -exec cat {} \; 2>/dev/null
    echo ""
    echo "=== known_hosts ==="
    find /home /root -name 'known_hosts' -exec echo "--- {} ---" \; -exec cat {} \; 2>/dev/null
} > "$OUTPUT_DIR/ssh_keys.txt"
echo "  已保存: ssh_keys.txt"

#===============================================================================
# 3. 进程信息
#===============================================================================
print_section "3. 进程信息"

echo -e "${YELLOW}[进程列表]${NC}"
{
    echo "=== ps auxwwf ==="
    ps auxwwf 2>/dev/null
    echo ""
    echo "=== ps 环境变量 ==="
    ps ewwo pid,args 2>/dev/null | head -100
} > "$OUTPUT_DIR/processes.txt"
echo "  已保存: processes.txt"

echo -e "${YELLOW}[进程详细信息]${NC}"
mkdir -p "$OUTPUT_DIR/proc_details"
for pid in $(ps -eo pid --no-headers 2>/dev/null | head -50); do
    pid=$(echo $pid | tr -d ' ')
    [[ -d "/proc/$pid" ]] || continue
    {
        echo "PID: $pid"
        echo "Cmdline: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
        echo "Exe: $(readlink /proc/$pid/exe 2>/dev/null)"
        echo "Cwd: $(readlink /proc/$pid/cwd 2>/dev/null)"
        echo "Environ: $(cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | head -20)"
        echo "---"
    } >> "$OUTPUT_DIR/proc_details/top50_procs.txt" 2>/dev/null
done
echo "  已保存: proc_details/"

#===============================================================================
# 4. 网络信息
#===============================================================================
print_section "4. 网络信息"

echo -e "${YELLOW}[网络连接]${NC}"
{
    echo "=== ss -tunpa ==="
    ss -tunpa 2>/dev/null || netstat -tunpa 2>/dev/null
    echo ""
    echo "=== ss -lnp ==="
    ss -lnp 2>/dev/null
} > "$OUTPUT_DIR/network_connections.txt"
echo "  已保存: network_connections.txt"

echo -e "${YELLOW}[网络配置]${NC}"
{
    echo "=== ip addr ==="
    ip addr 2>/dev/null || ifconfig -a 2>/dev/null
    echo ""
    echo "=== ip route ==="
    ip route 2>/dev/null || route -n 2>/dev/null
    echo ""
    echo "=== /etc/resolv.conf ==="
    cat /etc/resolv.conf 2>/dev/null
    echo ""
    echo "=== /etc/hosts ==="
    cat /etc/hosts 2>/dev/null
    echo ""
    echo "=== iptables ==="
    iptables -L -n -v 2>/dev/null || echo "无权限"
    echo ""
    echo "=== ARP 表 ==="
    ip neigh 2>/dev/null || arp -a 2>/dev/null
} > "$OUTPUT_DIR/network_config.txt"
echo "  已保存: network_config.txt"

#===============================================================================
# 5. 持久化配置
#===============================================================================
print_section "5. 持久化配置"

echo -e "${YELLOW}[Systemd 服务]${NC}"
{
    echo "=== 已启用的服务 ==="
    systemctl list-unit-files --state=enabled 2>/dev/null
    echo ""
    echo "=== 运行中的服务 ==="
    systemctl list-units --type=service --state=running 2>/dev/null
    echo ""
    echo "=== 失败的服务 ==="
    systemctl list-units --type=service --state=failed 2>/dev/null
    echo ""
    echo "=== Timers ==="
    systemctl list-timers --all 2>/dev/null
} > "$OUTPUT_DIR/systemd_services.txt"
echo "  已保存: systemd_services.txt"

# 复制可疑 service 文件
mkdir -p "$OUTPUT_DIR/systemd_units"
find /etc/systemd/system -name '*.service' -mtime -30 -exec cp {} "$OUTPUT_DIR/systemd_units/" \; 2>/dev/null
echo "  已复制最近修改的 service 文件"

echo -e "${YELLOW}[Crontab]${NC}"
{
    echo "=== /etc/crontab ==="
    cat /etc/crontab 2>/dev/null
    echo ""
    echo "=== /etc/cron.d/* ==="
    for f in /etc/cron.d/*; do
        [[ -f "$f" ]] && echo "--- $f ---" && cat "$f"
    done 2>/dev/null
    echo ""
    echo "=== 用户 crontab ==="
    for f in /var/spool/cron/crontabs/*; do
        [[ -f "$f" ]] && echo "--- $f ---" && cat "$f" 2>/dev/null
    done
} > "$OUTPUT_DIR/crontabs.txt"
echo "  已保存: crontabs.txt"

echo -e "${YELLOW}[Shell 配置]${NC}"
{
    echo "=== /etc/profile ==="
    cat /etc/profile 2>/dev/null
    echo ""
    echo "=== /etc/profile.d/* ==="
    for f in /etc/profile.d/*.sh; do
        [[ -f "$f" ]] && echo "--- $f ---" && cat "$f"
    done 2>/dev/null
    echo ""
    echo "=== /etc/bash.bashrc ==="
    cat /etc/bash.bashrc 2>/dev/null || cat /etc/bashrc 2>/dev/null
} > "$OUTPUT_DIR/shell_config.txt"
echo "  已保存: shell_config.txt"

#===============================================================================
# 6. 日志采集
#===============================================================================
print_section "6. 日志采集"

mkdir -p "$OUTPUT_DIR/logs"

echo -e "${YELLOW}[认证日志]${NC}"
for log in /var/log/auth.log /var/log/secure; do
    if [[ -r "$log" ]]; then
        tail -5000 "$log" > "$OUTPUT_DIR/logs/$(basename $log)" 2>/dev/null
        echo "  已采集: $(basename $log)"
    fi
done

echo -e "${YELLOW}[系统日志]${NC}"
for log in /var/log/syslog /var/log/messages /var/log/kern.log; do
    if [[ -r "$log" ]]; then
        tail -5000 "$log" > "$OUTPUT_DIR/logs/$(basename $log)" 2>/dev/null
        echo "  已采集: $(basename $log)"
    fi
done

echo -e "${YELLOW}[审计日志]${NC}"
if [[ -r /var/log/audit/audit.log ]]; then
    tail -10000 /var/log/audit/audit.log > "$OUTPUT_DIR/logs/audit.log" 2>/dev/null
    echo "  已采集: audit.log"
else
    echo "  audit.log 不存在或无权限"
fi

echo -e "${YELLOW}[Journald]${NC}"
{
    echo "=== 最近 1 天的 journal ==="
    journalctl --since "1 day ago" --no-pager 2>/dev/null | tail -5000
} > "$OUTPUT_DIR/logs/journald.txt" 2>/dev/null
echo "  已采集: journald.txt"

echo -e "${YELLOW}[Web 服务器日志]${NC}"
for log in /var/log/apache2/access.log /var/log/apache2/error.log \
           /var/log/nginx/access.log /var/log/nginx/error.log \
           /var/log/httpd/access_log /var/log/httpd/error_log; do
    if [[ -r "$log" ]]; then
        tail -5000 "$log" > "$OUTPUT_DIR/logs/$(basename $log)" 2>/dev/null
        echo "  已采集: $(basename $log)"
    fi
done

#===============================================================================
# 7. SSH 爆破分析 (参考 Emergency-Response-Notes)
#===============================================================================
print_section "7. SSH 爆破分析"

echo -e "${YELLOW}[SSH 失败登录分析]${NC}"
{
    echo "=== SSH 爆破分析报告 ==="
    echo "分析时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    # 确定认证日志路径
    AUTH_LOG=""
    for log in /var/log/auth.log /var/log/secure; do
        [[ -r "$log" ]] && AUTH_LOG="$log" && break
    done

    if [[ -n "$AUTH_LOG" ]]; then
        echo "=== 1. 失败登录 IP TOP 20 ==="
        grep -i "failed password\|authentication failure" "$AUTH_LOG" 2>/dev/null | \
            grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
            sort | uniq -c | sort -rn | head -20
        echo ""

        echo "=== 2. 失败登录用户名 TOP 20 ==="
        grep -i "failed password" "$AUTH_LOG" 2>/dev/null | \
            grep -oE 'for (invalid user )?[^ ]+' | sed 's/for invalid user //;s/for //' | \
            sort | uniq -c | sort -rn | head -20
        echo ""

        echo "=== 3. 成功登录 IP TOP 20 ==="
        grep -i "accepted password\|accepted publickey" "$AUTH_LOG" 2>/dev/null | \
            grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
            sort | uniq -c | sort -rn | head -20
        echo ""

        echo "=== 4. 爆破后成功登录 (危险!) ==="
        echo "以下 IP 有大量失败后成功登录:"
        # 获取失败次数 > 5 的 IP
        failed_ips=$(grep -i "failed password" "$AUTH_LOG" 2>/dev/null | \
            grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
            sort | uniq -c | awk '$1 > 5 {print $2}')

        for ip in $failed_ips; do
            if grep -i "accepted" "$AUTH_LOG" 2>/dev/null | grep -q "$ip"; then
                fail_count=$(grep -i "failed password" "$AUTH_LOG" | grep -c "$ip")
                succ_count=$(grep -i "accepted" "$AUTH_LOG" | grep -c "$ip")
                echo "  [!] $ip - 失败: $fail_count 次, 成功: $succ_count 次"
            fi
        done
        echo ""

        echo "=== 5. 时段分析 (按小时) ==="
        grep -i "failed password" "$AUTH_LOG" 2>/dev/null | \
            grep -oE '[A-Z][a-z]{2} [0-9]{1,2} [0-9]{2}:' | \
            awk '{print $3}' | sort | uniq -c | sort -rn | head -10
        echo ""

        echo "=== 6. 无效用户尝试 ==="
        grep -i "invalid user" "$AUTH_LOG" 2>/dev/null | \
            grep -oE 'invalid user [^ ]+' | sed 's/invalid user //' | \
            sort | uniq -c | sort -rn | head -20
        echo ""

        echo "=== 7. 今日失败登录详情 ==="
        today=$(date '+%b %e')
        grep -i "failed password" "$AUTH_LOG" 2>/dev/null | grep "^$today" | tail -20

    else
        echo "未找到认证日志 (/var/log/auth.log 或 /var/log/secure)"
    fi
} > "$OUTPUT_DIR/ssh_bruteforce.txt"
echo "  已保存: ssh_bruteforce.txt"

echo -e "${YELLOW}[SSH 配置安全检查]${NC}"
{
    echo "=== SSH 配置安全分析 ==="
    if [[ -r /etc/ssh/sshd_config ]]; then
        echo ""
        echo "=== 1. 关键安全配置 ==="
        grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|MaxAuthTries|LoginGraceTime|AllowUsers|AllowGroups|DenyUsers|DenyGroups|Port|ListenAddress)' /etc/ssh/sshd_config 2>/dev/null || echo "使用默认配置"

        echo ""
        echo "=== 2. 安全建议检查 ==="
        # PermitRootLogin
        if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
            echo "[!] 风险: PermitRootLogin 设置为 yes"
        else
            echo "[OK] PermitRootLogin 未设置为 yes"
        fi

        # PasswordAuthentication
        if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
            echo "[!] 注意: PasswordAuthentication 设置为 yes (建议使用密钥)"
        fi

        # MaxAuthTries
        if grep -q "^MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null; then
            tries=$(grep "^MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}')
            echo "[INFO] MaxAuthTries = $tries"
        else
            echo "[!] MaxAuthTries 使用默认值 (6)"
        fi

        echo ""
        echo "=== 3. 完整配置 ==="
        cat /etc/ssh/sshd_config
    else
        echo "无法读取 /etc/ssh/sshd_config"
    fi
} > "$OUTPUT_DIR/ssh_config_audit.txt"
echo "  已保存: ssh_config_audit.txt"

#===============================================================================
# 8. Shell 历史
#===============================================================================
print_section "8. Shell 历史"

mkdir -p "$OUTPUT_DIR/history"
echo -e "${YELLOW}[用户 Shell 历史]${NC}"
for home in /home/* /root; do
    [[ -d "$home" ]] || continue
    user=$(basename "$home")
    for hist in .bash_history .zsh_history .sh_history; do
        if [[ -r "$home/$hist" ]]; then
            cp "$home/$hist" "$OUTPUT_DIR/history/${user}_${hist}" 2>/dev/null
            echo "  已采集: ${user}_${hist}"
        fi
    done
done

#===============================================================================
# 9. 文件系统信息
#===============================================================================
print_section "9. 文件系统信息"

echo -e "${YELLOW}[挂载信息]${NC}"
{
    echo "=== mount ==="
    mount
    echo ""
    echo "=== df -h ==="
    df -h
    echo ""
    echo "=== /etc/fstab ==="
    cat /etc/fstab
} > "$OUTPUT_DIR/filesystem.txt"
echo "  已保存: filesystem.txt"

echo -e "${YELLOW}[最近修改的文件 (7天)]${NC}"
{
    echo "=== /etc 最近修改 ==="
    find /etc -type f -mtime -7 -ls 2>/dev/null | head -50
    echo ""
    echo "=== /usr/bin 最近修改 ==="
    find /usr/bin -type f -mtime -7 -ls 2>/dev/null | head -20
    echo ""
    echo "=== /tmp 文件 ==="
    find /tmp -type f -ls 2>/dev/null | head -50
    echo ""
    echo "=== /dev/shm 文件 ==="
    find /dev/shm -type f -ls 2>/dev/null
} > "$OUTPUT_DIR/recent_files.txt"
echo "  已保存: recent_files.txt"

echo -e "${YELLOW}[SUID/SGID 文件]${NC}"
{
    echo "=== SUID 文件 ==="
    find / -perm -4000 -type f -ls 2>/dev/null
    echo ""
    echo "=== SGID 文件 ==="
    find / -perm -2000 -type f -ls 2>/dev/null
} > "$OUTPUT_DIR/suid_sgid.txt" 2>/dev/null
echo "  已保存: suid_sgid.txt"

#===============================================================================
# 10. 内核与模块
#===============================================================================
print_section "10. 内核与模块"

{
    echo "=== lsmod ==="
    lsmod 2>/dev/null
    echo ""
    echo "=== /proc/modules ==="
    cat /proc/modules 2>/dev/null
    echo ""
    echo "=== 内核参数 ==="
    sysctl -a 2>/dev/null | head -200
} > "$OUTPUT_DIR/kernel_modules.txt"
echo "  已保存: kernel_modules.txt"

#===============================================================================
# 11. 打包
#===============================================================================
print_section "11. 打包采集数据"

cd "$(dirname "$OUTPUT_DIR")"
ARCHIVE_NAME="$(basename "$OUTPUT_DIR").tar.gz"
tar -czf "$ARCHIVE_NAME" "$(basename "$OUTPUT_DIR")" 2>/dev/null

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  采集完成!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "输出目录: $OUTPUT_DIR"
echo "压缩包:   $(dirname "$OUTPUT_DIR")/$ARCHIVE_NAME"
echo ""
echo "采集内容:"
ls -la "$OUTPUT_DIR"
echo ""
echo "文件大小: $(du -sh "$OUTPUT_DIR" | cut -f1)"
echo "压缩包大小: $(du -sh "$(dirname "$OUTPUT_DIR")/$ARCHIVE_NAME" | cut -f1)"
