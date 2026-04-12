#!/bin/bash
# Linux 快速扫描脚本
# 用法: bash quick_scan.sh

set -euo pipefail

VR="${VR:-$(command -v velociraptor 2>/dev/null || echo "$HOME/tools/velociraptor/velociraptor")}"
HAS_VR=false
[[ -x "$VR" ]] && HAS_VR=true

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
echo -e "${CYAN}  Linux 快速扫描 - $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${CYAN}  主机: $(hostname) | 内核: $(uname -r)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

#===============================================================================
# 1. 系统信息
#===============================================================================
print_section "1. 系统信息"

echo -e "${YELLOW}[基本信息]${NC}"
echo "主机名: $(hostname)"
echo "系统: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || uname -s)"
echo "内核: $(uname -r)"
echo "架构: $(uname -m)"
echo "运行时间: $(uptime -p 2>/dev/null || uptime)"

echo -e "\n${YELLOW}[安全状态]${NC}"
# SELinux
if command -v getenforce &>/dev/null; then
    echo "SELinux: $(getenforce 2>/dev/null || echo 'N/A')"
else
    echo "SELinux: 未安装"
fi
# AppArmor
if [[ -d /sys/kernel/security/apparmor ]]; then
    echo "AppArmor: $(cat /sys/kernel/security/apparmor/profiles 2>/dev/null | wc -l) 个 profiles"
else
    echo "AppArmor: 未启用"
fi
# Firewall
if command -v ufw &>/dev/null; then
    echo "UFW: $(ufw status 2>/dev/null | head -1 || echo 'N/A')"
elif command -v firewall-cmd &>/dev/null; then
    echo "Firewalld: $(firewall-cmd --state 2>/dev/null || echo 'N/A')"
fi

#===============================================================================
# 2. 进程检查
#===============================================================================
print_section "2. 进程检查"

echo -e "${YELLOW}[可疑进程 - 临时目录执行]${NC}"
ps aux 2>/dev/null | awk '$11 ~ /\/tmp\/|\/dev\/shm|\/var\/tmp|\/run\/user/ {print $2, $1, $11}' | head -10 || echo "未发现"

echo -e "\n${YELLOW}[可疑进程 - 隐藏名称]${NC}"
# 匹配真正的隐藏进程 (.sshd, .malware)，排除正常的相对路径执行 (./binary)
ps aux 2>/dev/null | awk '$11 ~ /^\.[^\/]/ {print $2, $1, $11}' | head -10 || echo "未发现"

echo -e "\n${YELLOW}[已删除但运行的进程]${NC}"
ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | awk '{print $NF}' | head -10 || echo "未发现"

echo -e "\n${YELLOW}[高资源占用进程 (CPU>50%)]${NC}"
ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && $3>50 {print $2, $1, $3"%", $11}' | head -5 || echo "未发现"

echo -e "\n${YELLOW}[挖矿特征进程]${NC}"
ps aux 2>/dev/null | grep -iE 'xmrig|minerd|kdevtmpfsi|kworker[0-9]{3,}|cryptonight|stratum' | grep -v grep | head -5 || echo "未发现"

echo -e "\n${YELLOW}[反弹 Shell 特征]${NC}"
ps aux 2>/dev/null | grep -E 'nc\s+-[el]|ncat.*-e|bash\s+-i|/dev/tcp|python.*socket' | grep -v grep | head -5 || echo "未发现"

#===============================================================================
# 3. 环境变量检查 (参考 LinuxCheck)
#===============================================================================
print_section "3. 环境变量检查"

echo -e "${YELLOW}[LD_PRELOAD 环境变量]${NC}"
if env | grep -q LD_PRELOAD; then
    echo -e "${RED}[!] 发现 LD_PRELOAD 环境变量:${NC}"
    env | grep LD_PRELOAD
else
    echo "正常 (未设置)"
fi

echo -e "\n${YELLOW}[LD_LIBRARY_PATH 环境变量]${NC}"
if env | grep -q LD_LIBRARY_PATH; then
    echo -e "${YELLOW}[!] 发现 LD_LIBRARY_PATH:${NC}"
    env | grep LD_LIBRARY_PATH
else
    echo "正常 (未设置)"
fi

echo -e "\n${YELLOW}[PROMPT_COMMAND 检查]${NC}"
if env | grep -q PROMPT_COMMAND; then
    echo -e "${YELLOW}[!] 发现 PROMPT_COMMAND:${NC}"
    env | grep PROMPT_COMMAND
else
    echo "正常 (未设置)"
fi

echo -e "\n${YELLOW}[可疑别名 (alias)]${NC}"
alias 2>/dev/null | grep -iE 'curl|wget|python|nc|bash|sh|chmod|rm|mv|cp' | head -5 || echo "未发现可疑别名"

#===============================================================================
# 4. 网络检查
#===============================================================================
print_section "4. 网络检查"

echo -e "${YELLOW}[网卡混杂模式检测]${NC}"
if ip link 2>/dev/null | grep -q PROMISC; then
    echo -e "${RED}[!] 检测到混杂模式网卡 (可能存在嗅探):${NC}"
    ip link | grep PROMISC
else
    echo "正常 (无混杂模式)"
fi

echo -e "\n${YELLOW}[监听端口 TOP 15]${NC}"
ss -tlnp 2>/dev/null | head -16 || netstat -tlnp 2>/dev/null | head -16

echo -e "\n${YELLOW}[外部连接 (非内网)]${NC}"
ss -tunp 2>/dev/null | grep ESTAB | grep -vE '127\.|::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.' | head -15 || echo "未发现"

echo -e "\n${YELLOW}[高危端口检测]${NC}"
echo "检查端口: 4444,5555,6666,1337,31337,6379,27017,9200,2375"
ss -tlnp 2>/dev/null | grep -E ':4444|:5555|:6666|:1337|:31337|:6379|:27017|:9200|:2375' || echo "未发现高危端口"

#===============================================================================
# 4. 用户检查
#===============================================================================
print_section "4. 用户检查"

echo -e "${YELLOW}[UID=0 用户 (除root)]${NC}"
awk -F: '$3==0 && $1!="root" {print "[!] 危险: " $1 " (UID=0)"}' /etc/passwd || echo "正常"

echo -e "\n${YELLOW}[空口令账户 (参考 LinuxCheck)]${NC}"
if [[ -r /etc/shadow ]]; then
    empty_pass=$(awk -F: '($2=="" || $2=="!" || $2=="*") && $1!="sync" && $1!="shutdown" && $1!="halt" {print $1}' /etc/shadow 2>/dev/null)
    if [[ -n "$empty_pass" ]]; then
        echo -e "${RED}[!] 发现空口令/锁定账户:${NC}"
        echo "$empty_pass"
    else
        echo "正常 (无空口令)"
    fi
else
    echo "无权限读取 /etc/shadow"
fi

echo -e "\n${YELLOW}[可登录用户]${NC}"
awk -F: '$7 ~ /bash|sh|zsh/ && $3>=1000 {print $1, "UID="$3, $7}' /etc/passwd | head -10

echo -e "\n${YELLOW}[最近登录]${NC}"
last -10 2>/dev/null || echo "无法读取"

echo -e "\n${YELLOW}[SSH authorized_keys]${NC}"
find /home /root -name 'authorized_keys' -ls 2>/dev/null | head -10 || echo "未发现"

echo -e "\n${YELLOW}[/etc/passwd 和 /etc/shadow 修改时间]${NC}"
ls -la /etc/passwd /etc/shadow 2>/dev/null

echo -e "\n${YELLOW}[sudo 配置检查]${NC}"
if [[ -r /etc/sudoers ]]; then
    grep -vE '^#|^$|^Defaults' /etc/sudoers 2>/dev/null | head -10
    ls -la /etc/sudoers.d/ 2>/dev/null | head -5
else
    echo "无权限读取"
fi

#===============================================================================
# 5. 历史命令检查 (参考 LinuxCheck)
#===============================================================================
print_section "5. 历史命令检查"

echo -e "${YELLOW}[可疑历史命令]${NC}"
for hist_file in /root/.bash_history /home/*/.bash_history; do
    [[ -r "$hist_file" ]] || continue
    suspicious=$(grep -E 'wget.*http|curl.*http|nc\s+-|bash\s+-i|/dev/tcp|base64|python.*-c|perl.*-e|chmod\s+777|chmod\s+\+x.*tmp' "$hist_file" 2>/dev/null | tail -5)
    if [[ -n "$suspicious" ]]; then
        echo -e "${YELLOW}--- $hist_file ---${NC}"
        echo "$suspicious"
    fi
done 2>/dev/null || echo "未发现可疑命令"

echo -e "\n${YELLOW}[敏感操作历史 (passwd/shadow/sudoers)]${NC}"
for hist_file in /root/.bash_history /home/*/.bash_history; do
    [[ -r "$hist_file" ]] || continue
    sensitive=$(grep -E 'passwd|shadow|sudoers|useradd|userdel|usermod' "$hist_file" 2>/dev/null | tail -3)
    if [[ -n "$sensitive" ]]; then
        echo -e "${YELLOW}--- $hist_file ---${NC}"
        echo "$sensitive"
    fi
done 2>/dev/null || echo "未发现"

#===============================================================================
# 6. 持久化检查
#===============================================================================
print_section "6. 持久化检查"

echo -e "${YELLOW}[最近 7 天新增的 systemd 服务]${NC}"
find /etc/systemd/system /lib/systemd/system -name '*.service' -mtime -7 -ls 2>/dev/null | head -10 || echo "未发现"

echo -e "\n${YELLOW}[用户级 systemd 服务]${NC}"
find /home -path '*/.config/systemd/user/*.service' -ls 2>/dev/null | head -5 || echo "未发现"

echo -e "\n${YELLOW}[Crontab 可疑条目]${NC}"
{
    crontab -l 2>/dev/null
    cat /etc/crontab 2>/dev/null
    cat /etc/cron.d/* 2>/dev/null
    cat /var/spool/cron/crontabs/* 2>/dev/null
} 2>/dev/null | grep -vE '^#|^$|^SHELL|^PATH|^MAILTO' | grep -E 'curl|wget|base64|/tmp/|python|perl|nc\s' | head -10 || echo "未发现"

echo -e "\n${YELLOW}[/etc/cron.d 最近修改]${NC}"
find /etc/cron.d -type f -mtime -7 -ls 2>/dev/null | head -5 || echo "未发现"

echo -e "\n${YELLOW}[rc.local]${NC}"
if [[ -f /etc/rc.local ]]; then
    ls -la /etc/rc.local
    grep -vE '^#|^$|^exit' /etc/rc.local 2>/dev/null | head -5
else
    echo "不存在"
fi

echo -e "\n${YELLOW}[ld.so.preload]${NC}"
if [[ -s /etc/ld.so.preload ]]; then
    echo -e "${RED}[!] 警告: /etc/ld.so.preload 存在且非空!${NC}"
    cat /etc/ld.so.preload
else
    echo "正常 (不存在或为空)"
fi

#===============================================================================
# 7. 文件检查
#===============================================================================
print_section "7. 文件检查"

echo -e "${YELLOW}[/tmp 可执行文件]${NC}"
find /tmp -type f -executable -ls 2>/dev/null | head -10 || echo "未发现"

echo -e "\n${YELLOW}[/dev/shm 文件]${NC}"
ls -la /dev/shm/ 2>/dev/null | head -10

echo -e "\n${YELLOW}[隐藏文件 (/tmp, /var/tmp)]${NC}"
find /tmp /var/tmp -name '.*' -type f -ls 2>/dev/null | head -10 || echo "未发现"

echo -e "\n${YELLOW}[SUID 文件 (异常位置)]${NC}"
find /tmp /var/tmp /home /dev/shm -perm -4000 -type f -ls 2>/dev/null | head -10 || echo "未发现"

echo -e "\n${YELLOW}[最近 7 天修改的 /usr/bin]${NC}"
find /usr/bin -type f -mtime -7 -ls 2>/dev/null | head -10 || echo "未发现"

echo -e "\n${YELLOW}[Webshell 检测 (最近 7 天)]${NC}"
find /var/www -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.asp' \) -mtime -7 -ls 2>/dev/null | head -10 || echo "未发现或目录不存在"

#===============================================================================
# 8. 总结
#===============================================================================
print_section "扫描完成"

echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
echo "如需深度检查，请运行:"
echo "  bash ir.sh full          # 完整检查"
echo "  bash ir.sh persistence   # 持久化深度分析"
echo "  bash ir.sh rootkit       # Rootkit 检测"
echo "  bash ir.sh miner         # 挖矿检测"
echo "  bash ir.sh supply        # 供应链安全检测"
echo "  bash ir.sh container     # 容器安全检测"
