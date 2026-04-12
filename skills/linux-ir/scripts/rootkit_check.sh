#!/bin/bash
# Linux Rootkit 检测脚本
# 用法: bash rootkit_check.sh

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
echo -e "${CYAN}  Linux Rootkit 检测 - $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

ISSUES=0

#===============================================================================
# 1. 进程隐藏检测 (ATT&CK T1564.001)
#===============================================================================
print_section "1. 进程隐藏检测 [T1564.001]"

echo -e "${YELLOW}[/proc 目录 vs ps 对比]${NC}"
# 获取 /proc 中的进程
proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||' | sort -n)
# 获取 ps 中的进程
ps_pids=$(ps -eo pid --no-headers 2>/dev/null | tr -d ' ' | sort -n)

# 比较差异，排除竞争条件导致的误报
confirmed_hidden=""
for pid in $proc_pids; do
    if ! echo "$ps_pids" | grep -q "^${pid}$"; then
        # 二次确认：检查进程是否仍然存在
        # 短生命周期进程可能在两次采样间消失，不算隐藏
        sleep 0.05  # 短暂等待
        if [[ -d "/proc/$pid" ]]; then
            # 进程仍存在但 ps 看不到，可能是真正的隐藏进程
            # 排除内核线程 (ppid=2 的进程)
            ppid=$(cat /proc/$pid/stat 2>/dev/null | awk '{print $4}' || echo "0")
            if [[ "$ppid" != "2" && "$ppid" != "0" ]]; then
                confirmed_hidden="$confirmed_hidden $pid"
            fi
        fi
        # 进程已消失 = 正常的短生命周期进程，忽略
    fi
done

if [[ -n "$confirmed_hidden" ]]; then
    echo -e "${RED}[!] 发现隐藏进程: $confirmed_hidden${NC}"
    for pid in $confirmed_hidden; do
        cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' || echo '无法读取')
        exe=$(readlink /proc/$pid/exe 2>/dev/null || echo '无法读取')
        echo "  PID $pid: $cmdline"
        echo "    Exe: $exe"
    done
    ISSUES=$((ISSUES + 1))
else
    echo -e "${GREEN}[✓] 未发现隐藏进程${NC}"
fi

echo -e "\n${YELLOW}[已删除但运行的进程 (可疑)]${NC}"
deleted_procs=$(ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' || true)
if [[ -n "$deleted_procs" ]]; then
    echo -e "${RED}[!] 发现已删除但运行的进程:${NC}"
    echo "$deleted_procs" | head -10
    ISSUES=$((ISSUES + 1))
else
    echo -e "${GREEN}[✓] 未发现${NC}"
fi

#===============================================================================
# 2. 内核模块检测 (ATT&CK T1014)
#===============================================================================
print_section "2. 内核模块/LKM Rootkit 检测 [T1014]"

echo -e "${YELLOW}[/sys/module vs lsmod 对比]${NC}"
# 获取 /sys/module 中的模块
sys_modules=$(ls /sys/module 2>/dev/null | sort)
# 获取 lsmod 中的模块
lsmod_modules=$(lsmod 2>/dev/null | awk 'NR>1 {print $1}' | sort)

hidden_modules=""
for mod in $sys_modules; do
    # 跳过非模块目录
    [[ -d "/sys/module/$mod/sections" ]] || continue
    if ! echo "$lsmod_modules" | grep -q "^${mod}$"; then
        hidden_modules="$hidden_modules $mod"
    fi
done

if [[ -n "$hidden_modules" ]]; then
    echo -e "${YELLOW}[!] 隐藏/内置模块: $hidden_modules${NC}"
else
    echo -e "${GREEN}[✓] 未发现隐藏模块${NC}"
fi

echo -e "\n${YELLOW}[可疑内核模块 (非常见)]${NC}"
lsmod 2>/dev/null | awk 'NR>1 {print $1}' | while read mod; do
    modinfo "$mod" 2>/dev/null | grep -qE 'author:.*unknown|description:.*hidden' && echo -e "${RED}[!] 可疑: $mod${NC}"
done || echo "检查完成"

echo -e "\n${YELLOW}[内核污染状态]${NC}"
taint=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo "0")
if [[ "$taint" != "0" ]]; then
    echo -e "${YELLOW}[!] 内核已污染 (tainted=$taint)${NC}"
    echo "  可能原因: 非签名模块、专有驱动、强制加载等"
else
    echo -e "${GREEN}[✓] 内核未污染${NC}"
fi

#===============================================================================
# 3. 系统调用劫持检测 (ATT&CK T1014)
#===============================================================================
print_section "3. 系统调用劫持检测 [T1014]"

echo -e "${YELLOW}[/proc/kallsyms 可疑修改]${NC}"
if [[ -r /proc/kallsyms ]]; then
    # 检查系统调用表是否在预期范围内
    syscall_addr=$(grep -w sys_call_table /proc/kallsyms 2>/dev/null | awk '{print $1}')
    if [[ -n "$syscall_addr" ]]; then
        echo "sys_call_table 地址: 0x$syscall_addr"
    else
        echo "无法获取 sys_call_table 地址"
    fi
else
    echo "无权限读取 /proc/kallsyms"
fi

echo -e "\n${YELLOW}[/dev 可疑设备]${NC}"
# 检查可疑的字符设备
find /dev -type c \( -name '.*' -o -name '*root*' -o -name '*hide*' -o -name '*kit*' \) -ls 2>/dev/null | head -5 || echo "未发现"

#===============================================================================
# 4. 文件隐藏检测 (ATT&CK T1564.001)
#===============================================================================
print_section "4. 文件隐藏检测 [T1564.001]"

echo -e "${YELLOW}[目录 vs ls 对比 (/tmp)]${NC}"
# 使用不同方法获取文件列表对比
readdir_count=$(ls -la /tmp 2>/dev/null | wc -l)
getdents_count=$(find /tmp -maxdepth 1 2>/dev/null | wc -l)
if [[ $((readdir_count - getdents_count)) -gt 5 || $((getdents_count - readdir_count)) -gt 5 ]]; then
    echo -e "${YELLOW}[!] 差异较大: ls=$readdir_count, find=$getdents_count (可能有隐藏文件)${NC}"
else
    echo -e "${GREEN}[✓] 正常 (ls=$readdir_count, find=$getdents_count)${NC}"
fi

echo -e "\n${YELLOW}[异常隐藏目录]${NC}"
for dir in /tmp /var/tmp /dev/shm /var /usr; do
    hidden=$(find "$dir" -maxdepth 2 -name '.*' -type d 2>/dev/null | grep -vE '^\.$|^\.\.$' | head -5)
    if [[ -n "$hidden" ]]; then
        echo "$hidden"
    fi
done || echo "未发现"

echo -e "\n${YELLOW}[可疑扩展属性]${NC}"
for dir in /tmp /var/tmp /usr/bin /usr/sbin; do
    getfattr -d -m - "$dir"/* 2>/dev/null | grep -v '^#' | head -5 || true
done || echo "未发现或无 getfattr 命令"

#===============================================================================
# 5. 网络隐藏检测 (ATT&CK T1205)
#===============================================================================
print_section "5. 网络隐藏检测 [T1205]"

echo -e "${YELLOW}[/proc/net/tcp vs ss 对比]${NC}"
proc_tcp_count=$(wc -l < /proc/net/tcp 2>/dev/null || echo 0)
ss_tcp_count=$(ss -t 2>/dev/null | wc -l)
echo "  /proc/net/tcp: $proc_tcp_count 行"
echo "  ss -t: $ss_tcp_count 行"
if [[ $((proc_tcp_count - ss_tcp_count)) -gt 10 ]]; then
    echo -e "${YELLOW}[!] 差异较大，可能存在隐藏连接${NC}"
fi

echo -e "\n${YELLOW}[iptables 隐藏规则检测]${NC}"
if command -v iptables &>/dev/null; then
    # 检查是否有 DROP 所有但实际在监听的端口
    iptables -L -n 2>/dev/null | head -20 || echo "无权限"
else
    echo "iptables 未安装"
fi

echo -e "\n${YELLOW}[端口敲门/隐蔽通道检测]${NC}"
# 检查 raw socket
ss -w 2>/dev/null | head -10 || echo "无 raw socket"

#===============================================================================
# 6. 库文件劫持检测 (ATT&CK T1574.006)
#===============================================================================
print_section "6. 库文件劫持检测 [T1574.006]"

echo -e "${YELLOW}[/etc/ld.so.preload]${NC}"
if [[ -f /etc/ld.so.preload ]]; then
    if [[ -s /etc/ld.so.preload ]]; then
        echo -e "${RED}[!] 警告: 存在且非空!${NC}"
        cat /etc/ld.so.preload
        ISSUES=$((ISSUES + 1))
    else
        echo "存在但为空"
    fi
else
    echo -e "${GREEN}[✓] 不存在 (正常)${NC}"
fi

echo -e "\n${YELLOW}[LD_PRELOAD 环境变量]${NC}"
# 检查所有进程的 LD_PRELOAD
found=false
for pid in /proc/[0-9]*; do
    [[ -r "$pid/environ" ]] || continue
    if grep -q 'LD_PRELOAD' "$pid/environ" 2>/dev/null; then
        echo -e "${RED}[!] PID $(basename $pid): 设置了 LD_PRELOAD${NC}"
        cat "$pid/environ" 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD
        found=true
        ISSUES=$((ISSUES + 1))
    fi
done
$found || echo -e "${GREEN}[✓] 未发现${NC}"

echo -e "\n${YELLOW}[/lib 和 /lib64 最近修改的共享库]${NC}"
find /lib /lib64 /usr/lib /usr/lib64 -name '*.so*' -mtime -7 -ls 2>/dev/null | head -10 || echo "未发现"

#===============================================================================
# 7. 二进制文件完整性检测 (ATT&CK T1036)
#===============================================================================
print_section "7. 二进制文件完整性检测 [T1036]"

echo -e "${YELLOW}[关键命令文件检查]${NC}"
for cmd in ls ps netstat ss lsof top; do
    cmd_path=$(which $cmd 2>/dev/null || true)
    [[ -z "$cmd_path" ]] && continue

    # 检查是否为动态链接
    file_info=$(file "$cmd_path" 2>/dev/null)

    # 检查是否被 alias
    if alias "$cmd" 2>/dev/null | grep -q .; then
        echo -e "${YELLOW}[!] $cmd 有 alias 定义${NC}"
    fi

    # 检查修改时间
    mtime=$(stat -c %y "$cmd_path" 2>/dev/null | cut -d. -f1)
    echo "  $cmd_path (修改: $mtime)"
done

echo -e "\n${YELLOW}[dpkg/rpm 包验证 (如可用)]${NC}"
if command -v dpkg &>/dev/null; then
    echo "Debian/Ubuntu 系统，检查关键包..."
    dpkg -V coreutils procps net-tools iproute2 2>/dev/null | head -10 || echo "验证通过或无权限"
elif command -v rpm &>/dev/null; then
    echo "RHEL/CentOS 系统，检查关键包..."
    rpm -Va coreutils procps-ng net-tools iproute 2>/dev/null | head -10 || echo "验证通过或无权限"
else
    echo "无法确定包管理器"
fi

#===============================================================================
# 8. 已知 Rootkit 特征检测
#===============================================================================
print_section "8. 已知 Rootkit 特征检测"

echo -e "${YELLOW}[已知 Rootkit 文件路径]${NC}"
rootkit_paths=(
    "/usr/include/..."
    "/usr/include/..  "
    "/dev/shm/.x"
    "/tmp/.ICE-unix/..."
    "/dev/.udev"
    "/lib/libproc.a"
    "/usr/lib/.libX"
    "/etc/cron.d/..."
)

for path in "${rootkit_paths[@]}"; do
    if [[ -e "$path" ]]; then
        echo -e "${RED}[!] 发现可疑路径: $path${NC}"
        ISSUES=$((ISSUES + 1))
    fi
done
echo "已检查 ${#rootkit_paths[@]} 个已知路径"

echo -e "\n${YELLOW}[Rootkit 进程名特征]${NC}"
rootkit_procs=(
    "adore" "knark" "rial" "sebek" "phalanx"
    "superkit" "suckit" "shkit" "shv4" "shv5"
    "reptile" "diamorphine"
)

for proc in "${rootkit_procs[@]}"; do
    if ps aux 2>/dev/null | grep -qiw "$proc"; then
        echo -e "${RED}[!] 发现可疑进程: $proc${NC}"
        ISSUES=$((ISSUES + 1))
    fi
done
echo "已检查 ${#rootkit_procs[@]} 个已知特征"

echo -e "\n${YELLOW}[chkrootkit/rkhunter (如已安装)]${NC}"
if command -v chkrootkit &>/dev/null; then
    echo "chkrootkit 可用，建议运行: sudo chkrootkit"
elif command -v rkhunter &>/dev/null; then
    echo "rkhunter 可用，建议运行: sudo rkhunter --check"
else
    echo "建议安装 chkrootkit 或 rkhunter 进行深度检测"
    echo "  apt install chkrootkit rkhunter  # Debian/Ubuntu"
    echo "  yum install chkrootkit rkhunter  # RHEL/CentOS"
fi

#===============================================================================
# 总结
#===============================================================================
print_section "检测完成"

echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
if [[ $ISSUES -gt 0 ]]; then
    echo -e "${RED}[!] 发现 $ISSUES 项可疑问题，建议进一步调查${NC}"
else
    echo -e "${GREEN}[✓] 未发现明显 Rootkit 迹象${NC}"
fi
echo ""
echo -e "${YELLOW}Rootkit 检测 ATT&CK 映射:${NC}"
echo "  T1014     - Rootkit"
echo "  T1564.001 - Hidden Files and Directories"
echo "  T1574.006 - LD_PRELOAD"
echo "  T1205     - Traffic Signaling"
echo "  T1036     - Masquerading"
