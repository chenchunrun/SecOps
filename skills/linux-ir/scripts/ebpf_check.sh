#!/bin/bash
#
# Linux IR - eBPF/BPF 后门检测
# 检测 BPFDoor / Symbiote / LinkPro 等 eBPF 恶意软件
# ATT&CK: T1014 (Rootkit), T1205.002 (Socket Filters)
#

set -o pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

VR="${VR:-$HOME/tools/velociraptor/velociraptor}"
HAS_VR=0
[[ -x "$VR" ]] && HAS_VR=1

print_header() {
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Linux IR - eBPF/BPF 后门检测${NC}"
    echo -e "${CYAN}  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

section() {
    echo -e "\n${CYAN}=== $1 ===${NC}"
}

alert() {
    echo -e "${RED}[!] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[!] $1${NC}"
}

info() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_header

#######################################
# 1. BPF 程序枚举
#######################################
section "BPF 程序枚举"

echo -e "${YELLOW}[*] 已加载的 BPF 程序:${NC}"
if command -v bpftool &>/dev/null; then
    bpf_progs=$(bpftool prog list 2>/dev/null)
    if [[ -n "$bpf_progs" ]]; then
        echo "$bpf_progs"

        # 统计
        prog_count=$(echo "$bpf_progs" | grep -c '^[0-9]' || true)
        warn "共 $prog_count 个 BPF 程序已加载"
    else
        info "无 BPF 程序"
    fi
else
    warn "bpftool 未安装，跳过 BPF 程序枚举"
    echo "  安装: apt install linux-tools-common 或 yum install bpftool"
fi

#######################################
# 2. BPF Maps 检测
#######################################
section "BPF Maps 检测"

if command -v bpftool &>/dev/null; then
    echo -e "${YELLOW}[*] BPF Maps:${NC}"
    bpftool map list 2>/dev/null | head -30 || info "无 BPF maps"
fi

#######################################
# 3. BPFDoor 特征检测
#######################################
section "BPFDoor 特征检测"

# 3.1 packet_recvmsg 等待状态
echo -e "${YELLOW}[*] 检查 packet_recvmsg 等待进程 (BPFDoor 特征):${NC}"
bpfdoor_procs=$(grep -l 'packet_recvmsg\|wait_for_more_packets' /proc/*/stack 2>/dev/null || true)
if [[ -n "$bpfdoor_procs" ]]; then
    alert "发现 packet 等待进程!"
    for stack_file in $bpfdoor_procs; do
        pid=$(echo "$stack_file" | grep -oP '/proc/\K[0-9]+')
        proc_name=$(cat /proc/$pid/comm 2>/dev/null)
        exe=$(readlink /proc/$pid/exe 2>/dev/null)
        echo "  PID: $pid, Name: $proc_name, Exe: $exe"
    done
else
    info "未发现 BPFDoor 特征进程"
fi

# 3.2 可疑进程名
echo -e "\n${YELLOW}[*] 检查 BPFDoor 常见进程名:${NC}"
bpfdoor_names=$(ps aux 2>/dev/null | grep -iE 'kdmtmpflush|dbus-srv|hald-addon|irqbalanced' | grep -v grep || true)
if [[ -n "$bpfdoor_names" ]]; then
    alert "发现可疑进程名!"
    echo "$bpfdoor_names"
else
    info "未发现可疑进程名"
fi

# 3.3 BPFDoor 端口范围 42391-43391
echo -e "\n${YELLOW}[*] 检查 BPFDoor 端口范围 (42391-43391):${NC}"
bpfdoor_ports=$(ss -tlnp 2>/dev/null | awk -F: '{print $NF}' | awk '{print $1}' | grep -E '^4239[1-9]$|^423[0-9]{2}$|^4239[0-9]$|^4339[0-1]$' || true)
if [[ -n "$bpfdoor_ports" ]]; then
    alert "发现 BPFDoor 可疑端口!"
    ss -tlnp 2>/dev/null | grep -E ':4239|:4339'
else
    info "未发现 BPFDoor 端口"
fi

#######################################
# 4. AF_PACKET Socket 检测
#######################################
section "AF_PACKET Socket 检测"

echo -e "${YELLOW}[*] 使用 AF_PACKET 的进程:${NC}"
# 通过 /proc/net/packet 检测
if [[ -r /proc/net/packet ]]; then
    packet_sockets=$(cat /proc/net/packet 2>/dev/null | tail -n +2)
    if [[ -n "$packet_sockets" ]]; then
        warn "发现 AF_PACKET sockets:"
        echo "$packet_sockets"

        # 尝试关联进程
        echo -e "\n${YELLOW}[*] 关联进程:${NC}"
        for inode in $(cat /proc/net/packet 2>/dev/null | tail -n +2 | awk '{print $9}'); do
            pid=$(find /proc -maxdepth 3 -path '/proc/*/fd/*' -lname "socket:\[$inode\]" 2>/dev/null | head -1 | cut -d/ -f3)
            if [[ -n "$pid" ]]; then
                proc_name=$(cat /proc/$pid/comm 2>/dev/null)
                echo "  Inode $inode -> PID $pid ($proc_name)"
            fi
        done
    else
        info "无 AF_PACKET sockets"
    fi
else
    warn "/proc/net/packet 不可读"
fi

#######################################
# 5. Raw Socket 检测
#######################################
section "Raw Socket 检测"

echo -e "${YELLOW}[*] Raw sockets:${NC}"
if [[ -r /proc/net/raw ]]; then
    raw_sockets=$(cat /proc/net/raw 2>/dev/null | tail -n +2 | wc -l)
    if [[ $raw_sockets -gt 0 ]]; then
        warn "发现 $raw_sockets 个 raw sockets"
        cat /proc/net/raw 2>/dev/null | head -10
    else
        info "无 raw sockets"
    fi
fi

if [[ -r /proc/net/raw6 ]]; then
    raw6_sockets=$(cat /proc/net/raw6 2>/dev/null | tail -n +2 | wc -l)
    if [[ $raw6_sockets -gt 0 ]]; then
        warn "发现 $raw6_sockets 个 raw6 sockets"
    fi
fi

#######################################
# 6. Symbiote 特征检测
#######################################
section "Symbiote 特征检测"

# 6.1 LD_PRELOAD 检测
echo -e "${YELLOW}[*] 检查 LD_PRELOAD 环境变量:${NC}"
ld_preload_procs=$(grep -l LD_PRELOAD /proc/*/environ 2>/dev/null || true)
if [[ -n "$ld_preload_procs" ]]; then
    alert "发现 LD_PRELOAD 进程!"
    for env_file in $ld_preload_procs; do
        pid=$(echo "$env_file" | grep -oP '/proc/\K[0-9]+')
        proc_name=$(cat /proc/$pid/comm 2>/dev/null)
        ld_val=$(tr '\0' '\n' < "$env_file" 2>/dev/null | grep LD_PRELOAD)
        echo "  PID $pid ($proc_name): $ld_val"
    done
else
    info "未发现进程 LD_PRELOAD"
fi

# 6.2 /etc/ld.so.preload
echo -e "\n${YELLOW}[*] /etc/ld.so.preload:${NC}"
if [[ -s /etc/ld.so.preload ]]; then
    alert "ld.so.preload 存在内容!"
    cat /etc/ld.so.preload
    ls -la /etc/ld.so.preload
else
    info "ld.so.preload 为空或不存在"
fi

#######################################
# 7. 可疑共享库检测
#######################################
section "可疑共享库检测"

echo -e "${YELLOW}[*] 检查非标准位置的 .so 文件:${NC}"
suspicious_so=$(find /tmp /var/tmp /dev/shm /home -name '*.so*' -type f 2>/dev/null | head -20)
if [[ -n "$suspicious_so" ]]; then
    warn "发现可疑共享库:"
    echo "$suspicious_so"
else
    info "未发现可疑共享库"
fi

#######################################
# 8. 内核符号表检测
#######################################
section "内核符号表 eBPF 相关检测"

echo -e "${YELLOW}[*] 检查可疑内核符号:${NC}"
suspicious_syms=$(grep -E 'bpf_.*hide|hide_.*bpf|rootkit|backdoor|stealth' /proc/kallsyms 2>/dev/null || true)
if [[ -n "$suspicious_syms" ]]; then
    alert "发现可疑内核符号!"
    echo "$suspicious_syms"
else
    info "未发现可疑内核符号"
fi

#######################################
# 9. debugfs BPF 检测
#######################################
section "debugfs BPF 检测"

echo -e "${YELLOW}[*] /sys/kernel/debug/tracing 检查:${NC}"
if [[ -d /sys/kernel/debug/tracing ]]; then
    # 检查 kprobe events
    kprobe_events=$(cat /sys/kernel/debug/tracing/kprobe_events 2>/dev/null | wc -l)
    if [[ $kprobe_events -gt 0 ]]; then
        warn "发现 $kprobe_events 个 kprobe events"
        head -10 /sys/kernel/debug/tracing/kprobe_events 2>/dev/null
    else
        info "无 kprobe events"
    fi
else
    warn "debugfs 未挂载或无权限"
fi

#######################################
# 10. VQL 深度检测 (可选)
#######################################
if [[ $HAS_VR -eq 1 ]]; then
    section "Velociraptor VQL 检测"

    echo -e "${YELLOW}[*] AF_PACKET 连接:${NC}"
    $VR query "SELECT Pid, Name FROM netstat() WHERE Family = 'AF_PACKET'" 2>/dev/null || echo "  无结果"
fi

#######################################
# 摘要
#######################################
echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}[完成] eBPF/BPF 后门检测结束${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

echo -e "\n${YELLOW}[提示] 防御建议:${NC}"
echo "  1. 如不需要 eBPF，可通过 sysctl 禁用: kernel.unprivileged_bpf_disabled=1"
echo "  2. 监控 BPF 程序加载: auditctl -a always,exit -F arch=b64 -S bpf"
echo "  3. 部署具有 eBPF 可见性的 EDR"
