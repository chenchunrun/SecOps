#!/bin/bash
#
# Linux IR - 无文件恶意软件检测
# 检测 memfd_create / 内存执行 / 进程注入
# ATT&CK: T1620 (Reflective Code Loading)
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
    echo -e "${CYAN}  Linux IR - 无文件恶意软件检测${NC}"
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
# 1. memfd_create 检测 (T1620)
#######################################
section "memfd_create 无文件执行检测"

echo -e "${YELLOW}[*] 检查 /proc/*/exe 指向 memfd:${NC}"
memfd_procs=$(ls -la /proc/*/exe 2>/dev/null | grep -E 'memfd:|/memfd:' || true)
if [[ -n "$memfd_procs" ]]; then
    alert "发现 memfd 执行的进程!"
    echo "$memfd_procs"

    # 提取 PID 进一步分析
    for pid in $(echo "$memfd_procs" | grep -oP '/proc/\K[0-9]+'); do
        echo -e "\n${YELLOW}[*] PID $pid 详情:${NC}"
        echo "  cmdline: $(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)"
        echo "  cwd: $(readlink /proc/$pid/cwd 2>/dev/null)"
        echo "  环境变量:"
        cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep -E 'SSH|USER|PWD|HOME' | head -5
    done
else
    info "未发现 memfd 执行的进程"
fi

#######################################
# 2. 已删除但运行的进程 (T1070)
#######################################
section "已删除但运行的进程"

echo -e "${YELLOW}[*] 检查 (deleted) 进程:${NC}"
deleted_procs=$(ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' || true)
if [[ -n "$deleted_procs" ]]; then
    alert "发现已删除但仍在运行的进程!"
    echo "$deleted_procs"

    # 详细分析
    for pid in $(echo "$deleted_procs" | grep -oP '/proc/\K[0-9]+'); do
        exe_path=$(readlink /proc/$pid/exe 2>/dev/null | sed 's/ (deleted)//')
        echo -e "\n${YELLOW}[*] PID $pid:${NC}"
        echo "  原路径: $exe_path"
        echo "  cmdline: $(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)"

        # 尝试恢复二进制
        if [[ -d "/proc/$pid" ]]; then
            echo "  可恢复: cp /proc/$pid/exe /tmp/recovered_$pid"
        fi
    done
else
    info "未发现已删除的运行进程"
fi

#######################################
# 3. /proc/PID/maps 异常检测
#######################################
section "/proc/PID/maps 内存映射检测"

echo -e "${YELLOW}[*] 检查匿名可执行内存段:${NC}"
suspicious_maps=0
for pid in $(ps -eo pid --no-headers); do
    if [[ -r "/proc/$pid/maps" ]]; then
        # 检查匿名可执行段 (无文件映射)
        anon_exec=$(grep -E '^[0-9a-f]+-[0-9a-f]+.*x.*\s+0\s+00:00\s+0\s*$' /proc/$pid/maps 2>/dev/null | wc -l)
        if [[ $anon_exec -gt 10 ]]; then
            proc_name=$(cat /proc/$pid/comm 2>/dev/null)
            warn "PID $pid ($proc_name): $anon_exec 个匿名可执行段"
            ((suspicious_maps++))
        fi
    fi
done 2>/dev/null

if [[ $suspicious_maps -eq 0 ]]; then
    info "未发现异常内存映射"
fi

#######################################
# 4. 无环境变量的进程
#######################################
section "无环境变量的进程"

echo -e "${YELLOW}[*] 检查 /proc/PID/environ 为空的进程:${NC}"
no_env_count=0
for pid in $(ps -eo pid --no-headers | head -200); do
    if [[ -r "/proc/$pid/environ" ]]; then
        env_size=$(stat -c %s "/proc/$pid/environ" 2>/dev/null || echo 0)
        if [[ $env_size -eq 0 ]]; then
            proc_name=$(cat /proc/$pid/comm 2>/dev/null)
            # 排除内核线程
            if [[ ! "$proc_name" =~ ^kworker|^migration|^rcu|^watchdog ]]; then
                warn "PID $pid ($proc_name): 无环境变量"
                ((no_env_count++))
            fi
        fi
    fi
done 2>/dev/null

if [[ $no_env_count -eq 0 ]]; then
    info "未发现异常 (所有用户进程都有环境变量)"
fi

#######################################
# 5. /dev/shm 可疑文件
#######################################
section "/dev/shm 共享内存检测"

echo -e "${YELLOW}[*] /dev/shm 内容:${NC}"
shm_files=$(find /dev/shm -type f 2>/dev/null)
if [[ -n "$shm_files" ]]; then
    warn "/dev/shm 中存在文件:"
    ls -la /dev/shm/ 2>/dev/null

    # 检查可执行文件
    exec_files=$(find /dev/shm -type f -executable 2>/dev/null)
    if [[ -n "$exec_files" ]]; then
        alert "发现可执行文件!"
        echo "$exec_files"
    fi
else
    info "/dev/shm 为空"
fi

#######################################
# 6. ptrace 注入检测
#######################################
section "进程注入检测 (ptrace)"

echo -e "${YELLOW}[*] 检查 TracerPid 不为 0 的进程:${NC}"
traced_count=0
for pid in $(ps -eo pid --no-headers | head -200); do
    if [[ -r "/proc/$pid/status" ]]; then
        tracer=$(grep -P '^TracerPid:\s+[1-9]' /proc/$pid/status 2>/dev/null)
        if [[ -n "$tracer" ]]; then
            proc_name=$(cat /proc/$pid/comm 2>/dev/null)
            tracer_pid=$(echo "$tracer" | awk '{print $2}')
            tracer_name=$(cat /proc/$tracer_pid/comm 2>/dev/null)
            warn "PID $pid ($proc_name) 被 PID $tracer_pid ($tracer_name) 追踪"
            ((traced_count++))
        fi
    fi
done 2>/dev/null

if [[ $traced_count -eq 0 ]]; then
    info "未发现进程被追踪"
fi

#######################################
# 7. /proc/PID/fd 指向 memfd
#######################################
section "文件描述符 memfd 检测"

echo -e "${YELLOW}[*] 检查 /proc/PID/fd 中的 memfd:${NC}"
memfd_fd=$(find /proc/*/fd -lname '*memfd*' 2>/dev/null | head -20)
if [[ -n "$memfd_fd" ]]; then
    alert "发现 memfd 文件描述符!"
    echo "$memfd_fd"
else
    info "未发现 memfd 文件描述符"
fi

#######################################
# 8. 使用 VQL 深度检测 (可选)
#######################################
if [[ $HAS_VR -eq 1 ]]; then
    section "Velociraptor VQL 深度检测"

    echo -e "${YELLOW}[*] memfd 进程:${NC}"
    $VR query "SELECT Pid, Name, Exe, CommandLine FROM pslist() WHERE Exe =~ 'memfd:' OR Exe =~ '/memfd:'" 2>/dev/null || echo "  无结果"

    echo -e "\n${YELLOW}[*] 已删除进程:${NC}"
    $VR query "SELECT Pid, Name, Exe FROM pslist() WHERE Exe =~ '\\(deleted\\)'" 2>/dev/null || echo "  无结果"
fi

#######################################
# 摘要
#######################################
echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}[完成] 无文件恶意软件检测结束${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
