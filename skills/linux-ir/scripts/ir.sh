#!/bin/bash
# Linux 入侵检查统一入口
# 用法: bash ir.sh [模式]
# 模式: (空)=摘要 | quick=快速 | full=完整 | persistence | network | rootkit | container | forensic | miner | supply | webshell | help

# 注意: 不使用 pipefail，因为 grep 无匹配时返回 1 会导致管道失败
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VR="${VR:-$(command -v velociraptor 2>/dev/null || echo "$HOME/tools/velociraptor/velociraptor")}"

# 颜色定义
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Linux 入侵检查工具 v2.1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_help() {
    print_header
    echo ""
    echo "用法: bash ir.sh [模式]"
    echo ""
    echo "模式:"
    echo "  (无参数)    摘要报告 - 10项关键检查，快速概览 (~5秒)"
    echo "  quick       快速扫描 - 详细输出，基础检查 (~30秒)"
    echo "  full        完整检查 - 所有模块深度扫描 (~2-3分钟)"
    echo "  persistence 持久化检查 - systemd/cron/init 深度分析"
    echo "  network     网络检查 - 连接/监听/DNS 分析"
    echo "  rootkit     Rootkit检测 - 内核/进程/文件隐藏检测"
    echo "  container   容器检查 - Docker/K8s 安全检测"
    echo "  forensic    取证采集 - 日志/历史/审计数据/SSH爆破分析"
    echo "  miner       挖矿检测 - 挖矿木马/矿池连接/CPU异常"
    echo "  supply      供应链检测 - pip投毒/Redis/JDWP/Docker API"
    echo "  webshell    Webshell检测 - 菜刀/蚁剑/冰蝎/哥斯拉"
    echo "  fileless    无文件恶意软件 - memfd_create/内存执行/进程注入"
    echo "  ebpf        eBPF/BPF后门 - BPFDoor/Symbiote/AF_PACKET"
    echo "  advanced    高级持久化 - MOTD/XDG/Udev/At/Git Hooks"
    echo "  help        显示此帮助"
    echo ""
    echo "示例:"
    echo "  bash ir.sh              # 推荐：先看摘要"
    echo "  bash ir.sh quick        # 发现问题后快速扫描"
    echo "  bash ir.sh full         # 完整深度检查"
    echo ""
}

check_velociraptor() {
    if [[ ! -x "$VR" ]]; then
        echo -e "${YELLOW}[!] Velociraptor 未安装，部分功能将使用原生命令替代${NC}"
        echo -e "${YELLOW}    安装: curl -L -o ~/tools/velociraptor/velociraptor https://github.com/Velocidex/velociraptor/releases/download/v0.73.3/velociraptor-v0.73.3-linux-amd64${NC}"
        return 1
    fi
    return 0
}

# 摘要报告 - 10项关键检查
summary_scan() {
    print_header
    echo -e "\n${CYAN}[摘要报告] $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${CYAN}主机: $(hostname) | 内核: $(uname -r)${NC}\n"

    local issues=0

    # 1. 可疑进程
    echo -n "[1/10] 可疑进程... "
    local procs
    procs=$(ps aux 2>/dev/null | grep -E '/tmp/|/dev/shm|/var/tmp|\(deleted\)|^\.' | grep -v grep | wc -l)
    if [[ $procs -gt 0 ]]; then
        echo -e "${RED}发现 $procs 个${NC}"
        issues=$((issues + 1))
    else
        echo -e "${GREEN}正常${NC}"
    fi

    # 2. 异常外连
    echo -n "[2/10] 异常外连... "
    local conns
    conns=$(ss -tunp 2>/dev/null | grep ESTAB | grep -vE '127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.' | wc -l)
    if [[ $conns -gt 5 ]]; then
        echo -e "${YELLOW}$conns 个外部连接${NC}"
    else
        echo -e "${GREEN}正常 ($conns)${NC}"
    fi

    # 3. 高危端口监听
    echo -n "[3/10] 高危端口... "
    local dangerous
    dangerous=$(ss -tlnp 2>/dev/null | grep -E ':4444|:5555|:6666|:1337|:31337|:6379|:27017' | wc -l)
    if [[ $dangerous -gt 0 ]]; then
        echo -e "${RED}发现 $dangerous 个${NC}"
        issues=$((issues + 1))
    else
        echo -e "${GREEN}正常${NC}"
    fi

    # 4. 最近 systemd 服务
    echo -n "[4/10] 新增服务... "
    local recent_svc
    recent_svc=$(find /etc/systemd/system -name '*.service' -mtime -7 2>/dev/null | wc -l)
    if [[ $recent_svc -gt 0 ]]; then
        echo -e "${YELLOW}$recent_svc 个 (7天内)${NC}"
    else
        echo -e "${GREEN}正常${NC}"
    fi

    # 5. 可疑 crontab
    echo -n "[5/10] Crontab... "
    local cron_sus
    cron_sus=$(cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null | grep -vE '^#|^$' | grep -cE 'curl|wget|base64|/tmp/' || true)
    if [[ $cron_sus -gt 0 ]]; then
        echo -e "${RED}发现 $cron_sus 条可疑${NC}"
        issues=$((issues + 1))
    else
        echo -e "${GREEN}正常${NC}"
    fi

    # 6. UID=0 异常用户
    echo -n "[6/10] Root用户... "
    local root_users
    root_users=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd | wc -l)
    if [[ $root_users -gt 0 ]]; then
        echo -e "${RED}发现 $root_users 个异常${NC}"
        issues=$((issues + 1))
    else
        echo -e "${GREEN}正常${NC}"
    fi

    # 7. SSH authorized_keys
    echo -n "[7/10] SSH Keys... "
    local ssh_keys
    ssh_keys=$(find /home /root -name 'authorized_keys' -mtime -7 2>/dev/null | wc -l)
    if [[ $ssh_keys -gt 0 ]]; then
        echo -e "${YELLOW}$ssh_keys 个最近修改${NC}"
    else
        echo -e "${GREEN}正常${NC}"
    fi

    # 8. ld.so.preload
    echo -n "[8/10] LD_PRELOAD... "
    if [[ -s /etc/ld.so.preload ]]; then
        echo -e "${RED}存在且非空!${NC}"
        issues=$((issues + 1))
    else
        echo -e "${GREEN}正常${NC}"
    fi

    # 9. /tmp 可执行文件
    echo -n "[9/10] /tmp 可执行... "
    local tmp_exec
    tmp_exec=$(find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | wc -l)
    if [[ $tmp_exec -gt 0 ]]; then
        echo -e "${YELLOW}$tmp_exec 个${NC}"
    else
        echo -e "${GREEN}正常${NC}"
    fi

    # 10. 删除但运行的进程
    echo -n "[10/10] 已删除进程... "
    local deleted
    deleted=$(ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | wc -l)
    if [[ $deleted -gt 0 ]]; then
        echo -e "${RED}$deleted 个${NC}"
        issues=$((issues + 1))
    else
        echo -e "${GREEN}正常${NC}"
    fi

    # 摘要
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    if [[ $issues -gt 0 ]]; then
        echo -e "${RED}[!] 发现 $issues 项高危问题，建议运行: bash ir.sh full${NC}"
    else
        echo -e "${GREEN}[✓] 未发现明显异常${NC}"
    fi
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# 模式分发
case "${1:-}" in
    help|-h|--help)
        print_help
        ;;
    quick)
        if [[ -x "$SCRIPT_DIR/quick_scan.sh" ]]; then
            bash "$SCRIPT_DIR/quick_scan.sh"
        else
            echo -e "${RED}[!] quick_scan.sh 不存在${NC}"
            exit 1
        fi
        ;;
    full)
        print_header
        echo -e "\n${CYAN}[完整检查模式]${NC}\n"
        for script in quick_scan.sh deep_persistence.sh rootkit_check.sh; do
            if [[ -x "$SCRIPT_DIR/$script" ]]; then
                echo -e "\n${CYAN}>>> 执行 $script${NC}"
                bash "$SCRIPT_DIR/$script"
            fi
        done
        ;;
    persistence)
        if [[ -x "$SCRIPT_DIR/deep_persistence.sh" ]]; then
            bash "$SCRIPT_DIR/deep_persistence.sh"
        else
            echo -e "${RED}[!] deep_persistence.sh 不存在${NC}"
            exit 1
        fi
        ;;
    network)
        print_header
        echo -e "\n${CYAN}[网络检查]${NC}\n"
        echo -e "${YELLOW}[监听端口]${NC}"
        ss -tlnp 2>/dev/null | head -20
        echo -e "\n${YELLOW}[外部连接]${NC}"
        ss -tunp 2>/dev/null | grep ESTAB | grep -vE '127\.|::1' | head -20
        echo -e "\n${YELLOW}[高危端口]${NC}"
        ss -tlnp 2>/dev/null | grep -E ':4444|:5555|:6666|:1337|:6379|:27017|:9200' || echo "未发现"
        ;;
    rootkit)
        if [[ -x "$SCRIPT_DIR/rootkit_check.sh" ]]; then
            bash "$SCRIPT_DIR/rootkit_check.sh"
        else
            echo -e "${RED}[!] rootkit_check.sh 不存在${NC}"
            exit 1
        fi
        ;;
    container)
        if [[ -x "$SCRIPT_DIR/container_check.sh" ]]; then
            bash "$SCRIPT_DIR/container_check.sh"
        else
            echo -e "${RED}[!] container_check.sh 不存在${NC}"
            exit 1
        fi
        ;;
    forensic)
        if [[ -x "$SCRIPT_DIR/forensic_artifacts.sh" ]]; then
            bash "$SCRIPT_DIR/forensic_artifacts.sh"
        else
            echo -e "${RED}[!] forensic_artifacts.sh 不存在${NC}"
            exit 1
        fi
        ;;
    miner)
        if [[ -x "$SCRIPT_DIR/miner_check.sh" ]]; then
            bash "$SCRIPT_DIR/miner_check.sh"
        else
            echo -e "${RED}[!] miner_check.sh 不存在${NC}"
            exit 1
        fi
        ;;
    supply)
        if [[ -x "$SCRIPT_DIR/supply_chain_check.sh" ]]; then
            bash "$SCRIPT_DIR/supply_chain_check.sh"
        else
            echo -e "${RED}[!] supply_chain_check.sh 不存在${NC}"
            exit 1
        fi
        ;;
    webshell)
        if [[ -x "$SCRIPT_DIR/webshell_check.sh" ]]; then
            bash "$SCRIPT_DIR/webshell_check.sh"
        else
            echo -e "${RED}[!] webshell_check.sh 不存在${NC}"
            exit 1
        fi
        ;;
    fileless)
        if [[ -x "$SCRIPT_DIR/fileless_check.sh" ]]; then
            bash "$SCRIPT_DIR/fileless_check.sh"
        else
            echo -e "${RED}[!] fileless_check.sh 不存在${NC}"
            exit 1
        fi
        ;;
    ebpf)
        if [[ -x "$SCRIPT_DIR/ebpf_check.sh" ]]; then
            bash "$SCRIPT_DIR/ebpf_check.sh"
        else
            echo -e "${RED}[!] ebpf_check.sh 不存在${NC}"
            exit 1
        fi
        ;;
    advanced)
        if [[ -x "$SCRIPT_DIR/advanced_persistence.sh" ]]; then
            bash "$SCRIPT_DIR/advanced_persistence.sh"
        else
            echo -e "${RED}[!] advanced_persistence.sh 不存在${NC}"
            exit 1
        fi
        ;;
    "")
        summary_scan
        ;;
    *)
        echo -e "${RED}[!] 未知模式: $1${NC}"
        print_help
        exit 1
        ;;
esac
