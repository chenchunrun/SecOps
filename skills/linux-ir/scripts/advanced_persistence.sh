#!/bin/bash
#
# Linux IR - 高级持久化检测
# 检测 MOTD / XDG Autostart / Udev Rules / At Jobs / Git Hooks / Package Manager Hooks
# ATT&CK: T1037.003, T1546.013, T1546.016, T1053.002, T1547.015, T1547.013
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
    echo -e "${CYAN}  Linux IR - 高级持久化检测${NC}"
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
# 1. MOTD 后门 (T1037.003)
#######################################
section "Message of the Day (MOTD) 检测"

echo -e "${YELLOW}[*] /etc/update-motd.d 内容:${NC}"
if [[ -d /etc/update-motd.d ]]; then
    ls -la /etc/update-motd.d/ 2>/dev/null

    # 检查最近修改
    recent_motd=$(find /etc/update-motd.d -mtime -7 -type f 2>/dev/null)
    if [[ -n "$recent_motd" ]]; then
        warn "最近 7 天修改:"
        echo "$recent_motd"
    fi

    # 检查可疑内容
    echo -e "\n${YELLOW}[*] 可疑 MOTD 脚本:${NC}"
    suspicious=$(grep -rlE 'curl|wget|nc\s|python.*http|bash\s+-i|/dev/tcp|base64' /etc/update-motd.d/ 2>/dev/null || true)
    if [[ -n "$suspicious" ]]; then
        alert "发现可疑脚本!"
        echo "$suspicious"
        for f in $suspicious; do
            echo -e "\n--- $f ---"
            grep -E 'curl|wget|nc\s|python|bash|/dev/tcp|base64' "$f" 2>/dev/null
        done
    else
        info "未发现可疑 MOTD 脚本"
    fi
else
    info "/etc/update-motd.d 不存在"
fi

echo -e "\n${YELLOW}[*] /etc/motd:${NC}"
if [[ -f /etc/motd ]]; then
    ls -la /etc/motd
    head -5 /etc/motd
else
    info "/etc/motd 不存在"
fi

#######################################
# 2. XDG Autostart (T1546.013)
#######################################
section "XDG Autostart 检测"

echo -e "${YELLOW}[*] 系统级 autostart:${NC}"
ls -la /etc/xdg/autostart/ 2>/dev/null || info "/etc/xdg/autostart 不存在"

echo -e "\n${YELLOW}[*] 用户级 autostart:${NC}"
for home_dir in /home/* /root; do
    autostart_dir="$home_dir/.config/autostart"
    if [[ -d "$autostart_dir" ]]; then
        echo "--- $autostart_dir ---"
        ls -la "$autostart_dir" 2>/dev/null
    fi
done

echo -e "\n${YELLOW}[*] 最近 7 天修改的 .desktop 文件:${NC}"
recent_desktop=$(find /etc/xdg/autostart /home/*/.config/autostart /root/.config/autostart -name '*.desktop' -mtime -7 2>/dev/null)
if [[ -n "$recent_desktop" ]]; then
    warn "发现最近修改:"
    echo "$recent_desktop"
    for f in $recent_desktop; do
        echo -e "\n--- $f ---"
        grep -E 'Exec=|Name=' "$f" 2>/dev/null
    done
else
    info "无最近修改"
fi

# 检查可疑 Exec 命令
echo -e "\n${YELLOW}[*] 可疑 Exec 命令:${NC}"
suspicious_exec=$(grep -rh 'Exec=' /etc/xdg/autostart /home/*/.config/autostart 2>/dev/null | grep -iE 'curl|wget|nc\s|python|/tmp/|/dev/shm|base64' || true)
if [[ -n "$suspicious_exec" ]]; then
    alert "发现可疑命令!"
    echo "$suspicious_exec"
else
    info "未发现可疑命令"
fi

#######################################
# 3. Udev Rules (T1546.016)
#######################################
section "Udev Rules 检测"

echo -e "${YELLOW}[*] /etc/udev/rules.d 内容:${NC}"
ls -la /etc/udev/rules.d/ 2>/dev/null

echo -e "\n${YELLOW}[*] 最近 7 天修改:${NC}"
recent_udev=$(find /etc/udev/rules.d -mtime -7 -type f 2>/dev/null)
if [[ -n "$recent_udev" ]]; then
    warn "发现最近修改:"
    echo "$recent_udev"
else
    info "无最近修改"
fi

echo -e "\n${YELLOW}[*] 可疑 RUN 命令:${NC}"
suspicious_udev=$(grep -rE 'RUN\+?=.*curl|RUN\+?=.*wget|RUN\+?=.*nc\s|RUN\+?=.*/tmp/|RUN\+?=.*python|RUN\+?=.*bash' /etc/udev/rules.d/ 2>/dev/null || true)
if [[ -n "$suspicious_udev" ]]; then
    alert "发现可疑规则!"
    echo "$suspicious_udev"
else
    info "未发现可疑 udev 规则"
fi

#######################################
# 4. At Jobs (T1053.002)
#######################################
section "At Jobs 检测"

echo -e "${YELLOW}[*] At 队列:${NC}"
if command -v atq &>/dev/null; then
    at_jobs=$(atq 2>/dev/null)
    if [[ -n "$at_jobs" ]]; then
        warn "存在 at 任务:"
        echo "$at_jobs"

        # 显示任务内容
        echo -e "\n${YELLOW}[*] 任务详情:${NC}"
        for job_id in $(atq 2>/dev/null | awk '{print $1}'); do
            echo "--- Job $job_id ---"
            at -c "$job_id" 2>/dev/null | tail -20
        done
    else
        info "无 at 任务"
    fi
else
    info "at 命令不可用"
fi

echo -e "\n${YELLOW}[*] /var/spool/at 内容:${NC}"
if [[ -d /var/spool/at ]]; then
    ls -la /var/spool/at/ 2>/dev/null
    ls -la /var/spool/at/spool/ 2>/dev/null
else
    info "/var/spool/at 不存在"
fi

# CentOS/RHEL
if [[ -d /var/spool/cron/atjobs ]]; then
    echo -e "\n${YELLOW}[*] /var/spool/cron/atjobs:${NC}"
    ls -la /var/spool/cron/atjobs/ 2>/dev/null
fi

#######################################
# 5. Git Hooks (T1547.015)
#######################################
section "Git Hooks 检测"

echo -e "${YELLOW}[*] 搜索 .git/hooks 可执行文件:${NC}"
git_hooks=$(find /home /root /opt /var/www -path '*/.git/hooks/*' -type f -executable 2>/dev/null | head -30)
if [[ -n "$git_hooks" ]]; then
    warn "发现 Git hooks:"
    echo "$git_hooks"

    # 检查可疑内容
    echo -e "\n${YELLOW}[*] 可疑 hook 内容:${NC}"
    for hook in $git_hooks; do
        if grep -qE 'curl|wget|nc\s|python.*http|/dev/tcp|base64' "$hook" 2>/dev/null; then
            alert "可疑: $hook"
            grep -E 'curl|wget|nc|python|/dev/tcp|base64' "$hook" 2>/dev/null
        fi
    done
else
    info "未发现可执行 Git hooks"
fi

# Git 全局配置
echo -e "\n${YELLOW}[*] Git 全局配置检查:${NC}"
for home_dir in /home/* /root; do
    gitconfig="$home_dir/.gitconfig"
    if [[ -f "$gitconfig" ]]; then
        # 检查 core.pager, core.editor 等可疑配置
        suspicious_git=$(grep -E 'pager\s*=|editor\s*=|alias\.' "$gitconfig" 2>/dev/null | grep -iE 'curl|wget|nc\s|bash|python' || true)
        if [[ -n "$suspicious_git" ]]; then
            alert "$gitconfig 可疑配置:"
            echo "$suspicious_git"
        fi
    fi
done

#######################################
# 6. Package Manager Hooks (T1547.013)
#######################################
section "Package Manager Hooks 检测"

# APT
echo -e "${YELLOW}[*] APT Hooks:${NC}"
if [[ -d /etc/apt/apt.conf.d ]]; then
    ls -la /etc/apt/apt.conf.d/ 2>/dev/null | head -20

    # 检查可疑 hooks
    echo -e "\n${YELLOW}[*] APT Hook 命令:${NC}"
    grep -rE 'APT::Update::Pre-Invoke|APT::Update::Post-Invoke|DPkg::Pre-Install-Pkgs|DPkg::Post-Invoke' /etc/apt/apt.conf.d/ 2>/dev/null | head -10 || info "未发现自定义 hooks"
fi

# YUM/DNF
echo -e "\n${YELLOW}[*] YUM/DNF Plugins:${NC}"
if [[ -d /etc/yum/pluginconf.d ]]; then
    ls -la /etc/yum/pluginconf.d/ 2>/dev/null
fi
if [[ -d /usr/lib/yum-plugins ]]; then
    ls -la /usr/lib/yum-plugins/ 2>/dev/null
fi
if [[ -d /etc/dnf/plugins ]]; then
    ls -la /etc/dnf/plugins/ 2>/dev/null
fi

# dpkg hooks
echo -e "\n${YELLOW}[*] DPKG Hooks:${NC}"
for hook_dir in /etc/dpkg/dpkg.cfg.d /var/lib/dpkg/info; do
    if [[ -d "$hook_dir" ]]; then
        recent=$(find "$hook_dir" -name '*.postinst' -o -name '*.preinst' -mtime -7 2>/dev/null | head -10)
        if [[ -n "$recent" ]]; then
            warn "最近 7 天修改的 dpkg 脚本: $hook_dir"
            echo "$recent"
        fi
    fi
done

#######################################
# 7. Polkit Rules
#######################################
section "Polkit Rules 检测"

echo -e "${YELLOW}[*] /etc/polkit-1/rules.d:${NC}"
if [[ -d /etc/polkit-1/rules.d ]]; then
    ls -la /etc/polkit-1/rules.d/ 2>/dev/null

    recent_polkit=$(find /etc/polkit-1/rules.d -mtime -7 -type f 2>/dev/null)
    if [[ -n "$recent_polkit" ]]; then
        warn "最近 7 天修改:"
        echo "$recent_polkit"
    fi
else
    info "polkit rules 目录不存在"
fi

#######################################
# 8. Anacron
#######################################
section "Anacron 检测"

echo -e "${YELLOW}[*] /etc/anacrontab:${NC}"
if [[ -f /etc/anacrontab ]]; then
    cat /etc/anacrontab | grep -vE '^#|^$'
else
    info "anacrontab 不存在"
fi

#######################################
# 9. 历史记录清除检测 (T1070.003)
#######################################
section "历史记录清除检测"

echo -e "${YELLOW}[*] 检查空的 history 文件:${NC}"
for home_dir in /home/* /root; do
    for hist_file in "$home_dir/.bash_history" "$home_dir/.zsh_history"; do
        if [[ -f "$hist_file" ]]; then
            size=$(stat -c %s "$hist_file" 2>/dev/null || echo 0)
            if [[ $size -eq 0 ]]; then
                alert "$hist_file 为空!"
            fi
        fi
    done
done

echo -e "\n${YELLOW}[*] 检查 HISTFILE 篡改:${NC}"
suspicious_hist=$(grep -rE 'HISTSIZE=0|HISTFILESIZE=0|unset HISTFILE|HISTFILE=/dev/null' /home/*/.bashrc /home/*/.zshrc /root/.bashrc /root/.zshrc /etc/profile* 2>/dev/null || true)
if [[ -n "$suspicious_hist" ]]; then
    alert "发现历史记录禁用配置!"
    echo "$suspicious_hist"
else
    info "未发现历史记录篡改"
fi

#######################################
# 10. 时间戳篡改检测 (T1070.006)
#######################################
section "时间戳篡改检测"

echo -e "${YELLOW}[*] 检查 mtime < ctime (时间戳被修改):${NC}"
# ctime 无法被 touch 修改，如果 mtime < ctime 说明被篡改过
timestomp_count=0
for f in /usr/bin/* /usr/sbin/* /bin/* /sbin/*; do
    if [[ -f "$f" ]]; then
        mtime=$(stat -c %Y "$f" 2>/dev/null)
        ctime=$(stat -c %Z "$f" 2>/dev/null)
        if [[ -n "$mtime" && -n "$ctime" && $mtime -lt $ctime ]]; then
            # 差异超过 1 天才告警
            diff=$((ctime - mtime))
            if [[ $diff -gt 86400 ]]; then
                warn "$f: mtime 早于 ctime $((diff/86400)) 天"
                ((timestomp_count++))
                if [[ $timestomp_count -ge 5 ]]; then
                    echo "  ... 更多结果省略"
                    break
                fi
            fi
        fi
    fi
done 2>/dev/null

if [[ $timestomp_count -eq 0 ]]; then
    info "未发现明显时间戳篡改"
fi

#######################################
# 摘要
#######################################
echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}[完成] 高级持久化检测结束${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
