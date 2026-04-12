#!/bin/bash
# Linux 深度持久化检测脚本
# 用法: bash deep_persistence.sh

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
echo -e "${CYAN}  Linux 深度持久化检测 - $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

#===============================================================================
# 1. Systemd 服务深度检查 (ATT&CK T1543.002)
#===============================================================================
print_section "1. Systemd 服务深度检查 [T1543.002]"

# 系统服务白名单 (官方合法服务使用 /tmp 等路径)
SERVICE_WHITELIST=(
    "xfs_scrub@.service"
    "xfs_scrub_media@.service"
    "systemd-tmpfiles-clean.service"
    "tmp.mount"
)

is_whitelisted_service() {
    local svc_name=$(basename "$1")
    for w in "${SERVICE_WHITELIST[@]}"; do
        [[ "$svc_name" == "$w" ]] && return 0
    done
    return 1
}

echo -e "${YELLOW}[系统服务 - 可疑 ExecStart]${NC}"
found_suspicious=false
for svc in /etc/systemd/system/*.service /lib/systemd/system/*.service; do
    [[ -f "$svc" ]] || continue
    # 跳过白名单服务
    is_whitelisted_service "$svc" && continue
    if grep -qE 'ExecStart=.*(curl|wget|python|perl|bash\s+-c|/tmp/|/dev/shm|base64)' "$svc" 2>/dev/null; then
        echo -e "${RED}[!] 可疑服务: $svc${NC}"
        grep -E 'ExecStart|Description' "$svc" 2>/dev/null | head -3
        echo ""
        found_suspicious=true
    fi
done
$found_suspicious || echo "未发现可疑服务"

echo -e "${YELLOW}[用户服务]${NC}"
find /home -path '*/.config/systemd/user/*.service' -exec sh -c '
    echo "--- {} ---"
    grep -E "ExecStart|Description" "{}" 2>/dev/null
' \; 2>/dev/null | head -30 || echo "未发现"

echo -e "\n${YELLOW}[最近创建/修改的服务 (7天)]${NC}"
find /etc/systemd/system /lib/systemd/system -name '*.service' -mtime -7 -exec ls -la {} \; 2>/dev/null | head -10 || echo "未发现"

echo -e "\n${YELLOW}[Systemd Timers]${NC}"
systemctl list-timers --all 2>/dev/null | head -15 || echo "无法获取"

echo -e "\n${YELLOW}[可疑 Timer 配置]${NC}"
for timer in /etc/systemd/system/*.timer; do
    [[ -f "$timer" ]] || continue
    if grep -qE 'OnCalendar|OnBootSec|OnUnitActiveSec' "$timer" 2>/dev/null; then
        echo "--- $timer ---"
        grep -E 'OnCalendar|OnBootSec|Unit' "$timer" 2>/dev/null
    fi
done

#===============================================================================
# 2. Cron 深度检查 (ATT&CK T1053.003)
#===============================================================================
print_section "2. Cron 深度检查 [T1053.003]"

echo -e "${YELLOW}[/etc/crontab]${NC}"
if [[ -r /etc/crontab ]]; then
    grep -vE '^#|^$|^SHELL|^PATH|^MAILTO' /etc/crontab 2>/dev/null || echo "空"
else
    echo "无权限"
fi

echo -e "\n${YELLOW}[/etc/cron.d/*]${NC}"
for f in /etc/cron.d/*; do
    [[ -f "$f" ]] || continue
    echo "--- $f ---"
    grep -vE '^#|^$' "$f" 2>/dev/null | head -5
done

echo -e "\n${YELLOW}[用户 Crontab]${NC}"
for user in $(cut -d: -f1 /etc/passwd); do
    cron_file="/var/spool/cron/crontabs/$user"
    if [[ -r "$cron_file" ]]; then
        content=$(grep -vE '^#|^$' "$cron_file" 2>/dev/null)
        if [[ -n "$content" ]]; then
            echo "--- $user ---"
            echo "$content" | head -5
        fi
    fi
done 2>/dev/null || echo "无权限或为空"

echo -e "\n${YELLOW}[cron.hourly/daily/weekly/monthly]${NC}"
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$dir" ]] || continue
    scripts=$(find "$dir" -type f -executable 2>/dev/null | wc -l)
    recent=$(find "$dir" -type f -mtime -7 2>/dev/null | wc -l)
    echo "$dir: $scripts 个脚本, $recent 个最近修改"
    if [[ $recent -gt 0 ]]; then
        find "$dir" -type f -mtime -7 -ls 2>/dev/null | head -3
    fi
done

echo -e "\n${YELLOW}[可疑 Cron 命令模式]${NC}"
{
    cat /etc/crontab 2>/dev/null
    cat /etc/cron.d/* 2>/dev/null
    cat /var/spool/cron/crontabs/* 2>/dev/null
} 2>/dev/null | grep -E 'curl|wget|python|perl|base64|/tmp/|nc\s|bash\s+-c' | head -10 || echo "未发现"

#===============================================================================
# 3. Init 脚本检查 (ATT&CK T1037)
#===============================================================================
print_section "3. Init 脚本检查 [T1037]"

echo -e "${YELLOW}[/etc/rc.local]${NC}"
if [[ -f /etc/rc.local ]]; then
    ls -la /etc/rc.local
    echo "内容:"
    grep -vE '^#|^$|^exit 0' /etc/rc.local 2>/dev/null | head -10 || echo "(空)"
else
    echo "不存在"
fi

echo -e "\n${YELLOW}[/etc/init.d/ 最近修改]${NC}"
find /etc/init.d -type f -mtime -7 -ls 2>/dev/null | head -10 || echo "未发现"

echo -e "\n${YELLOW}[/etc/rc*.d/ 可疑链接]${NC}"
for d in /etc/rc{0,1,2,3,4,5,6,S}.d; do
    [[ -d "$d" ]] || continue
    # 查找非系统包管理的启动脚本
    find "$d" -type l -mtime -7 -ls 2>/dev/null
done | head -10 || echo "未发现"

#===============================================================================
# 4. Shell 配置文件检查 (ATT&CK T1546.004)
#===============================================================================
print_section "4. Shell 配置文件检查 [T1546.004]"

echo -e "${YELLOW}[/etc/profile.d/]${NC}"
for f in /etc/profile.d/*.sh; do
    [[ -f "$f" ]] || continue
    if grep -qE 'curl|wget|python|base64|/tmp/' "$f" 2>/dev/null; then
        echo -e "${RED}[!] 可疑: $f${NC}"
        grep -E 'curl|wget|python|base64|/tmp/' "$f" | head -3
    fi
done
find /etc/profile.d -mtime -7 -ls 2>/dev/null | head -5

echo -e "\n${YELLOW}[/etc/bash.bashrc 和 /etc/bashrc]${NC}"
for f in /etc/bash.bashrc /etc/bashrc; do
    [[ -f "$f" ]] || continue
    echo "--- $f (最后修改: $(stat -c %y "$f" 2>/dev/null | cut -d. -f1)) ---"
    # 检查可疑命令
    if grep -qE '^[^#]*(curl|wget|python|nc\s|/tmp/)' "$f" 2>/dev/null; then
        echo -e "${RED}[!] 发现可疑命令${NC}"
        grep -nE '^[^#]*(curl|wget|python|nc\s|/tmp/)' "$f" | head -3
    fi
done

echo -e "\n${YELLOW}[用户 .bashrc/.profile 可疑内容]${NC}"
for home in /home/* /root; do
    [[ -d "$home" ]] || continue
    for rc in .bashrc .bash_profile .profile .zshrc; do
        f="$home/$rc"
        [[ -f "$f" ]] || continue
        if grep -qE '^[^#]*(curl|wget|python.*http|base64|nc\s+-|/tmp/|/dev/tcp)' "$f" 2>/dev/null; then
            echo -e "${RED}[!] $f${NC}"
            grep -nE '^[^#]*(curl|wget|python.*http|base64|nc\s+-|/tmp/|/dev/tcp)' "$f" 2>/dev/null | head -3
        fi
    done
done 2>/dev/null || echo "无权限"

#===============================================================================
# 5. SSH 配置检查 (ATT&CK T1098.004)
#===============================================================================
print_section "5. SSH 配置检查 [T1098.004]"

echo -e "${YELLOW}[SSH authorized_keys]${NC}"
find /home /root -name 'authorized_keys' -exec sh -c '
    echo "--- {} ---"
    ls -la "{}"
    wc -l < "{}"
    echo "Keys:"
    cat "{}" 2>/dev/null | head -3
' \; 2>/dev/null || echo "未发现"

echo -e "\n${YELLOW}[sshd_config 关键配置]${NC}"
if [[ -r /etc/ssh/sshd_config ]]; then
    grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AuthorizedKeysFile|AllowUsers|AllowGroups)' /etc/ssh/sshd_config 2>/dev/null || echo "使用默认配置"
else
    echo "无权限"
fi

echo -e "\n${YELLOW}[/etc/ssh/sshd_config.d/]${NC}"
ls -la /etc/ssh/sshd_config.d/ 2>/dev/null | head -10 || echo "目录不存在"

echo -e "\n${YELLOW}[SSH RC 文件]${NC}"
find /home /root -name '.ssh' -exec sh -c '
    for f in rc environment; do
        if [[ -f "{}/$f" ]]; then
            echo "--- {}/$f ---"
            cat "{}/$f" 2>/dev/null | head -5
        fi
    done
' \; 2>/dev/null

#===============================================================================
# 6. PAM 后门检查 (ATT&CK T1556.003)
#===============================================================================
print_section "6. PAM 后门检查 [T1556.003]"

echo -e "${YELLOW}[PAM 配置最近修改]${NC}"
find /etc/pam.d -type f -mtime -7 -ls 2>/dev/null | head -10 || echo "未发现"

echo -e "\n${YELLOW}[可疑 PAM 模块]${NC}"
# 非标准 PAM 模块
for f in /etc/pam.d/*; do
    [[ -f "$f" ]] || continue
    if grep -qE 'pam_exec|pam_script|pam_python' "$f" 2>/dev/null; then
        echo -e "${RED}[!] $f 包含可疑模块${NC}"
        grep -E 'pam_exec|pam_script|pam_python' "$f"
    fi
done

echo -e "\n${YELLOW}[/lib/security/ 或 /lib64/security/ 非标准模块]${NC}"
for libdir in /lib/security /lib64/security /lib/x86_64-linux-gnu/security; do
    [[ -d "$libdir" ]] || continue
    find "$libdir" -name '*.so' -mtime -30 -ls 2>/dev/null | head -5
done

#===============================================================================
# 7. LD_PRELOAD 劫持检查 (ATT&CK T1574.006)
#===============================================================================
print_section "7. LD_PRELOAD 劫持检查 [T1574.006]"

echo -e "${YELLOW}[/etc/ld.so.preload]${NC}"
if [[ -f /etc/ld.so.preload ]]; then
    if [[ -s /etc/ld.so.preload ]]; then
        echo -e "${RED}[!] 警告: 文件存在且非空!${NC}"
        ls -la /etc/ld.so.preload
        cat /etc/ld.so.preload
    else
        echo "文件存在但为空"
    fi
else
    echo "不存在 (正常)"
fi

echo -e "\n${YELLOW}[/etc/ld.so.conf.d/ 可疑条目]${NC}"
for f in /etc/ld.so.conf.d/*.conf; do
    [[ -f "$f" ]] || continue
    if grep -qE '/tmp|/home|/var/tmp|/dev/shm' "$f" 2>/dev/null; then
        echo -e "${RED}[!] 可疑: $f${NC}"
        cat "$f"
    fi
done
find /etc/ld.so.conf.d -mtime -7 -ls 2>/dev/null | head -5

echo -e "\n${YELLOW}[环境变量 LD_PRELOAD]${NC}"
env | grep -i ld_preload || echo "当前 shell 未设置"
grep -r 'LD_PRELOAD' /etc/environment /etc/profile /etc/profile.d/ 2>/dev/null | head -5 || echo "未在系统配置中发现"

#===============================================================================
# 8. 内核模块检查 (ATT&CK T1547.006)
#===============================================================================
print_section "8. 内核模块检查 [T1547.006]"

echo -e "${YELLOW}[已加载的非标准模块]${NC}"
lsmod 2>/dev/null | grep -vE '^Module|^(nvidia|nouveau|iwl|ath|rtl|r8|intel|amd|e1000|virtio|vmw|xen|hyperv|kvm|vbox|drm|snd|usb|hid|i2c|acpi|pci|scsi|sd_|sr_|cdrom|loop|fuse|overlay|nf|ip|xt_|bridge|tun|tap|bluetooth|cfg80211|rfkill|dm_|ext4|xfs|btrfs|nfs|cifs)' | head -15

echo -e "\n${YELLOW}[最近加载的模块 (dmesg)]${NC}"
dmesg 2>/dev/null | grep -iE 'module.*loaded|insmod|modprobe' | tail -10 || echo "无权限或无记录"

echo -e "\n${YELLOW}[/etc/modules 和 /etc/modules-load.d/]${NC}"
cat /etc/modules 2>/dev/null | grep -vE '^#|^$' || echo "/etc/modules 为空或不存在"
ls -la /etc/modules-load.d/ 2>/dev/null | head -5

#===============================================================================
# 总结
#===============================================================================
print_section "检查完成"

echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
echo -e "${YELLOW}持久化机制 ATT&CK 映射:${NC}"
echo "  T1543.002 - Systemd Service"
echo "  T1053.003 - Cron"
echo "  T1037     - Boot/Logon Init Scripts"
echo "  T1546.004 - Unix Shell Configuration"
echo "  T1098.004 - SSH Authorized Keys"
echo "  T1556.003 - PAM Modification"
echo "  T1574.006 - LD_PRELOAD Hijacking"
echo "  T1547.006 - Kernel Modules"
