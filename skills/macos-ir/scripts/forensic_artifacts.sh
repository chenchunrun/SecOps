#!/bin/bash
# macOS 取证数据采集脚本
# 参考 CrowdStrike AutoMacTC，补充 VQL 无法覆盖的取证点

set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

VR="${HOME}/tools/velociraptor/velociraptor"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  macOS 取证数据采集${NC}"
echo -e "${BLUE}  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# ========================================
# 1. Quarantine 数据库 (VQL sqlite)
# ========================================
echo -e "${CYAN}=== 1. Quarantine 隔离记录 (下载来源追踪) ===${NC}"
echo ""

QUARANTINE_DB="$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
if [[ -f "$QUARANTINE_DB" ]]; then
    echo -e "${YELLOW}[INFO] 最近 10 条下载记录:${NC}"
    $VR query "SELECT
        LSQuarantineAgentName as Agent,
        LSQuarantineOriginURLString as URL,
        LSQuarantineDataURLString as DataURL,
        timestamp(epoch=LSQuarantineTimeStamp + 978307200) as Time
    FROM sqlite(file='$QUARANTINE_DB', query='SELECT * FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 10')" 2>/dev/null | grep -v '^\[' | grep -v '^\]' | head -50

    # 检查可疑下载来源
    echo ""
    echo -e "${YELLOW}[INFO] 可疑下载来源检查:${NC}"
    SUSPICIOUS_DOWNLOADS=$($VR query "SELECT LSQuarantineOriginURLString as URL FROM sqlite(file='$QUARANTINE_DB', query='SELECT * FROM LSQuarantineEvent') WHERE URL =~ 'github.com/.*release|drive.google|dropbox|mega.nz|mediafire|anonfiles'" 2>/dev/null || true)
    if [[ -n "$SUSPICIOUS_DOWNLOADS" && "$SUSPICIOUS_DOWNLOADS" != "[]" ]]; then
        echo -e "${RED}[!] 发现可疑下载来源:${NC}"
        echo "$SUSPICIOUS_DOWNLOADS"
    else
        echo -e "${GREEN}[OK]${NC} 未发现可疑下载来源"
    fi
else
    echo -e "${YELLOW}[!]${NC} Quarantine 数据库不存在"
fi
echo ""

# ========================================
# 2. 安装历史 (VQL plist)
# ========================================
echo -e "${CYAN}=== 2. 软件安装历史 ===${NC}"
echo ""

INSTALL_HISTORY="/Library/Receipts/InstallHistory.plist"
if [[ -f "$INSTALL_HISTORY" ]]; then
    echo -e "${YELLOW}[INFO] 最近 7 天安装的软件:${NC}"
    # plist 插件返回格式特殊，用 plutil 更可靠
    plutil -p "$INSTALL_HISTORY" 2>/dev/null | grep -E "displayName|date|packageIdentifiers" | head -30
else
    echo -e "${YELLOW}[!]${NC} 安装历史文件不存在"
fi
echo ""

# ========================================
# 3. Shell 历史
# ========================================
echo -e "${CYAN}=== 3. Shell 命令历史 ===${NC}"
echo ""

# 可疑命令模式
SUSPICIOUS_CMDS="curl.*\\|.*sh|wget.*\\|.*bash|osascript.*-e|base64 -[dD]|security find-.*password|rm -rf /|chmod 777|nc -[el]|python.*-c|ruby.*-e|perl.*-e"

for hist in "$HOME/.zsh_history" "$HOME/.bash_history"; do
    if [[ -f "$hist" ]]; then
        echo -e "${YELLOW}[INFO] 检查: $hist${NC}"
        SUSPICIOUS=$(grep -E "$SUSPICIOUS_CMDS" "$hist" 2>/dev/null | tail -20 || true)
        if [[ -n "$SUSPICIOUS" ]]; then
            echo -e "${RED}[!] 发现可疑命令:${NC}"
            echo "$SUSPICIOUS" | while read line; do
                echo "    $line"
            done
        else
            echo -e "${GREEN}[OK]${NC} 未发现可疑命令"
        fi
    fi
done
echo ""

# ========================================
# 4. 统一日志 (Unified Logs)
# ========================================
echo -e "${CYAN}=== 4. 统一日志分析 ===${NC}"
echo ""

echo -e "${YELLOW}[INFO] sudo 命令执行记录 (最近 1 小时):${NC}"
log show --predicate 'process == "sudo"' --style compact --last 1h 2>/dev/null | head -10 || echo "    需要 Full Disk Access 权限"

echo ""
echo -e "${YELLOW}[INFO] 登录事件 (最近 1 小时):${NC}"
log show --predicate 'eventMessage CONTAINS "Authentication" OR eventMessage CONTAINS "login"' --style compact --last 1h 2>/dev/null | head -10 || echo "    需要 Full Disk Access 权限"

echo ""
echo -e "${YELLOW}[INFO] 进程执行记录 (最近 1 小时):${NC}"
log show --predicate 'subsystem == "com.apple.xpc.launchd" AND eventMessage CONTAINS "spawn"' --style compact --last 1h 2>/dev/null | head -10 || echo "    需要 Full Disk Access 权限"
echo ""

# ========================================
# 5. 审计日志 (Audit Logs)
# ========================================
echo -e "${CYAN}=== 5. 审计日志 ===${NC}"
echo ""

AUDIT_DIR="/var/audit"
if [[ -d "$AUDIT_DIR" ]]; then
    echo -e "${YELLOW}[INFO] 审计日志文件:${NC}"
    ls -la "$AUDIT_DIR" 2>/dev/null | head -10 || echo "    需要 root 权限"

    # 尝试解析最新的审计日志
    LATEST_AUDIT=$(ls -t "$AUDIT_DIR"/*.* 2>/dev/null | head -1 || true)
    if [[ -n "$LATEST_AUDIT" && -r "$LATEST_AUDIT" ]]; then
        echo ""
        echo -e "${YELLOW}[INFO] 最新审计日志内容:${NC}"
        praudit -l "$LATEST_AUDIT" 2>/dev/null | head -20 || echo "    解析失败或需要权限"
    fi
else
    echo -e "${YELLOW}[!]${NC} 审计日志目录不存在"
fi
echo ""

# ========================================
# 6. Event Taps (键盘记录器检测)
# ========================================
echo -e "${CYAN}=== 6. Event Taps (键盘记录器检测) ===${NC}"
echo ""

# 检查有 Accessibility 权限的应用
echo -e "${YELLOW}[INFO] Accessibility 权限应用:${NC}"
sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND auth_value=2;" 2>/dev/null | while read app; do
    echo "    $app"
done || echo "    需要 root 权限查询系统 TCC.db"

# 用户级 TCC
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND auth_value=2;" 2>/dev/null | while read app; do
    echo "    [用户级] $app"
done || true

# 检查 Input Monitoring 权限
echo ""
echo -e "${YELLOW}[INFO] Input Monitoring 权限 (键盘监控):${NC}"
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "SELECT client FROM access WHERE service='kTCCServiceListenEvent' AND auth_value=2;" 2>/dev/null | while read app; do
    echo -e "    ${RED}[!] $app${NC}"
done || echo "    无"
echo ""

# ========================================
# 7. 最近使用 (MRU)
# ========================================
echo -e "${CYAN}=== 7. 最近使用记录 ===${NC}"
echo ""

# 最近打开的应用
echo -e "${YELLOW}[INFO] 最近打开的应用:${NC}"
$VR query "SELECT FullPath, Mtime FROM glob(globs='$HOME/Library/Application Support/com.apple.sharedfilelist/*.sfl2')" 2>/dev/null | grep "FullPath" | head -10

# Finder 最近文件
FINDER_RECENTS="$HOME/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentDocuments.sfl2"
if [[ -f "$FINDER_RECENTS" ]]; then
    echo ""
    echo -e "${YELLOW}[INFO] Finder 最近文档:${NC}"
    strings "$FINDER_RECENTS" 2>/dev/null | grep -E "^/Users|^/Volumes" | head -10
fi
echo ""

# ========================================
# 8. Terminal 状态
# ========================================
echo -e "${CYAN}=== 8. Terminal 保存状态 ===${NC}"
echo ""

TERMINAL_STATE="$HOME/Library/Saved Application State/com.apple.Terminal.savedState"
if [[ -d "$TERMINAL_STATE" ]]; then
    echo -e "${YELLOW}[INFO] Terminal 状态文件:${NC}"
    ls -la "$TERMINAL_STATE" 2>/dev/null

    # 尝试提取可读内容
    echo ""
    echo -e "${YELLOW}[INFO] 可能的历史命令片段:${NC}"
    strings "$TERMINAL_STATE/windows.plist" 2>/dev/null | grep -E "^(cd |ls |cat |curl |wget |python|sudo)" | head -10 || echo "    无法提取或无内容"
else
    echo -e "${GREEN}[OK]${NC} 无 Terminal 保存状态"
fi
echo ""

# ========================================
# 9. 诊断数据 (CoreAnalytics)
# ========================================
echo -e "${CYAN}=== 9. 诊断数据 (程序执行证据) ===${NC}"
echo ""

# DiagnosticReports
DIAG_DIR="/Library/Logs/DiagnosticReports"
if [[ -d "$DIAG_DIR" ]]; then
    echo -e "${YELLOW}[INFO] 最近的崩溃报告:${NC}"
    ls -lt "$DIAG_DIR"/*.crash 2>/dev/null | head -5 || echo "    无崩溃报告"

    # 检查可疑进程崩溃
    echo ""
    echo -e "${YELLOW}[INFO] 可疑进程崩溃:${NC}"
    grep -l "osascript\|python\|curl\|wget" "$DIAG_DIR"/*.crash 2>/dev/null | head -5 || echo "    无"
fi

# Analytics 数据
ANALYTICS_DIR="/private/var/db/analyticsd/aggregates"
if [[ -d "$ANALYTICS_DIR" ]]; then
    echo ""
    echo -e "${YELLOW}[INFO] Analytics 数据文件:${NC}"
    ls -lt "$ANALYTICS_DIR" 2>/dev/null | head -5 || echo "    需要 root 权限"
fi
echo ""

# ========================================
# 10. 网络配置历史
# ========================================
echo -e "${CYAN}=== 10. 网络配置历史 ===${NC}"
echo ""

# WiFi 历史
echo -e "${YELLOW}[INFO] 已知 WiFi 网络:${NC}"
networksetup -listpreferredwirelessnetworks en0 2>/dev/null | head -15 || echo "    无法获取"

# DNS 配置
echo ""
echo -e "${YELLOW}[INFO] DNS 配置:${NC}"
scutil --dns 2>/dev/null | grep "nameserver" | head -5
echo ""

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  取证数据采集完成${NC}"
echo -e "${BLUE}========================================${NC}"
