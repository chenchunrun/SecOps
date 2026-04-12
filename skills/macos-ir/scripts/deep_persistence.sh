#!/bin/bash
# macOS 持久化深度分析脚本
# 分析所有持久化机制并标记可疑项

set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

VR="${HOME}/tools/velociraptor/velociraptor"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  macOS 持久化深度分析${NC}"
echo -e "${BLUE}  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 可疑关键词
SUSPICIOUS_KEYWORDS="curl|wget|python|ruby|perl|osascript|base64|/tmp/|nc |ncat|bash -|zsh -|sh -c"

analyze_plist() {
    local plist="$1"
    local type="$2"

    if [[ ! -f "$plist" ]]; then
        return
    fi

    local label=$(plutil -p "$plist" 2>/dev/null | grep '"Label"' | sed 's/.*=> "//' | sed 's/"//')
    local program=$(plutil -p "$plist" 2>/dev/null | grep -A1 '"ProgramArguments"' | grep -v "ProgramArguments" | head -1 | sed 's/.*"//' | sed 's/".*//')
    local interval=$(plutil -p "$plist" 2>/dev/null | grep '"StartInterval"' | sed 's/.*=> //')
    local keepalive=$(plutil -p "$plist" 2>/dev/null | grep '"KeepAlive"' | sed 's/.*=> //')
    local mtime=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$plist" 2>/dev/null)

    # 检查可疑特征
    local is_suspicious=false
    local reasons=""

    # 检查程序参数
    if plutil -p "$plist" 2>/dev/null | grep -qE "$SUSPICIOUS_KEYWORDS"; then
        is_suspicious=true
        reasons="${reasons}可疑命令; "
    fi

    # 检查短间隔 (< 60秒)
    if [[ -n "$interval" && "$interval" =~ ^[0-9]+$ && "$interval" -lt 60 ]]; then
        is_suspicious=true
        reasons="${reasons}短间隔($interval秒); "
    fi

    # 检查隐藏名称
    if [[ "$(basename "$plist")" == .* ]]; then
        is_suspicious=true
        reasons="${reasons}隐藏文件; "
    fi

    # 检查非标准标签
    if [[ -n "$label" && ! "$label" =~ ^com\.(apple|google|microsoft|docker) ]]; then
        if [[ "$label" =~ [0-9]{8,} || "$label" =~ ^[a-z]{1,3}\. ]]; then
            is_suspicious=true
            reasons="${reasons}可疑标签; "
        fi
    fi

    # 输出
    if $is_suspicious; then
        echo -e "${RED}[!] $plist${NC}"
        echo -e "    类型: $type | 标签: $label"
        echo -e "    修改时间: $mtime"
        echo -e "    ${RED}可疑原因: $reasons${NC}"
        if [[ -n "$program" ]]; then
            echo -e "    程序: $program"
        fi
        echo ""
    else
        echo -e "${GREEN}[OK]${NC} $plist"
        echo -e "    类型: $type | 标签: $label | 修改: $mtime"
    fi
}

echo -e "${CYAN}=== 1. LaunchAgents (用户级) ===${NC}"
echo ""
for plist in "$HOME/Library/LaunchAgents/"*.plist; do
    [[ -f "$plist" ]] && analyze_plist "$plist" "用户 LaunchAgent"
done
echo ""

echo -e "${CYAN}=== 2. LaunchAgents (系统级) ===${NC}"
echo ""
for plist in /Library/LaunchAgents/*.plist; do
    [[ -f "$plist" ]] && analyze_plist "$plist" "系统 LaunchAgent"
done
echo ""

echo -e "${CYAN}=== 3. LaunchDaemons ===${NC}"
echo ""
for plist in /Library/LaunchDaemons/*.plist; do
    [[ -f "$plist" ]] && analyze_plist "$plist" "LaunchDaemon"
done
echo ""

echo -e "${CYAN}=== 4. Login Items ===${NC}"
echo ""
BTM_FILE="$HOME/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"
if [[ -f "$BTM_FILE" ]]; then
    echo -e "${YELLOW}[INFO]${NC} Login Items 文件存在"
    echo "    路径: $BTM_FILE"
    echo "    修改时间: $(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$BTM_FILE" 2>/dev/null)"
    # 尝试解析 BTM 文件
    strings "$BTM_FILE" 2>/dev/null | grep -E "\.app|/Applications" | head -10 | while read line; do
        echo "    应用: $line"
    done
else
    echo -e "${GREEN}[OK]${NC} 无 Login Items 文件"
fi
echo ""

echo -e "${CYAN}=== 5. Crontab ===${NC}"
echo ""
CRON=$(crontab -l 2>/dev/null || true)
if [[ -n "$CRON" ]]; then
    echo -e "${YELLOW}[!] 发现 crontab 条目:${NC}"
    echo "$CRON" | while read line; do
        if echo "$line" | grep -qE "$SUSPICIOUS_KEYWORDS"; then
            echo -e "    ${RED}[可疑] $line${NC}"
        else
            echo "    $line"
        fi
    done
else
    echo -e "${GREEN}[OK]${NC} 无用户 crontab"
fi

# 系统 crontab
if [[ -d /var/at/tabs ]]; then
    for tab in /var/at/tabs/*; do
        [[ -f "$tab" ]] && echo -e "${YELLOW}[INFO]${NC} 系统 crontab: $tab"
    done
fi
echo ""

echo -e "${CYAN}=== 6. Periodic 脚本 ===${NC}"
echo ""
for dir in /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly; do
    if [[ -d "$dir" ]]; then
        for script in "$dir"/*; do
            if [[ -f "$script" && ! "$(basename "$script")" =~ ^[0-9]{3}\. ]]; then
                echo -e "${YELLOW}[!]${NC} 非标准 periodic 脚本: $script"
            fi
        done
    fi
done
echo -e "${GREEN}[OK]${NC} Periodic 脚本检查完成"
echo ""

echo -e "${CYAN}=== 7. 内核扩展 ===${NC}"
echo ""
THIRD_PARTY_KEXT=$(kextstat 2>/dev/null | grep -v "com.apple" | tail -n +2 || true)
if [[ -n "$THIRD_PARTY_KEXT" ]]; then
    echo -e "${YELLOW}[INFO]${NC} 第三方内核扩展:"
    echo "$THIRD_PARTY_KEXT" | awk '{print "    " $6}'
else
    echo -e "${GREEN}[OK]${NC} 无第三方内核扩展"
fi
echo ""

echo -e "${CYAN}=== 8. 系统扩展 ===${NC}"
echo ""
systemextensionsctl list 2>/dev/null | grep -v "com.apple" | tail -n +2 || echo -e "${GREEN}[OK]${NC} 无第三方系统扩展"
echo ""

echo -e "${CYAN}=== 9. Authorization 插件 ===${NC}"
echo ""
AUTH_PLUGINS=$(ls /Library/Security/SecurityAgentPlugins/ 2>/dev/null || true)
if [[ -n "$AUTH_PLUGINS" ]]; then
    echo -e "${YELLOW}[INFO]${NC} Authorization 插件:"
    echo "$AUTH_PLUGINS" | while read plugin; do
        echo "    $plugin"
    done
else
    echo -e "${GREEN}[OK]${NC} 无自定义 Authorization 插件"
fi
echo ""

echo -e "${CYAN}=== 10. Overrides.plist (高级持久化) ===${NC}"
echo ""
OVERRIDES="/var/db/launchd.db/com.apple.launchd/overrides.plist"
if [[ -f "$OVERRIDES" ]]; then
    echo -e "${YELLOW}[INFO]${NC} Overrides.plist 存在"
    echo "    路径: $OVERRIDES"
    echo "    修改时间: $(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$OVERRIDES" 2>/dev/null)"
    # 检查是否有异常覆盖
    OVERRIDE_COUNT=$(plutil -p "$OVERRIDES" 2>/dev/null | grep -c "Disabled" || echo 0)
    echo "    覆盖条目: $OVERRIDE_COUNT"
else
    echo -e "${GREEN}[OK]${NC} 无 Overrides.plist"
fi
echo ""

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  持久化分析完成${NC}"
echo -e "${BLUE}========================================${NC}"
