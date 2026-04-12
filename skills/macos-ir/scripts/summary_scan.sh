#!/bin/bash
# macOS 安全检查摘要报告
# 输出简洁的单页报告，适合快速查看
# 用法: ./summary_scan.sh

VR="${HOME}/tools/velociraptor/velociraptor"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# 检查 Velociraptor
if [[ ! -x "$VR" ]]; then
    echo "错误: Velociraptor 未安装"
    exit 1
fi

# 计数器
CRITICAL=0
WARNING=0

echo ""
echo -e "${BOLD}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║          macOS 安全检查摘要报告                        ║${NC}"
echo -e "${BOLD}║          $(date '+%Y-%m-%d %H:%M:%S')                          ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# 系统信息
echo -e "${BLUE}系统:${NC} $(sw_vers -productName) $(sw_vers -productVersion) | $(hostname) | $(uname -m)"
echo ""

# 检查函数
check_item() {
    local name="$1"
    local status="$2"  # ok/warn/critical
    local detail="$3"

    case "$status" in
        ok)
            echo -e "  ${GREEN}✓${NC} $name"
            ;;
        warn)
            echo -e "  ${YELLOW}!${NC} $name ${YELLOW}($detail)${NC}"
            ((WARNING++))
            ;;
        critical)
            echo -e "  ${RED}✗${NC} $name ${RED}($detail)${NC}"
            ((CRITICAL++))
            ;;
    esac
}

echo -e "${BOLD}安全状态检查${NC}"
echo "────────────────────────────────────────────────────────"

# 1. SIP
SIP=$(csrutil status 2>/dev/null)
if echo "$SIP" | grep -q "enabled"; then
    check_item "SIP 保护" "ok"
else
    check_item "SIP 保护" "critical" "已禁用"
fi

# 2. 高危端口
PORTS_RESULT=$($VR query "SELECT Laddr.Port as Port FROM netstat() WHERE Status = 'LISTEN' AND Laddr.Port IN (4444, 5555, 6666, 1337, 31337)" 2>/dev/null)
if echo "$PORTS_RESULT" | grep -q '"Port"'; then
    PORTS=$(echo "$PORTS_RESULT" | grep -c '"Port"')
    check_item "高危端口" "critical" "$PORTS 个"
else
    check_item "高危端口" "ok"
fi

# 3. 隐藏 LaunchAgent
HIDDEN_RESULT=$($VR query "SELECT FullPath FROM glob(globs=['/Library/LaunchAgents/.*.plist', '/Users/*/Library/LaunchAgents/.*.plist'])" 2>/dev/null)
if echo "$HIDDEN_RESULT" | grep -q '"FullPath"'; then
    HIDDEN=$(echo "$HIDDEN_RESULT" | grep -c '"FullPath"')
    check_item "隐藏持久化" "critical" "$HIDDEN 个隐藏 plist"
else
    check_item "隐藏持久化" "ok"
fi

# 4. Stealer 特征
STEALER_RESULT=$($VR query "SELECT FullPath FROM glob(globs=['/tmp/pw.dat', '/private/tmp/pw.dat'])" 2>/dev/null)
if echo "$STEALER_RESULT" | grep -q '"FullPath"'; then
    check_item "Stealer 特征" "critical" "发现 pw.dat"
else
    check_item "Stealer 特征" "ok"
fi

# 5. 可疑 dylib
DYLIB_RESULT=$($VR query "SELECT FullPath FROM glob(globs=['/tmp/*.dylib', '/private/tmp/*.dylib'])" 2>/dev/null)
if echo "$DYLIB_RESULT" | grep -q '"FullPath"'; then
    DYLIB=$(echo "$DYLIB_RESULT" | grep -c '"FullPath"')
    check_item "Dylib 注入" "critical" "$DYLIB 个可疑 dylib"
else
    check_item "Dylib 注入" "ok"
fi

# 6. osascript 钓鱼 (VQL层排除自身查询)
PHISH_RESULT=$($VR query "SELECT Pid, Name FROM pslist() WHERE (CommandLine =~ 'display dialog.*password' OR CommandLine =~ 'hidden answer') AND NOT CommandLine =~ 'velociraptor'" 2>/dev/null)
if echo "$PHISH_RESULT" | grep -q '"Pid"'; then
    check_item "凭据钓鱼" "critical" "发现 osascript 钓鱼"
else
    check_item "凭据钓鱼" "ok"
fi

# 7. 最近 LaunchAgent
RECENT_RESULT=$($VR query "SELECT FullPath FROM glob(globs=['/Library/LaunchAgents/*.plist', '/Users/*/Library/LaunchAgents/*.plist']) WHERE Mtime > now() - 604800" 2>/dev/null)
if echo "$RECENT_RESULT" | grep -q '"FullPath"'; then
    RECENT=$(echo "$RECENT_RESULT" | grep -c '"FullPath"')
    check_item "新增持久化" "warn" "7天内 $RECENT 个"
else
    check_item "新增持久化" "ok"
fi

# 8. SSH Keys
SSH_RESULT=$($VR query "SELECT FullPath FROM glob(globs='/Users/*/.ssh/authorized_keys') WHERE Size > 0" 2>/dev/null)
if echo "$SSH_RESULT" | grep -q '"FullPath"'; then
    check_item "SSH 密钥" "warn" "存在 authorized_keys"
else
    check_item "SSH 密钥" "ok"
fi

# 9. 第三方内核扩展
KEXT=$(kextstat 2>/dev/null | grep -v "com.apple" | tail -n +2 | wc -l | tr -d ' ')
if [[ "$KEXT" -gt 0 ]]; then
    check_item "内核扩展" "warn" "$KEXT 个第三方"
else
    check_item "内核扩展" "ok"
fi

# 10. 外部连接
EXT_CONN=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1\|::1" | wc -l | tr -d ' ')
check_item "外部连接" "ok"

echo ""
echo "────────────────────────────────────────────────────────"

# 总结
if [[ $CRITICAL -gt 0 ]]; then
    echo -e "${RED}${BOLD}结论: 发现 $CRITICAL 个严重问题，$WARNING 个警告${NC}"
    echo -e "${RED}建议: 立即运行 ./quick_scan.sh --full 进行详细检查${NC}"
elif [[ $WARNING -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}结论: 发现 $WARNING 个警告，无严重问题${NC}"
    echo -e "${YELLOW}建议: 检查警告项是否为预期配置${NC}"
else
    echo -e "${GREEN}${BOLD}结论: 系统安全，未发现异常${NC}"
fi

echo ""
