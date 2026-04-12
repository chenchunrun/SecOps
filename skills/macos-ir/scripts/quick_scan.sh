#!/bin/bash
# macOS 快速安全扫描脚本 v2.1
# 优化: 减少误报，增加白名单过滤
# 用法: ./quick_scan.sh [--full]

set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

VR="${HOME}/tools/velociraptor/velociraptor"
FULL_SCAN=false

[[ "$1" == "--full" ]] && FULL_SCAN=true

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  macOS 快速安全扫描 v2.1${NC}"
echo -e "${BLUE}  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 检查 Velociraptor
if [[ ! -x "$VR" ]]; then
    echo -e "${RED}[!] Velociraptor 未安装: $VR${NC}"
    echo "    安装: curl -L -o ~/tools/velociraptor/velociraptor https://github.com/Velocidex/velociraptor/releases/download/v0.73.3/velociraptor-v0.73.3-darwin-arm64"
    exit 1
fi

ISSUES=0

echo -e "${BLUE}[1/10] 系统信息${NC}"
echo "----------------------------------------"
sw_vers
echo "主机名: $(hostname)"
echo "架构: $(uname -m)"
echo ""

echo -e "${BLUE}[2/10] SIP 状态${NC}"
echo "----------------------------------------"
SIP_STATUS=$(csrutil status 2>/dev/null || echo "unknown")
if echo "$SIP_STATUS" | grep -q "enabled"; then
    echo -e "${GREEN}[OK] $SIP_STATUS${NC}"
else
    echo -e "${RED}[!] $SIP_STATUS${NC}"
    ((ISSUES++))
fi
echo ""

echo -e "${BLUE}[3/10] 可疑进程检查${NC}"
echo "----------------------------------------"
# 优化: 排除已知正常应用和系统进程
# 白名单: Chrome, Lark, Safari, mdworker, velociraptor, python3 (uv工具), node, WebKit, System
SUSPICIOUS=$($VR query "SELECT Pid, Name, Exe, CommandLine FROM pslist() WHERE
  (Exe =~ '/tmp/[^C]|/private/tmp/[^C]' OR Name =~ '^\\.')
  AND NOT Exe =~ 'Chrome|Lark|Safari|mdworker|velociraptor|python3|node|dart|WebKit|System|Library/Developer'
  AND NOT Name =~ 'velociraptor|python|node|zsh|bash'" 2>/dev/null | grep -E '"Pid"|"Name"|"Exe"|"CommandLine"' | grep -v "velociraptor" || true)

# 额外检查真正的恶意特征
MALICIOUS=$($VR query "SELECT Pid, Name, CommandLine FROM pslist() WHERE
  CommandLine =~ 'osascript.*display dialog.*password|hidden answer|curl.*\\|.*bash|wget.*\\|.*sh'
  AND NOT CommandLine =~ 'velociraptor query'" 2>/dev/null | grep -E '"Pid"' | grep -v "velociraptor" || true)

if [[ -n "$MALICIOUS" ]]; then
    echo -e "${RED}[!] 发现恶意进程特征:${NC}"
    echo "$MALICIOUS"
    ((ISSUES++))
elif [[ -n "$SUSPICIOUS" && ! "$SUSPICIOUS" =~ "velociraptor" ]]; then
    echo -e "${YELLOW}[!] 发现可疑进程:${NC}"
    echo "$SUSPICIOUS" | head -20
else
    echo -e "${GREEN}[OK] 未发现可疑进程${NC}"
fi
echo ""

echo -e "${BLUE}[4/10] 高危端口监听${NC}"
echo "----------------------------------------"
HIGH_RISK_PORTS=$($VR query "SELECT Laddr.Port as Port FROM netstat() WHERE Status = 'LISTEN' AND Laddr.Port IN (4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337)" 2>/dev/null | grep '"Port"' || true)
if [[ -n "$HIGH_RISK_PORTS" ]]; then
    echo -e "${RED}[!] 发现高危端口:${NC}"
    echo "$HIGH_RISK_PORTS" | sed 's/.*"Port": /  端口: /' | sed 's/,.*//'
    ((ISSUES++))
else
    echo -e "${GREEN}[OK] 未发现高危端口${NC}"
fi
echo ""

echo -e "${BLUE}[5/10] 最近 LaunchAgent (7天)${NC}"
echo "----------------------------------------"
RECENT_LA=$($VR query "SELECT FullPath, Mtime FROM glob(globs=['/Library/LaunchAgents/*.plist', '/Library/LaunchDaemons/*.plist', '$HOME/Library/LaunchAgents/*.plist']) WHERE Mtime > now() - 604800" 2>/dev/null | grep "FullPath" || true)
if [[ -n "$RECENT_LA" ]]; then
    echo -e "${YELLOW}[INFO] 最近新增的 LaunchAgent:${NC}"
    echo "$RECENT_LA" | sed 's/.*"FullPath": "/  /' | sed 's/".*//'
    # 不计入问题数，仅信息提示
else
    echo -e "${GREEN}[OK] 无最近新增${NC}"
fi
echo ""

echo -e "${BLUE}[6/10] 隐藏的 LaunchAgent${NC}"
echo "----------------------------------------"
HIDDEN_LA=$($VR query "SELECT FullPath FROM glob(globs=['/Library/LaunchAgents/.*.plist', '/Library/LaunchDaemons/.*.plist', '$HOME/Library/LaunchAgents/.*.plist'])" 2>/dev/null | grep "FullPath" || true)
if [[ -n "$HIDDEN_LA" ]]; then
    echo -e "${RED}[!] 发现隐藏的 LaunchAgent:${NC}"
    echo "$HIDDEN_LA" | sed 's/.*"FullPath": "/  /' | sed 's/".*//'
    ((ISSUES++))
else
    echo -e "${GREEN}[OK] 未发现隐藏项${NC}"
fi
echo ""

echo -e "${BLUE}[7/10] SSH authorized_keys${NC}"
echo "----------------------------------------"
SSH_KEYS=$($VR query "SELECT FullPath, Size FROM glob(globs='/Users/*/.ssh/authorized_keys') WHERE Size > 0" 2>/dev/null | grep "FullPath" || true)
if [[ -n "$SSH_KEYS" ]]; then
    echo -e "${YELLOW}[INFO] 发现 SSH 授权密钥:${NC}"
    echo "$SSH_KEYS" | sed 's/.*"FullPath": "/  /' | sed 's/".*//'
    # 不计入问题数，仅信息提示
else
    echo -e "${GREEN}[OK] 未发现 SSH 授权密钥${NC}"
fi
echo ""

echo -e "${BLUE}[8/10] Stealer 特征文件${NC}"
echo "----------------------------------------"
STEALER_FILES=$($VR query "SELECT FullPath FROM glob(globs=['/tmp/pw.dat', '/private/tmp/pw.dat', '$HOME/pw.dat', '/tmp/cookies*', '/tmp/*wallet*'])" 2>/dev/null | grep "FullPath" || true)
if [[ -n "$STEALER_FILES" ]]; then
    echo -e "${RED}[!] 发现 Stealer 特征文件:${NC}"
    echo "$STEALER_FILES" | sed 's/.*"FullPath": "/  /' | sed 's/".*//'
    ((ISSUES++))
else
    echo -e "${GREEN}[OK] 未发现 Stealer 特征${NC}"
fi
echo ""

echo -e "${BLUE}[9/10] 可疑 dylib 文件${NC}"
echo "----------------------------------------"
DYLIB_FILES=$($VR query "SELECT FullPath FROM glob(globs=['/tmp/*.dylib', '/private/tmp/*.dylib', '$HOME/.*.dylib'])" 2>/dev/null | grep "FullPath" || true)
if [[ -n "$DYLIB_FILES" ]]; then
    echo -e "${RED}[!] 发现可疑 dylib:${NC}"
    echo "$DYLIB_FILES" | sed 's/.*"FullPath": "/  /' | sed 's/".*//'
    ((ISSUES++))
else
    echo -e "${GREEN}[OK] 未发现可疑 dylib${NC}"
fi
echo ""

echo -e "${BLUE}[10/10] 外部连接${NC}"
echo "----------------------------------------"
# 简化输出，只显示进程名和目标
EXTERNAL=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1\|::1\|localhost" | awk '{print $1}' | sort -u | head -10 || true)
if [[ -n "$EXTERNAL" ]]; then
    echo -e "${YELLOW}[INFO] 有外部连接的进程:${NC}"
    echo "$EXTERNAL" | sed 's/^/  /'
else
    echo -e "${GREEN}[OK] 无外部连接${NC}"
fi
echo ""

# 完整扫描模式
if $FULL_SCAN; then
    echo -e "${BLUE}[FULL] TCC 数据库检查${NC}"
    echo "----------------------------------------"
    TCC_RECENT=$($VR query "SELECT FullPath, Mtime FROM glob(globs='$HOME/Library/Application Support/com.apple.TCC/TCC.db') WHERE Mtime > now() - 604800" 2>/dev/null | grep "FullPath" || true)
    if [[ -n "$TCC_RECENT" ]]; then
        echo -e "${YELLOW}[INFO] TCC 数据库最近被修改${NC}"
    else
        echo -e "${GREEN}[OK] TCC 数据库正常${NC}"
    fi
    echo ""

    echo -e "${BLUE}[FULL] 非 Apple 内核扩展${NC}"
    echo "----------------------------------------"
    KEXT=$(kextstat 2>/dev/null | grep -v "com.apple" | tail -n +2 || true)
    if [[ -n "$KEXT" ]]; then
        echo -e "${YELLOW}[INFO] 第三方内核扩展:${NC}"
        echo "$KEXT" | awk '{print "  " $6}'
    else
        echo -e "${GREEN}[OK] 无第三方内核扩展${NC}"
    fi
    echo ""

    echo -e "${BLUE}[FULL] Crontab 检查${NC}"
    echo "----------------------------------------"
    CRON=$(crontab -l 2>/dev/null || true)
    if [[ -n "$CRON" ]]; then
        echo -e "${YELLOW}[INFO] 发现 crontab 条目:${NC}"
        echo "$CRON"
    else
        echo -e "${GREEN}[OK] 无 crontab 条目${NC}"
    fi
    echo ""
fi

echo -e "${BLUE}========================================${NC}"
if [[ $ISSUES -eq 0 ]]; then
    echo -e "${GREEN}  扫描完成: 未发现安全问题${NC}"
else
    echo -e "${RED}  扫描完成: 发现 $ISSUES 个安全问题${NC}"
fi
echo -e "${BLUE}========================================${NC}"
