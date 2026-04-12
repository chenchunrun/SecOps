#!/bin/bash
# macOS 代码签名检查脚本
# 检查应用程序和进程的签名状态

set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  macOS 代码签名检查${NC}"
echo -e "${BLUE}  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

check_signature() {
    local path="$1"
    local type="$2"

    if [[ ! -e "$path" ]]; then
        return
    fi

    local sig_info=$(codesign -dv --verbose=2 "$path" 2>&1 || true)
    local verify=$(codesign --verify --verbose "$path" 2>&1 || true)

    # 提取关键信息
    local team_id=$(echo "$sig_info" | grep "TeamIdentifier=" | cut -d= -f2)
    local authority=$(echo "$sig_info" | grep "Authority=" | head -1 | cut -d= -f2)
    local is_signed=true
    local is_valid=true
    local is_apple=false
    local is_notarized=false

    # 检查是否签名
    if echo "$sig_info" | grep -q "code object is not signed"; then
        is_signed=false
    fi

    # 检查签名是否有效
    if echo "$verify" | grep -qE "invalid signature|a sealed resource is missing"; then
        is_valid=false
    fi

    # 检查是否 Apple 签名
    if echo "$authority" | grep -qE "Apple|Software Signing"; then
        is_apple=true
    fi

    # 检查公证状态
    local notary=$(spctl --assess --verbose "$path" 2>&1 || true)
    if echo "$notary" | grep -q "accepted"; then
        is_notarized=true
    fi

    # 输出结果
    if ! $is_signed; then
        echo -e "${RED}[!] 未签名: $path${NC}"
        echo -e "    类型: $type"
        echo ""
    elif ! $is_valid; then
        echo -e "${RED}[!] 签名无效: $path${NC}"
        echo -e "    类型: $type"
        echo -e "    ${RED}错误: $verify${NC}"
        echo ""
    elif ! $is_apple && [[ "$type" != "第三方应用" ]]; then
        echo -e "${YELLOW}[!] 非 Apple 签名: $path${NC}"
        echo -e "    类型: $type | Team: $team_id"
        echo -e "    Authority: $authority"
        if $is_notarized; then
            echo -e "    ${GREEN}公证: 已通过${NC}"
        else
            echo -e "    ${YELLOW}公证: 未知${NC}"
        fi
        echo ""
    fi
}

echo -e "${CYAN}=== 1. 运行中的进程签名检查 ===${NC}"
echo ""

# 获取非系统进程的可执行路径
ps -eo pid,comm | tail -n +2 | while read pid comm; do
    # 获取完整路径
    path=$(ps -p "$pid" -o comm= 2>/dev/null || true)
    if [[ -n "$path" && ! "$path" =~ ^/System && ! "$path" =~ ^/usr/libexec && ! "$path" =~ ^/sbin ]]; then
        # 尝试获取实际路径
        real_path=$(lsof -p "$pid" 2>/dev/null | grep txt | head -1 | awk '{print $NF}' || true)
        if [[ -n "$real_path" && -f "$real_path" ]]; then
            check_signature "$real_path" "运行进程"
        fi
    fi
done 2>/dev/null || true

echo -e "${GREEN}[OK]${NC} 进程签名检查完成"
echo ""

echo -e "${CYAN}=== 2. /Applications 应用签名 ===${NC}"
echo ""

for app in /Applications/*.app; do
    if [[ -d "$app" ]]; then
        check_signature "$app" "第三方应用"
    fi
done
echo -e "${GREEN}[OK]${NC} 应用签名检查完成"
echo ""

echo -e "${CYAN}=== 3. LaunchAgent/Daemon 程序签名 ===${NC}"
echo ""

# 从 plist 中提取程序路径并检查签名
check_plist_program() {
    local plist="$1"
    if [[ ! -f "$plist" ]]; then
        return
    fi

    # 提取 ProgramArguments 的第一个元素或 Program
    local program=$(plutil -p "$plist" 2>/dev/null | grep -A1 '"ProgramArguments"' | grep -v "ProgramArguments" | head -1 | sed 's/.*"//' | sed 's/".*//' || true)
    if [[ -z "$program" ]]; then
        program=$(plutil -p "$plist" 2>/dev/null | grep '"Program"' | sed 's/.*=> "//' | sed 's/"//' || true)
    fi

    if [[ -n "$program" && -f "$program" ]]; then
        check_signature "$program" "LaunchAgent/Daemon 程序"
    fi
}

for plist in /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist "$HOME/Library/LaunchAgents/"*.plist; do
    [[ -f "$plist" ]] && check_plist_program "$plist"
done 2>/dev/null || true

echo -e "${GREEN}[OK]${NC} LaunchAgent/Daemon 程序签名检查完成"
echo ""

echo -e "${CYAN}=== 4. 临时目录可执行文件 ===${NC}"
echo ""

find /tmp /private/tmp -type f -perm +111 2>/dev/null | while read file; do
    check_signature "$file" "临时目录可执行"
done || true

echo -e "${GREEN}[OK]${NC} 临时目录检查完成"
echo ""

echo -e "${CYAN}=== 5. Quarantine 属性检查 ===${NC}"
echo ""

# 检查最近下载的文件是否被移除了 quarantine 属性
DOWNLOADS_DIR="$HOME/Downloads"
find "$DOWNLOADS_DIR" -maxdepth 2 -type f \( -name "*.app" -o -name "*.pkg" -o -name "*.dmg" \) -mtime -7 2>/dev/null | while read file; do
    quarantine=$(xattr -p com.apple.quarantine "$file" 2>/dev/null || true)
    if [[ -z "$quarantine" ]]; then
        echo -e "${YELLOW}[!] 无 Quarantine 属性: $file${NC}"
        echo "    可能被手动移除或通过非浏览器方式下载"
    fi
done || true

echo -e "${GREEN}[OK]${NC} Quarantine 检查完成"
echo ""

echo -e "${CYAN}=== 6. Hardened Runtime 检查 ===${NC}"
echo ""

# 检查关键应用是否启用 Hardened Runtime
check_hardened() {
    local app="$1"
    if [[ ! -d "$app" ]]; then
        return
    fi

    local flags=$(codesign -d --verbose=2 "$app" 2>&1 | grep "flags=" || true)
    local name=$(basename "$app")

    if echo "$flags" | grep -q "runtime"; then
        echo -e "${GREEN}[OK]${NC} Hardened Runtime: $name"
    else
        if [[ ! "$app" =~ ^/System ]]; then
            echo -e "${YELLOW}[!]${NC} 无 Hardened Runtime: $name"
        fi
    fi
}

# 检查一些常见应用
for app in /Applications/Terminal.app /Applications/Safari.app /Applications/iTerm.app /Applications/Visual\ Studio\ Code.app; do
    [[ -d "$app" ]] && check_hardened "$app"
done

echo ""

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  代码签名检查完成${NC}"
echo -e "${BLUE}========================================${NC}"
