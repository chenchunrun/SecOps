#!/bin/bash
# Linux Webshell 检测脚本
# 参考: LinuxCheck, d-eyes
# 支持检测: 菜刀/蚁剑/冰蝎/哥斯拉/Weevely 等
# 用法: bash webshell_check.sh [目录]

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# 扫描目录
SCAN_DIR="${1:-/var/www}"

print_section() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Webshell 检测 - $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${CYAN}  扫描目录: $SCAN_DIR${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ ! -d "$SCAN_DIR" ]]; then
    echo -e "${RED}[!] 目录不存在: $SCAN_DIR${NC}"
    echo "用法: bash webshell_check.sh [目录]"
    echo "默认目录: /var/www"
    exit 1
fi

ISSUES=0

#===============================================================================
# 1. PHP Webshell 检测
#===============================================================================
print_section "1. PHP Webshell 检测"

echo -e "${YELLOW}[危险函数检测]${NC}"
# 一句话木马特征
dangerous_funcs='eval\s*\(|assert\s*\(|preg_replace\s*\(.*\/e|create_function\s*\(|call_user_func\s*\(|call_user_func_array\s*\('
php_shells=$(grep -rlE "$dangerous_funcs" "$SCAN_DIR" --include='*.php' --include='*.phtml' --include='*.php5' --include='*.phar' 2>/dev/null | head -20 || true)

if [[ -n "$php_shells" ]]; then
    echo -e "${RED}[!] 发现可疑 PHP 文件:${NC}"
    echo "$php_shells" | while read f; do
        echo -e "${YELLOW}--- $f ---${NC}"
        grep -nE "$dangerous_funcs" "$f" 2>/dev/null | head -3
        ((ISSUES++)) || true
    done
else
    echo "未发现危险函数"
fi

echo -e "\n${YELLOW}[命令执行函数]${NC}"
cmd_funcs='system\s*\(|passthru\s*\(|shell_exec\s*\(|exec\s*\(|popen\s*\(|proc_open\s*\('
cmd_shells=$(grep -rlE "$cmd_funcs" "$SCAN_DIR" --include='*.php' 2>/dev/null | head -20 || true)

if [[ -n "$cmd_shells" ]]; then
    echo -e "${YELLOW}[!] 发现命令执行函数:${NC}"
    echo "$cmd_shells" | while read f; do
        echo "$f"
    done
else
    echo "未发现"
fi

#===============================================================================
# 2. 中国菜刀 (Chopper) 特征检测
#===============================================================================
print_section "2. 中国菜刀 (Chopper) 检测"

echo -e "${YELLOW}[菜刀一句话特征]${NC}"
# 经典菜刀特征: <?php @eval($_POST['xxx']);?>
chopper_pattern='@eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[|@assert\s*\(\s*\$_(POST|GET|REQUEST)'
chopper_shells=$(grep -rlE "$chopper_pattern" "$SCAN_DIR" --include='*.php' 2>/dev/null | head -10 || true)

if [[ -n "$chopper_shells" ]]; then
    echo -e "${RED}[!] 发现菜刀特征:${NC}"
    echo "$chopper_shells" | while read f; do
        echo -e "${YELLOW}--- $f ---${NC}"
        grep -nE "$chopper_pattern" "$f" 2>/dev/null | head -2
        ((ISSUES++)) || true
    done
else
    echo "未发现"
fi

#===============================================================================
# 3. 蚁剑 (AntSword) 特征检测
#===============================================================================
print_section "3. 蚁剑 (AntSword) 检测"

echo -e "${YELLOW}[蚁剑特征]${NC}"
# 蚁剑特征: base64_decode + eval 组合, @ini_set
antsword_pattern='base64_decode\s*\(\s*\$_(POST|GET|REQUEST)|@ini_set\s*\(\s*["\x27]display_errors|str_replace\s*\(.*chr\s*\('
antsword_shells=$(grep -rlE "$antsword_pattern" "$SCAN_DIR" --include='*.php' 2>/dev/null | head -10 || true)

if [[ -n "$antsword_shells" ]]; then
    echo -e "${RED}[!] 发现蚁剑特征:${NC}"
    echo "$antsword_shells" | while read f; do
        echo -e "${YELLOW}--- $f ---${NC}"
        grep -nE "$antsword_pattern" "$f" 2>/dev/null | head -2
        ((ISSUES++)) || true
    done
else
    echo "未发现"
fi

# 蚁剑编码器特征
echo -e "\n${YELLOW}[蚁剑编码器特征]${NC}"
encoder_pattern='gzinflate\s*\(\s*base64_decode|str_rot13\s*\(\s*base64_decode|gzuncompress\s*\(\s*base64_decode'
encoder_shells=$(grep -rlE "$encoder_pattern" "$SCAN_DIR" --include='*.php' 2>/dev/null | head -10 || true)

if [[ -n "$encoder_shells" ]]; then
    echo -e "${YELLOW}[!] 发现编码特征:${NC}"
    echo "$encoder_shells"
else
    echo "未发现"
fi

#===============================================================================
# 4. 冰蝎 (Behinder) 特征检测
#===============================================================================
print_section "4. 冰蝎 (Behinder) 检测"

echo -e "${YELLOW}[冰蝎2.0特征]${NC}"
# 冰蝎2特征: openssl_decrypt + AES
behinder2_pattern='openssl_decrypt|mcrypt_decrypt|AES-128-ECB|Decrypt\s*\(\s*\$'
behinder2_shells=$(grep -rlE "$behinder2_pattern" "$SCAN_DIR" --include='*.php' 2>/dev/null | head -10 || true)

if [[ -n "$behinder2_shells" ]]; then
    echo -e "${RED}[!] 发现冰蝎2特征:${NC}"
    echo "$behinder2_shells" | while read f; do
        echo "$f"
        ((ISSUES++)) || true
    done
else
    echo "未发现"
fi

echo -e "\n${YELLOW}[冰蝎3.0/4.0特征]${NC}"
# 冰蝎3/4特征: 类定义 + 反序列化
behinder3_pattern='class\s+\w+\s*\{.*function\s+__destruct|unserialize\s*\(\s*\$_(POST|GET)|new\s+ReflectionClass'
behinder3_shells=$(grep -rlE "$behinder3_pattern" "$SCAN_DIR" --include='*.php' 2>/dev/null | head -10 || true)

if [[ -n "$behinder3_shells" ]]; then
    echo -e "${RED}[!] 发现冰蝎3/4特征:${NC}"
    echo "$behinder3_shells"
else
    echo "未发现"
fi

# 冰蝎流量特征 (文件内容)
echo -e "\n${YELLOW}[冰蝎密钥特征]${NC}"
# 默认密钥特征
key_pattern='e45e329feb5d925b|rebeyond|behinder'
key_files=$(grep -rlE "$key_pattern" "$SCAN_DIR" --include='*.php' 2>/dev/null | head -5 || true)

if [[ -n "$key_files" ]]; then
    echo -e "${RED}[!] 发现冰蝎默认密钥:${NC}"
    echo "$key_files"
    ((ISSUES++))
else
    echo "未发现"
fi

#===============================================================================
# 5. 哥斯拉 (Godzilla) 特征检测
#===============================================================================
print_section "5. 哥斯拉 (Godzilla) 检测"

echo -e "${YELLOW}[哥斯拉PHP特征]${NC}"
# 哥斯拉特征
godzilla_pattern='session_start\s*\(\s*\)\s*;.*@set_time_limit|pass\s*=\s*["\x27].*["\x27]\s*;.*@eval|methodName|getBasicsInfo|execCommand'
godzilla_shells=$(grep -rlE "$godzilla_pattern" "$SCAN_DIR" --include='*.php' 2>/dev/null | head -10 || true)

if [[ -n "$godzilla_shells" ]]; then
    echo -e "${RED}[!] 发现哥斯拉特征:${NC}"
    echo "$godzilla_shells" | while read f; do
        echo -e "${YELLOW}--- $f ---${NC}"
        grep -nE 'pass\s*=|key\s*=' "$f" 2>/dev/null | head -2
        ((ISSUES++)) || true
    done
else
    echo "未发现"
fi

# 哥斯拉加密特征
echo -e "\n${YELLOW}[哥斯拉加密特征]${NC}"
godzilla_enc='xor_encode|rc4_encrypt|base64_encode\s*\(\s*serialize'
godzilla_enc_files=$(grep -rlE "$godzilla_enc" "$SCAN_DIR" --include='*.php' 2>/dev/null | head -5 || true)

if [[ -n "$godzilla_enc_files" ]]; then
    echo -e "${YELLOW}[!] 发现加密特征:${NC}"
    echo "$godzilla_enc_files"
else
    echo "未发现"
fi

#===============================================================================
# 6. Weevely 特征检测
#===============================================================================
print_section "6. Weevely 检测"

echo -e "${YELLOW}[Weevely特征]${NC}"
# Weevely 特征: 混淆的 eval + 字符串拼接
weevely_pattern='\$\w\s*=\s*str_replace\s*\(.*\$\w\s*=\s*str_replace|\$\w{1,2}\s*\.\s*\$\w{1,2}\s*\.\s*\$\w{1,2}.*eval'
weevely_shells=$(grep -rlE "$weevely_pattern" "$SCAN_DIR" --include='*.php' 2>/dev/null | head -10 || true)

if [[ -n "$weevely_shells" ]]; then
    echo -e "${RED}[!] 发现 Weevely 特征:${NC}"
    echo "$weevely_shells"
    ((ISSUES++))
else
    echo "未发现"
fi

#===============================================================================
# 7. JSP Webshell 检测
#===============================================================================
print_section "7. JSP Webshell 检测"

echo -e "${YELLOW}[JSP 危险类]${NC}"
jsp_pattern='Runtime\.getRuntime\(\)|ProcessBuilder|\.exec\s*\(|getParameter.*cmd|request\.getParameter'
jsp_shells=$(grep -rlE "$jsp_pattern" "$SCAN_DIR" --include='*.jsp' --include='*.jspx' 2>/dev/null | head -10 || true)

if [[ -n "$jsp_shells" ]]; then
    echo -e "${RED}[!] 发现可疑 JSP 文件:${NC}"
    echo "$jsp_shells" | while read f; do
        echo -e "${YELLOW}--- $f ---${NC}"
        grep -nE "$jsp_pattern" "$f" 2>/dev/null | head -3
        ((ISSUES++)) || true
    done
else
    echo "未发现"
fi

echo -e "\n${YELLOW}[JSP 冰蝎/哥斯拉特征]${NC}"
jsp_behinder='AES/ECB|Cipher\.getInstance|defineClass|ClassLoader'
jsp_beh_shells=$(grep -rlE "$jsp_behinder" "$SCAN_DIR" --include='*.jsp' 2>/dev/null | head -5 || true)

if [[ -n "$jsp_beh_shells" ]]; then
    echo -e "${YELLOW}[!] 发现 JSP 加密马特征:${NC}"
    echo "$jsp_beh_shells"
else
    echo "未发现"
fi

#===============================================================================
# 8. ASP/ASPX Webshell 检测
#===============================================================================
print_section "8. ASP/ASPX Webshell 检测"

echo -e "${YELLOW}[ASP/ASPX 危险函数]${NC}"
asp_pattern='Execute\s*\(|Eval\s*\(|CreateObject\s*\(|WScript\.Shell|cmd\.exe|Process\.Start'
asp_shells=$(grep -rlE "$asp_pattern" "$SCAN_DIR" --include='*.asp' --include='*.aspx' --include='*.ashx' 2>/dev/null | head -10 || true)

if [[ -n "$asp_shells" ]]; then
    echo -e "${RED}[!] 发现可疑 ASP/ASPX 文件:${NC}"
    echo "$asp_shells"
    ((ISSUES++))
else
    echo "未发现"
fi

#===============================================================================
# 9. 可疑文件名检测
#===============================================================================
print_section "9. 可疑文件名检测"

echo -e "${YELLOW}[可疑文件名模式]${NC}"
suspicious_names=$(find "$SCAN_DIR" -type f \( \
    -name '*shell*' -o -name '*hack*' -o -name '*backdoor*' -o \
    -name '*c99*' -o -name '*r57*' -o -name '*b374k*' -o \
    -name '*wso*' -o -name '*spy*' -o -name '*cmd*' -o \
    -name '*.php.*' -o -name '*eval*' \
    \) 2>/dev/null | grep -E '\.(php|jsp|asp|aspx)' | head -20 || true)

if [[ -n "$suspicious_names" ]]; then
    echo -e "${YELLOW}[!] 发现可疑文件名:${NC}"
    echo "$suspicious_names"
else
    echo "未发现"
fi

echo -e "\n${YELLOW}[隐藏的 Web 文件]${NC}"
hidden_web=$(find "$SCAN_DIR" -name '.*' -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.asp' \) 2>/dev/null | head -10 || true)

if [[ -n "$hidden_web" ]]; then
    echo -e "${RED}[!] 发现隐藏 Web 文件:${NC}"
    echo "$hidden_web"
    ((ISSUES++))
else
    echo "未发现"
fi

#===============================================================================
# 10. 最近修改的 Web 文件
#===============================================================================
print_section "10. 最近修改的 Web 文件 (7天)"

echo -e "${YELLOW}[PHP 文件]${NC}"
find "$SCAN_DIR" -name '*.php' -type f -mtime -7 -ls 2>/dev/null | head -15 || echo "未发现"

echo -e "\n${YELLOW}[JSP 文件]${NC}"
find "$SCAN_DIR" -name '*.jsp' -type f -mtime -7 -ls 2>/dev/null | head -10 || echo "未发现"

#===============================================================================
# 11. 文件权限异常检测
#===============================================================================
print_section "11. 文件权限异常"

echo -e "${YELLOW}[777 权限 Web 文件]${NC}"
find "$SCAN_DIR" -type f \( -name '*.php' -o -name '*.jsp' \) -perm 777 -ls 2>/dev/null | head -10 || echo "未发现"

echo -e "\n${YELLOW}[Web 目录下的可执行文件]${NC}"
find "$SCAN_DIR" -type f -executable \( -name '*.php' -o -name '*.sh' -o -name '*.py' \) -ls 2>/dev/null | head -10 || echo "未发现"

#===============================================================================
# 总结
#===============================================================================
print_section "检测完成"

echo "扫描目录: $SCAN_DIR"
echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
if [[ $ISSUES -gt 0 ]]; then
    echo -e "${RED}[!] 发现 $ISSUES 项 Webshell 相关问题${NC}"
    echo ""
    echo -e "${YELLOW}处置建议:${NC}"
    echo "  1. 备份可疑文件进行分析"
    echo "  2. 删除确认的 Webshell"
    echo "  3. 检查 Web 日志定位入侵时间"
    echo "  4. 修复上传漏洞/权限配置"
    echo "  5. 更新 Web 应用和框架"
else
    echo -e "${GREEN}[✓] 未发现 Webshell${NC}"
fi
echo ""
echo -e "${YELLOW}Webshell 检测 ATT&CK 映射:${NC}"
echo "  T1505.003 - Web Shell"
echo "  T1059.004 - Unix Shell"
echo "  T1059.001 - PowerShell (ASPX)"

echo ""
echo -e "${YELLOW}支持检测的 Webshell 类型:${NC}"
echo "  - 中国菜刀 (Chopper)"
echo "  - 蚁剑 (AntSword)"
echo "  - 冰蝎 (Behinder) 2.0/3.0/4.0"
echo "  - 哥斯拉 (Godzilla)"
echo "  - Weevely"
echo "  - C99/R57/B374k 等经典 Webshell"
