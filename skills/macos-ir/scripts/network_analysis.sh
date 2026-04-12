#!/bin/bash
# macOS 网络连接深度分析脚本
# 补充 VQL netstat() 的不足，提供进程-连接关联

set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

VR="${HOME}/tools/velociraptor/velociraptor"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  macOS 网络连接深度分析${NC}"
echo -e "${BLUE}  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 高危端口列表
HIGH_RISK_PORTS="4444|5555|6666|7777|8888|9999|1337|31337|1234|12345|9001|8443|2222|3333"

# 已知 C2 端口 (常见远控)
C2_PORTS="4443|8080|8443|9090|5000|6000|7000|1080|1081|8000"

# 可疑国家 IP 范围 (示例)
SUSPICIOUS_RANGES="^(185\.|91\.|45\.|194\.|195\.|5\.)"

echo -e "${CYAN}=== 1. 监听端口分析 ===${NC}"
echo ""

echo -e "${YELLOW}[INFO] 所有监听端口:${NC}"
echo "----------------------------------------"
lsof -i -n -P 2>/dev/null | grep LISTEN | awk '{printf "  %-15s %-8s %s\n", $1, $10, $9}'
echo ""

# 检查高危端口
echo -e "${YELLOW}[INFO] 高危端口检查:${NC}"
echo "----------------------------------------"
HIGH_RISK=$(lsof -i -n -P 2>/dev/null | grep LISTEN | grep -E ":($HIGH_RISK_PORTS)" || true)
if [[ -n "$HIGH_RISK" ]]; then
    echo -e "${RED}[!] 发现高危监听端口:${NC}"
    echo "$HIGH_RISK" | awk '{print "  " $1 " " $9}'
else
    echo -e "${GREEN}[OK]${NC} 未发现高危监听端口"
fi
echo ""

echo -e "${CYAN}=== 2. 外部连接分析 ===${NC}"
echo ""

echo -e "${YELLOW}[INFO] 活跃外部连接:${NC}"
echo "----------------------------------------"
EXTERNAL=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1\|::1\|localhost" || true)
if [[ -n "$EXTERNAL" ]]; then
    echo "$EXTERNAL" | awk '{printf "  %-15s %-8s -> %s\n", $1, $2, $9}'
else
    echo "  无活跃外部连接"
fi
echo ""

# 提取并分析远程 IP
echo -e "${YELLOW}[INFO] 远程 IP 分析:${NC}"
echo "----------------------------------------"
REMOTE_IPS=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1\|::1" | awk -F'>' '{print $2}' | cut -d: -f1 | sort -u || true)
if [[ -n "$REMOTE_IPS" ]]; then
    while read ip; do
        if [[ -n "$ip" ]]; then
            # 检查是否为可疑 IP 范围
            if echo "$ip" | grep -qE "$SUSPICIOUS_RANGES"; then
                echo -e "  ${YELLOW}[可疑]${NC} $ip"
            else
                echo "  [正常] $ip"
            fi
        fi
    done <<< "$REMOTE_IPS"
else
    echo "  无外部 IP 连接"
fi
echo ""

echo -e "${CYAN}=== 3. 进程网络行为分析 ===${NC}"
echo ""

# 检查脚本解释器的网络连接
echo -e "${YELLOW}[INFO] 脚本解释器网络连接:${NC}"
echo "----------------------------------------"
SCRIPT_NET=$(lsof -i -n -P 2>/dev/null | grep -E "python|ruby|perl|node|bash|zsh|sh" | grep -E "ESTABLISHED|LISTEN" || true)
if [[ -n "$SCRIPT_NET" ]]; then
    echo -e "${RED}[!] 发现脚本解释器网络活动:${NC}"
    echo "$SCRIPT_NET" | awk '{print "  " $1 " (PID:" $2 ") " $9}'
else
    echo -e "${GREEN}[OK]${NC} 无脚本解释器网络连接"
fi
echo ""

# 检查临时目录程序的网络连接
echo -e "${YELLOW}[INFO] 临时目录程序网络连接:${NC}"
echo "----------------------------------------"
TMP_NET=false
while read pid; do
    if [[ -n "$pid" ]]; then
        exe=$(ps -p "$pid" -o comm= 2>/dev/null || true)
        path=$(lsof -p "$pid" 2>/dev/null | grep txt | head -1 | awk '{print $NF}' || true)
        if [[ "$path" =~ /tmp/|/private/tmp|/var/folders ]]; then
            net_info=$(lsof -i -n -P 2>/dev/null | grep "^$exe" | head -3 || true)
            if [[ -n "$net_info" ]]; then
                echo -e "${RED}[!] 临时目录程序有网络连接:${NC}"
                echo "  路径: $path"
                echo "  网络: $net_info"
                TMP_NET=true
            fi
        fi
    fi
done < <(ps -eo pid | tail -n +2)

if ! $TMP_NET; then
    echo -e "${GREEN}[OK]${NC} 无临时目录程序网络连接"
fi
echo ""

echo -e "${CYAN}=== 4. DNS 查询分析 ===${NC}"
echo ""

echo -e "${YELLOW}[INFO] DNS 相关连接:${NC}"
echo "----------------------------------------"
DNS_CONN=$(lsof -i :53 -n -P 2>/dev/null || true)
if [[ -n "$DNS_CONN" ]]; then
    echo "$DNS_CONN" | grep -v "^COMMAND" | awk '{print "  " $1 " -> " $9}'
else
    echo "  无活跃 DNS 连接"
fi
echo ""

# 检查非标准 DNS 服务器
echo -e "${YELLOW}[INFO] 配置的 DNS 服务器:${NC}"
echo "----------------------------------------"
scutil --dns 2>/dev/null | grep "nameserver" | head -5 | while read line; do
    echo "  $line"
done
echo ""

echo -e "${CYAN}=== 5. 隐藏连接检测 ===${NC}"
echo ""

# 使用 netstat 获取原始连接列表
echo -e "${YELLOW}[INFO] netstat 原始连接数:${NC}"
echo "----------------------------------------"
NETSTAT_COUNT=$(netstat -an 2>/dev/null | grep -c ESTABLISHED || echo 0)
LSOF_COUNT=$(lsof -i -n -P 2>/dev/null | grep -c ESTABLISHED || echo 0)
echo "  netstat 显示: $NETSTAT_COUNT 个 ESTABLISHED 连接"
echo "  lsof 显示: $LSOF_COUNT 个 ESTABLISHED 连接"

if [[ $NETSTAT_COUNT -gt $((LSOF_COUNT + 5)) ]]; then
    echo -e "${YELLOW}[!] netstat 比 lsof 多 $((NETSTAT_COUNT - LSOF_COUNT)) 个连接，可能存在隐藏进程${NC}"
else
    echo -e "${GREEN}[OK]${NC} 连接数一致"
fi
echo ""

echo -e "${CYAN}=== 6. 防火墙状态 ===${NC}"
echo ""

# 检查 pf 防火墙状态
PF_STATUS=$(/sbin/pfctl -s info 2>/dev/null | head -5 || echo "无法获取")
echo -e "${YELLOW}[INFO] PF 防火墙:${NC}"
echo "----------------------------------------"
if echo "$PF_STATUS" | grep -q "Status: Enabled"; then
    echo -e "${GREEN}[OK]${NC} PF 防火墙已启用"
else
    echo -e "${YELLOW}[!]${NC} PF 防火墙状态: $PF_STATUS"
fi

# 检查应用防火墙
ALF_STATUS=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
echo ""
echo -e "${YELLOW}[INFO] 应用防火墙:${NC}"
echo "----------------------------------------"
if echo "$ALF_STATUS" | grep -q "enabled"; then
    echo -e "${GREEN}[OK]${NC} 应用防火墙已启用"
else
    echo -e "${YELLOW}[!]${NC} $ALF_STATUS"
fi
echo ""

echo -e "${CYAN}=== 7. VPN/Proxy 检测 ===${NC}"
echo ""

# 检查 VPN 接口
VPN_IF=$(ifconfig 2>/dev/null | grep -E "^(utun|ppp|ipsec)" || true)
if [[ -n "$VPN_IF" ]]; then
    echo -e "${YELLOW}[INFO] VPN 接口:${NC}"
    ifconfig 2>/dev/null | grep -E "^(utun|ppp|ipsec)" -A 3 | head -20
else
    echo -e "${GREEN}[OK]${NC} 未检测到 VPN 接口"
fi
echo ""

# 检查代理设置
echo -e "${YELLOW}[INFO] 系统代理设置:${NC}"
echo "----------------------------------------"
PROXY_HTTP=$(networksetup -getwebproxy "Wi-Fi" 2>/dev/null || true)
PROXY_SOCKS=$(networksetup -getsocksfirewallproxy "Wi-Fi" 2>/dev/null || true)

if echo "$PROXY_HTTP" | grep -q "Enabled: Yes"; then
    echo "  HTTP 代理: 已启用"
    echo "$PROXY_HTTP" | grep -E "Server|Port" | sed 's/^/    /'
else
    echo "  HTTP 代理: 未启用"
fi

if echo "$PROXY_SOCKS" | grep -q "Enabled: Yes"; then
    echo "  SOCKS 代理: 已启用"
    echo "$PROXY_SOCKS" | grep -E "Server|Port" | sed 's/^/    /'
else
    echo "  SOCKS 代理: 未启用"
fi
echo ""

echo -e "${CYAN}=== 8. 常见 C2 端口检查 ===${NC}"
echo ""

C2_FOUND=$(lsof -i -n -P 2>/dev/null | grep -E ":($C2_PORTS)" | grep -v "127.0.0.1\|::1" || true)
if [[ -n "$C2_FOUND" ]]; then
    echo -e "${YELLOW}[!] 发现常见 C2 端口连接:${NC}"
    echo "$C2_FOUND" | awk '{print "  " $1 " (PID:" $2 ") " $9}'
else
    echo -e "${GREEN}[OK]${NC} 未发现常见 C2 端口连接"
fi
echo ""

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  网络分析完成${NC}"
echo -e "${BLUE}========================================${NC}"
