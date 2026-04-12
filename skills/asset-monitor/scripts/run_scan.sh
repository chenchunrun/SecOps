#!/bin/bash
# 执行资产扫描（供定时任务调用或手动执行）
# 用法: run_scan.sh <target_id> [scan_type]
# scan_type: full, quick, subdomain, port, scheduled

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TARGET_ID="$1"
SCAN_TYPE="${2:-full}"

if [ -z "$TARGET_ID" ]; then
    echo '{"error": "请提供目标 ID"}' >&2
    exit 1
fi

if [ ! -f "$DB_FILE" ]; then
    echo '{"error": "数据库不存在，请先添加监控目标"}' >&2
    exit 1
fi

# 获取目标信息
TARGET_INFO=$(duckdb "$DB_FILE" -json "SELECT * FROM targets WHERE id = '$TARGET_ID' LIMIT 1" 2>/dev/null)
if [ "$TARGET_INFO" == "[]" ]; then
    echo '{"error": "目标不存在"}' >&2
    exit 1
fi

# 记录扫描开始
SCAN_ID="scan_$(date +%s)_$RANDOM"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

duckdb "$DB_FILE" << SQL
INSERT INTO scan_history (id, target_id, scan_type, started_at, status)
VALUES ('$SCAN_ID', '$TARGET_ID', '$SCAN_TYPE', '$TIMESTAMP', 'running');

UPDATE targets SET last_scan_at = '$TIMESTAMP' WHERE id = '$TARGET_ID';
SQL

# 输出扫描开始信息
echo "{\"scan_id\": \"$SCAN_ID\", \"target_id\": \"$TARGET_ID\", \"scan_type\": \"$SCAN_TYPE\", \"started_at\": \"$TIMESTAMP\", \"status\": \"running\"}"
echo ""
echo "提示: 此脚本仅记录扫描状态。实际资产发现需要通过 Claude AI 使用 MCP 工具执行："
echo "  - mcp__cybersec-cloud__intel_icp_lookup: ICP 备案查询"
echo "  - mcp__cybersec-cloud__cyberspace-search: 网络空间资产搜索"
echo "  - mcp__cybersec-cloud__ops_portscan: 端口扫描"
echo ""
echo "使用方式:"
echo "  1. 在 Claude Code 中说 '扫描 <目标名称> 的资产'"
echo "  2. Claude 会自动调用 MCP 工具并保存结果"
echo ""

# 对于定时任务，这里可以集成外部扫描工具
# 例如: subfinder, httpx, nmap 等
# 当前仅作为占位符

# 标记扫描为待处理（等待 Claude AI 执行实际扫描）
duckdb "$DB_FILE" << SQL
UPDATE scan_history
SET status = 'pending', error_message = '等待 AI 代理执行实际扫描'
WHERE id = '$SCAN_ID';
SQL
