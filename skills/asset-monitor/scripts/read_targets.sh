#!/bin/bash
# 读取所有监控目标
# 用法: read_targets.sh [target_id]

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TARGET_ID="$1"

# 确保数据库存在
if [ ! -f "$DB_FILE" ]; then
    "$SCRIPT_DIR/init_db.sh" > /dev/null
    echo "[]"
    exit 0
fi

# 构建查询
if [ -n "$TARGET_ID" ]; then
    WHERE_CLAUSE="WHERE id = '$TARGET_ID'"
else
    WHERE_CLAUSE="WHERE status != 'deleted'"
fi

# 查询并转换为 JSON
duckdb "$DB_FILE" -json << SQL
SELECT
    id,
    name,
    type,
    seed_domains,
    seed_ips,
    keywords,
    metadata,
    config,
    status,
    strftime(created_at, '%Y-%m-%dT%H:%M:%SZ') as created_at,
    CASE WHEN last_scan_at IS NOT NULL
         THEN strftime(last_scan_at, '%Y-%m-%dT%H:%M:%SZ')
         ELSE NULL END as last_scan_at
FROM targets
$WHERE_CLAUSE
ORDER BY created_at DESC;
SQL
