#!/bin/bash
# 获取扫描历史
# 用法: get_scan_history.sh [target_id] [--limit <n>]

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"

TARGET_ID="$1"
LIMIT=20

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --limit)
            LIMIT="$2"
            shift 2
            ;;
        *)
            if [ -z "$TARGET_ID" ] && [[ ! "$1" =~ ^-- ]]; then
                TARGET_ID="$1"
            fi
            shift
            ;;
    esac
done

# 确保数据库存在
if [ ! -f "$DB_FILE" ]; then
    echo "[]"
    exit 0
fi

# 构建查询
if [ -n "$TARGET_ID" ]; then
    WHERE_CLAUSE="WHERE sh.target_id = '$TARGET_ID'"
else
    WHERE_CLAUSE=""
fi

duckdb "$DB_FILE" -json << SQL
SELECT
    sh.id,
    sh.target_id,
    t.name as target_name,
    sh.scan_type,
    strftime(sh.started_at, '%Y-%m-%dT%H:%M:%SZ') as started_at,
    CASE WHEN sh.finished_at IS NOT NULL
         THEN strftime(sh.finished_at, '%Y-%m-%dT%H:%M:%SZ')
         ELSE NULL END as finished_at,
    sh.status,
    sh.new_assets,
    sh.updated_assets,
    sh.removed_assets,
    sh.error_message
FROM scan_history sh
LEFT JOIN targets t ON sh.target_id = t.id
$WHERE_CLAUSE
ORDER BY sh.started_at DESC
LIMIT $LIMIT;
SQL
