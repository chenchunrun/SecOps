#!/bin/bash
# 获取变更记录
# 用法: get_changes.sh [--recent] [--target <target_id>] [--unack] [--limit <n>]

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RECENT_ONLY=false
TARGET_ID=""
UNACK_ONLY=false
LIMIT=50

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --recent)
            RECENT_ONLY=true
            shift
            ;;
        --target)
            TARGET_ID="$2"
            shift 2
            ;;
        --unack)
            UNACK_ONLY=true
            shift
            ;;
        --limit)
            LIMIT="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# 确保数据库存在
if [ ! -f "$DB_FILE" ]; then
    "$SCRIPT_DIR/init_db.sh" > /dev/null
    echo "[]"
    exit 0
fi

# 构建 WHERE 子句
WHERE_CLAUSE="1=1"
if [ -n "$TARGET_ID" ]; then
    WHERE_CLAUSE="$WHERE_CLAUSE AND target_id = '$TARGET_ID'"
fi
if [ "$RECENT_ONLY" = true ]; then
    WHERE_CLAUSE="$WHERE_CLAUSE AND detected_at >= CURRENT_TIMESTAMP - INTERVAL '24 HOUR'"
fi
if [ "$UNACK_ONLY" = true ]; then
    WHERE_CLAUSE="$WHERE_CLAUSE AND is_acknowledged = FALSE"
fi

# 查询变更记录
duckdb "$DB_FILE" -json << SQL
SELECT
    id,
    target_id,
    asset_id,
    change_type,
    field,
    old_value,
    new_value,
    strftime(detected_at, '%Y-%m-%dT%H:%M:%SZ') as detected_at,
    severity,
    description,
    is_acknowledged,
    CASE WHEN acknowledged_at IS NOT NULL
         THEN strftime(acknowledged_at, '%Y-%m-%dT%H:%M:%SZ')
         ELSE NULL END as acknowledged_at
FROM changes
WHERE $WHERE_CLAUSE
ORDER BY detected_at DESC
LIMIT $LIMIT;
SQL
