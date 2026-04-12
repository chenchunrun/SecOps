#!/bin/bash
# 读取资产记录
# 用法: read_records.sh [target_id] [--type <type>] [--risk <level>] [--stats]

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TARGET_ID=""
ASSET_TYPE=""
RISK_LEVEL=""
SHOW_STATS=false

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            ASSET_TYPE="$2"
            shift 2
            ;;
        --risk)
            RISK_LEVEL="$2"
            shift 2
            ;;
        --stats)
            SHOW_STATS=true
            shift
            ;;
        *)
            if [ -z "$TARGET_ID" ]; then
                TARGET_ID="$1"
            fi
            shift
            ;;
    esac
done

# 确保数据库存在
if [ ! -f "$DB_FILE" ]; then
    "$SCRIPT_DIR/init_db.sh" > /dev/null
    if [ "$SHOW_STATS" = true ]; then
        echo '{"total": 0, "by_type": {}, "by_risk": {}, "by_status": {}}'
    else
        echo "[]"
    fi
    exit 0
fi

# 构建 WHERE 子句
WHERE_CLAUSE="status = 'active'"
if [ -n "$TARGET_ID" ]; then
    WHERE_CLAUSE="$WHERE_CLAUSE AND target_id = '$TARGET_ID'"
fi
if [ -n "$ASSET_TYPE" ]; then
    WHERE_CLAUSE="$WHERE_CLAUSE AND type = '$ASSET_TYPE'"
fi
if [ -n "$RISK_LEVEL" ]; then
    WHERE_CLAUSE="$WHERE_CLAUSE AND risk_level = '$RISK_LEVEL'"
fi

if [ "$SHOW_STATS" = true ]; then
    # 输出统计信息
    duckdb "$DB_FILE" -json << SQL
SELECT
    (SELECT COUNT(*) FROM assets WHERE $WHERE_CLAUSE) as total,
    (SELECT json_group_object(type, cnt) FROM (
        SELECT type, COUNT(*) as cnt FROM assets WHERE $WHERE_CLAUSE GROUP BY type
    )) as by_type,
    (SELECT json_group_object(risk_level, cnt) FROM (
        SELECT risk_level, COUNT(*) as cnt FROM assets WHERE $WHERE_CLAUSE GROUP BY risk_level
    )) as by_risk,
    (SELECT json_group_object(status, cnt) FROM (
        SELECT status, COUNT(*) as cnt FROM assets GROUP BY status
    )) as by_status;
SQL
else
    # 输出完整记录
    duckdb "$DB_FILE" -json << SQL
SELECT
    id,
    target_id,
    type,
    value,
    attributes,
    tags,
    risk_level,
    risk_reason,
    strftime(first_seen_at, '%Y-%m-%dT%H:%M:%SZ') as first_seen_at,
    strftime(last_seen_at, '%Y-%m-%dT%H:%M:%SZ') as last_seen_at,
    CASE WHEN last_changed_at IS NOT NULL
         THEN strftime(last_changed_at, '%Y-%m-%dT%H:%M:%SZ')
         ELSE NULL END as last_changed_at,
    status,
    related_asset_ids,
    parent_asset_id
FROM assets
WHERE $WHERE_CLAUSE
ORDER BY last_seen_at DESC;
SQL
fi
