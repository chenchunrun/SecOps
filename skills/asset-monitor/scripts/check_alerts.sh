#!/bin/bash
# 检查未确认的告警
# 用法: check_alerts.sh [--target <target_id>] [--severity <level>] [--summary]

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TARGET_ID=""
SEVERITY=""
SUMMARY_ONLY=false

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            TARGET_ID="$2"
            shift 2
            ;;
        --severity)
            SEVERITY="$2"
            shift 2
            ;;
        --summary)
            SUMMARY_ONLY=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# 确保数据库存在
if [ ! -f "$DB_FILE" ]; then
    if [ "$SUMMARY_ONLY" = true ]; then
        echo '{"total": 0, "by_severity": {}, "by_type": {}}'
    else
        echo "[]"
    fi
    exit 0
fi

# 构建 WHERE 子句
WHERE_CLAUSE="is_acknowledged = FALSE"
if [ -n "$TARGET_ID" ]; then
    WHERE_CLAUSE="$WHERE_CLAUSE AND target_id = '$TARGET_ID'"
fi
if [ -n "$SEVERITY" ]; then
    WHERE_CLAUSE="$WHERE_CLAUSE AND severity = '$SEVERITY'"
fi

if [ "$SUMMARY_ONLY" = true ]; then
    # 输出摘要
    duckdb "$DB_FILE" -json << SQL
SELECT
    (SELECT COUNT(*) FROM changes WHERE $WHERE_CLAUSE) as total,
    (SELECT json_group_object(severity, cnt) FROM (
        SELECT severity, COUNT(*) as cnt FROM changes WHERE $WHERE_CLAUSE GROUP BY severity ORDER BY cnt DESC
    )) as by_severity,
    (SELECT json_group_object(change_type, cnt) FROM (
        SELECT change_type, COUNT(*) as cnt FROM changes WHERE $WHERE_CLAUSE GROUP BY change_type ORDER BY cnt DESC
    )) as by_type,
    (SELECT json_group_object(target_id, cnt) FROM (
        SELECT target_id, COUNT(*) as cnt FROM changes WHERE $WHERE_CLAUSE GROUP BY target_id ORDER BY cnt DESC
    )) as by_target;
SQL
else
    # 输出详细告警列表
    duckdb "$DB_FILE" -json << SQL
SELECT
    c.id,
    c.target_id,
    t.name as target_name,
    c.asset_id,
    c.change_type,
    c.field,
    c.old_value,
    c.new_value,
    strftime(c.detected_at, '%Y-%m-%dT%H:%M:%SZ') as detected_at,
    c.severity,
    c.description
FROM changes c
LEFT JOIN targets t ON c.target_id = t.id
WHERE $WHERE_CLAUSE
ORDER BY
    CASE c.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END,
    c.detected_at DESC
LIMIT 100;
SQL
fi
