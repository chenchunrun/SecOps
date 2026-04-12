#!/bin/bash
# 确认/忽略变更告警
# 用法: ack_change.sh "<change_id>" [--all-target <target_id>]

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"

CHANGE_ID="$1"
ACK_ALL_TARGET=""

if [ "$1" == "--all-target" ]; then
    ACK_ALL_TARGET="$2"
    CHANGE_ID=""
fi

if [ -z "$CHANGE_ID" ] && [ -z "$ACK_ALL_TARGET" ]; then
    echo '{"error": "请提供变更 ID 或使用 --all-target <target_id>"}' >&2
    exit 1
fi

if [ ! -f "$DB_FILE" ]; then
    echo '{"error": "数据库不存在"}' >&2
    exit 1
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if [ -n "$ACK_ALL_TARGET" ]; then
    # 确认目标的所有未确认变更
    COUNT=$(duckdb "$DB_FILE" -noheader -csv "SELECT COUNT(*) FROM changes WHERE target_id = '$ACK_ALL_TARGET' AND is_acknowledged = FALSE" 2>/dev/null)

    duckdb "$DB_FILE" "UPDATE changes SET is_acknowledged = TRUE, acknowledged_at = '$TIMESTAMP' WHERE target_id = '$ACK_ALL_TARGET' AND is_acknowledged = FALSE"

    echo "{\"success\": true, \"acknowledged_count\": $COUNT, \"target_id\": \"$ACK_ALL_TARGET\"}"
else
    # 确认单个变更
    EXISTS=$(duckdb "$DB_FILE" -noheader -csv "SELECT id FROM changes WHERE id = '$CHANGE_ID' LIMIT 1" 2>/dev/null)

    if [ -z "$EXISTS" ]; then
        echo '{"error": "变更记录不存在"}' >&2
        exit 1
    fi

    duckdb "$DB_FILE" "UPDATE changes SET is_acknowledged = TRUE, acknowledged_at = '$TIMESTAMP' WHERE id = '$CHANGE_ID'"

    echo "{\"success\": true, \"change_id\": \"$CHANGE_ID\"}"
fi
