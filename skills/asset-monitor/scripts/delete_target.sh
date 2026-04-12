#!/bin/bash
# 删除监控目标（软删除）
# 用法: delete_target.sh "<target_id>" [--hard]

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"

TARGET_ID="$1"
HARD_DELETE=false

if [ "$2" == "--hard" ]; then
    HARD_DELETE=true
fi

if [ -z "$TARGET_ID" ]; then
    echo '{"error": "目标 ID 不能为空"}' >&2
    exit 1
fi

if [ ! -f "$DB_FILE" ]; then
    echo '{"error": "数据库不存在"}' >&2
    exit 1
fi

# 检查目标是否存在
TARGET_NAME=$(duckdb "$DB_FILE" -noheader -csv "SELECT name FROM targets WHERE id = '$TARGET_ID' LIMIT 1" 2>/dev/null)
if [ -z "$TARGET_NAME" ]; then
    echo '{"error": "目标不存在"}' >&2
    exit 1
fi

if [ "$HARD_DELETE" = true ]; then
    # 硬删除：彻底删除数据
    duckdb "$DB_FILE" << SQL
    DELETE FROM changes WHERE target_id = '$TARGET_ID';
    DELETE FROM assets WHERE target_id = '$TARGET_ID';
    DELETE FROM scan_history WHERE target_id = '$TARGET_ID';
    DELETE FROM scheduled_tasks WHERE target_id = '$TARGET_ID';
    DELETE FROM alert_rules WHERE target_id = '$TARGET_ID';
    DELETE FROM targets WHERE id = '$TARGET_ID';
SQL
    echo "{\"success\": true, \"deleted_target\": \"$TARGET_NAME\", \"mode\": \"hard\"}"
else
    # 软删除：标记为已删除
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    duckdb "$DB_FILE" << SQL
    UPDATE targets SET status = 'deleted' WHERE id = '$TARGET_ID';
    UPDATE assets SET status = 'deleted' WHERE target_id = '$TARGET_ID';
SQL
    echo "{\"success\": true, \"deleted_target\": \"$TARGET_NAME\", \"mode\": \"soft\"}"
fi
