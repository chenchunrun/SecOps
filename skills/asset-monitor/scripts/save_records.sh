#!/bin/bash
# 保存资产记录并检测变更
# 用法: save_records.sh '<json_array>'
# 记录格式: {"target_id": "...", "type": "subdomain|ip|domain|...", "value": "...", "attributes": {...}, "risk_level": "safe|low|medium|high|critical"}

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

NEW_RECORDS="$1"

if [ -z "$NEW_RECORDS" ]; then
    echo '{"error": "记录数据不能为空"}' >&2
    exit 1
fi

# 确保数据库存在
if [ ! -f "$DB_FILE" ]; then
    "$SCRIPT_DIR/init_db.sh" > /dev/null
fi

# 验证 JSON 格式
if ! echo "$NEW_RECORDS" | jq empty 2>/dev/null; then
    echo '{"error": "无效的 JSON 格式"}' >&2
    exit 1
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
NEW_COUNT=0
UPDATED_COUNT=0
CHANGES="[]"

# 处理每条新记录
while IFS= read -r record; do
    [ -z "$record" ] && continue

    RECORD_VALUE=$(echo "$record" | jq -r '.value')
    RECORD_TYPE=$(echo "$record" | jq -r '.type')
    TARGET_ID=$(echo "$record" | jq -r '.target_id')
    ATTRIBUTES=$(echo "$record" | jq -c '.attributes // {}')
    TAGS=$(echo "$record" | jq -c '.tags // []')
    RISK_LEVEL=$(echo "$record" | jq -r '.risk_level // "unknown"')
    RISK_REASON=$(echo "$record" | jq -r '.risk_reason // empty')

    # 检查是否已存在
    EXISTING_ID=$(duckdb "$DB_FILE" -noheader -csv "SELECT id FROM assets WHERE target_id = '$TARGET_ID' AND type = '$RECORD_TYPE' AND value = '$RECORD_VALUE' LIMIT 1" 2>/dev/null)

    if [ -z "$EXISTING_ID" ]; then
        # 新资产
        RECORD_ID="rec_$(date +%s)_$RANDOM"

        # 转义字符串
        ATTRIBUTES_ESC=$(echo "$ATTRIBUTES" | sed "s/'/''/g")
        TAGS_ESC=$(echo "$TAGS" | sed "s/'/''/g")
        RISK_REASON_ESC=$(echo "$RISK_REASON" | sed "s/'/''/g")
        VALUE_ESC=$(echo "$RECORD_VALUE" | sed "s/'/''/g")

        # 插入资产
        duckdb "$DB_FILE" << SQL
INSERT INTO assets (id, target_id, type, value, attributes, tags, risk_level, risk_reason, first_seen_at, last_seen_at, status)
VALUES ('$RECORD_ID', '$TARGET_ID', '$RECORD_TYPE', '$VALUE_ESC', '$ATTRIBUTES_ESC', '$TAGS_ESC', '$RISK_LEVEL', '$RISK_REASON_ESC', '$TIMESTAMP', '$TIMESTAMP', 'active');
SQL

        NEW_COUNT=$((NEW_COUNT + 1))

        # 记录变更
        CHANGE_ID="chg_$(date +%s)_$RANDOM"
        DESCRIPTION="发现新${RECORD_TYPE}: ${RECORD_VALUE}"
        DESC_ESC=$(echo "$DESCRIPTION" | sed "s/'/''/g")

        duckdb "$DB_FILE" << SQL
INSERT INTO changes (id, target_id, asset_id, change_type, field, old_value, new_value, detected_at, severity, description, is_acknowledged)
VALUES ('$CHANGE_ID', '$TARGET_ID', '$RECORD_ID', 'added', 'value', NULL, '$VALUE_ESC', '$TIMESTAMP', 'info', '$DESC_ESC', FALSE);
SQL

        # 添加到变更列表
        CHANGE_JSON=$(jq -n \
            --arg id "$CHANGE_ID" \
            --arg tid "$TARGET_ID" \
            --arg aid "$RECORD_ID" \
            --arg val "$RECORD_VALUE" \
            --arg desc "$DESCRIPTION" \
            --arg ts "$TIMESTAMP" \
            '{
                id: $id,
                target_id: $tid,
                asset_id: $aid,
                change_type: "added",
                field: "value",
                old_value: null,
                new_value: $val,
                detected_at: $ts,
                severity: "info",
                description: $desc,
                is_acknowledged: false
            }')
        CHANGES=$(echo "$CHANGES" | jq --argjson c "$CHANGE_JSON" '. += [$c]')
    else
        # 已存在，更新 last_seen_at
        duckdb "$DB_FILE" "UPDATE assets SET last_seen_at = '$TIMESTAMP' WHERE id = '$EXISTING_ID'"
        UPDATED_COUNT=$((UPDATED_COUNT + 1))
    fi
done < <(echo "$NEW_RECORDS" | jq -c '.[]')

# 获取总记录数
TOTAL=$(duckdb "$DB_FILE" -noheader -csv "SELECT COUNT(*) FROM assets WHERE status = 'active'" 2>/dev/null)

# 输出结果
cat << EOF
{
  "success": true,
  "new_assets": $NEW_COUNT,
  "updated_assets": $UPDATED_COUNT,
  "total_records": $TOTAL,
  "changes": $CHANGES
}
EOF
