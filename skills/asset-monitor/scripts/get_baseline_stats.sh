#!/bin/bash
# 获取两高一弱统计数据
# 用法: get_baseline_stats.sh [target_id]

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"

# 检查数据库
if [ ! -f "$DB_FILE" ]; then
    echo '{"high_vulns": 0, "high_ports": 0, "weak_passwords": 0, "last_scan": null}'
    exit 0
fi

TARGET_ID="$1"

# 构建 WHERE 子句
if [ -n "$TARGET_ID" ]; then
    WHERE_CLAUSE="WHERE target_id = '$TARGET_ID'"
else
    WHERE_CLAUSE=""
fi

# 查询统计数据
RESULT=$(duckdb "$DB_FILE" -json << SQL
SELECT
    (SELECT COUNT(*) FROM baseline_vulns WHERE status = 'open' ${TARGET_ID:+AND target_id = '$TARGET_ID'}) as high_vulns,
    (SELECT COUNT(*) FROM baseline_ports WHERE status = 'open' ${TARGET_ID:+AND target_id = '$TARGET_ID'}) as high_ports,
    (SELECT COUNT(*) FROM baseline_weak_credentials WHERE status = 'open' ${TARGET_ID:+AND target_id = '$TARGET_ID'}) as weak_passwords,
    (SELECT MAX(finished_at) FROM baseline_scans WHERE status = 'completed' ${TARGET_ID:+AND target_id = '$TARGET_ID'}) as last_scan
SQL
2>/dev/null)

if [ -n "$RESULT" ] && [ "$RESULT" != "[]" ]; then
    # 提取第一行结果
    echo "$RESULT" | jq '.[0] // {"high_vulns": 0, "high_ports": 0, "weak_passwords": 0, "last_scan": null}'
else
    echo '{"high_vulns": 0, "high_ports": 0, "weak_passwords": 0, "last_scan": null}'
fi
