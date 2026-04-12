#!/bin/bash
# 设置定时扫描任务
# 用法: setup_scheduler.sh <target_id> <interval_hours> [--enable|--disable|--status]
# macOS 使用 launchd, Linux 使用 cron

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLIST_DIR="${HOME}/Library/LaunchAgents"
CRON_MARKER="# asset-monitor-scheduled"

TARGET_ID="$1"
INTERVAL_HOURS="${2:-24}"
ACTION="${3:---enable}"

if [ -z "$TARGET_ID" ]; then
    echo '{"error": "请提供目标 ID"}' >&2
    exit 1
fi

# 生成任务标识
TASK_ID="com.cybersec.asset-monitor.${TARGET_ID}"
PLIST_FILE="${PLIST_DIR}/${TASK_ID}.plist"

show_status() {
    if [ "$(uname)" == "Darwin" ]; then
        # macOS
        if [ -f "$PLIST_FILE" ]; then
            LOADED=$(launchctl list | grep "$TASK_ID" | wc -l | tr -d ' ')
            if [ "$LOADED" -gt 0 ]; then
                echo '{"status": "active", "scheduler": "launchd", "plist": "'"$PLIST_FILE"'"}'
            else
                echo '{"status": "inactive", "scheduler": "launchd", "plist": "'"$PLIST_FILE"'"}'
            fi
        else
            echo '{"status": "not_configured", "scheduler": "launchd"}'
        fi
    else
        # Linux
        CRON_EXISTS=$(crontab -l 2>/dev/null | grep "$TARGET_ID" | wc -l)
        if [ "$CRON_EXISTS" -gt 0 ]; then
            echo '{"status": "active", "scheduler": "cron"}'
        else
            echo '{"status": "not_configured", "scheduler": "cron"}'
        fi
    fi
}

enable_task() {
    INTERVAL_SECONDS=$((INTERVAL_HOURS * 3600))

    if [ "$(uname)" == "Darwin" ]; then
        # macOS: 创建 launchd plist
        mkdir -p "$PLIST_DIR"

        cat > "$PLIST_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${TASK_ID}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${SCRIPT_DIR}/run_scan.sh</string>
        <string>${TARGET_ID}</string>
        <string>scheduled</string>
    </array>
    <key>StartInterval</key>
    <integer>${INTERVAL_SECONDS}</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>${ASSET_DIR}/logs/${TARGET_ID}.log</string>
    <key>StandardErrorPath</key>
    <string>${ASSET_DIR}/logs/${TARGET_ID}.error.log</string>
    <key>WorkingDirectory</key>
    <string>${SCRIPT_DIR}</string>
</dict>
</plist>
EOF
        # 创建日志目录
        mkdir -p "${ASSET_DIR}/logs"

        # 加载任务
        launchctl unload "$PLIST_FILE" 2>/dev/null
        launchctl load "$PLIST_FILE"

        # 更新数据库
        TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        NEXT_RUN=$(date -u -v+${INTERVAL_HOURS}H +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d "+${INTERVAL_HOURS} hours" +"%Y-%m-%dT%H:%M:%SZ")

        duckdb "$DB_FILE" << SQL
INSERT INTO scheduled_tasks (id, target_id, task_type, cron_expression, enabled, created_at, next_run_at)
VALUES ('task_$(date +%s)', '$TARGET_ID', 'full_scan', 'every ${INTERVAL_HOURS}h', TRUE, '$TIMESTAMP', '$NEXT_RUN')
ON CONFLICT (id) DO UPDATE SET enabled = TRUE, next_run_at = '$NEXT_RUN';
SQL

        echo "{\"success\": true, \"scheduler\": \"launchd\", \"interval_hours\": $INTERVAL_HOURS, \"plist\": \"$PLIST_FILE\"}"
    else
        # Linux: 添加 cron 任务
        CRON_EXPR="0 */${INTERVAL_HOURS} * * *"
        CRON_CMD="${SCRIPT_DIR}/run_scan.sh ${TARGET_ID} scheduled >> ${ASSET_DIR}/logs/${TARGET_ID}.log 2>&1 ${CRON_MARKER}-${TARGET_ID}"

        # 移除旧任务
        (crontab -l 2>/dev/null | grep -v "${CRON_MARKER}-${TARGET_ID}") | crontab -

        # 添加新任务
        (crontab -l 2>/dev/null; echo "${CRON_EXPR} ${CRON_CMD}") | crontab -

        # 创建日志目录
        mkdir -p "${ASSET_DIR}/logs"

        echo "{\"success\": true, \"scheduler\": \"cron\", \"interval_hours\": $INTERVAL_HOURS, \"cron\": \"$CRON_EXPR\"}"
    fi
}

disable_task() {
    if [ "$(uname)" == "Darwin" ]; then
        # macOS
        if [ -f "$PLIST_FILE" ]; then
            launchctl unload "$PLIST_FILE" 2>/dev/null
            rm -f "$PLIST_FILE"
            duckdb "$DB_FILE" "UPDATE scheduled_tasks SET enabled = FALSE WHERE target_id = '$TARGET_ID'"
            echo '{"success": true, "message": "定时任务已禁用"}'
        else
            echo '{"error": "任务不存在"}' >&2
            exit 1
        fi
    else
        # Linux
        (crontab -l 2>/dev/null | grep -v "${CRON_MARKER}-${TARGET_ID}") | crontab -
        duckdb "$DB_FILE" "UPDATE scheduled_tasks SET enabled = FALSE WHERE target_id = '$TARGET_ID'"
        echo '{"success": true, "message": "定时任务已禁用"}'
    fi
}

case "$ACTION" in
    --status)
        show_status
        ;;
    --disable)
        disable_task
        ;;
    --enable|*)
        enable_task
        ;;
esac
