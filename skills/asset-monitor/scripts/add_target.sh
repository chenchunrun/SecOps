#!/bin/bash
# 添加监控目标
# 用法: add_target.sh "<name>" "<type>" "<seed_domains>" [description]
# 类型: organization, domain, ipRange, custom
# seed_domains: 逗号分隔的域名列表

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

NAME="$1"
TYPE="${2:-domain}"
SEED_DOMAINS="$3"

if [ -z "$NAME" ]; then
    echo '{"error": "名称不能为空"}' >&2
    exit 1
fi

# 验证类型
case "$TYPE" in
    organization|domain|ipRange|custom) ;;
    *)
        echo '{"error": "无效的类型，支持: organization, domain, ipRange, custom"}' >&2
        exit 1
        ;;
esac

# 确保数据库存在
if [ ! -f "$DB_FILE" ]; then
    "$SCRIPT_DIR/init_db.sh" > /dev/null
fi

# 检查是否已存在
EXISTING=$(duckdb "$DB_FILE" -noheader -csv "SELECT id FROM targets WHERE name = '$NAME' LIMIT 1" 2>/dev/null)
if [ -n "$EXISTING" ]; then
    echo "{\"error\": \"目标已存在\", \"existing_id\": \"$EXISTING\"}"
    exit 1
fi

# 生成 ID 和时间戳
TARGET_ID="target_$(date +%s)_$RANDOM"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 构建 seed_domains JSON 数组
if [ -n "$SEED_DOMAINS" ]; then
    SEED_DOMAINS_JSON=$(echo "$SEED_DOMAINS" | tr ',' '\n' | jq -R . | jq -s .)
else
    SEED_DOMAINS_JSON="[]"
fi

# 默认配置
CONFIG_JSON='{
    "scan_interval_minutes": 1440,
    "enable_subdomain_enum": true,
    "enable_port_scan": true,
    "enable_vuln_check": false,
    "enable_cert_monitor": true,
    "enable_change_alert": true,
    "ports_to_scan": [21, 22, 23, 25, 80, 443, 3306, 3389, 6379, 8080, 8443, 9200],
    "max_subdomains": 10000,
    "alert_level": "medium"
}'

# 转义 JSON 用于 SQL
SEED_DOMAINS_ESCAPED=$(echo "$SEED_DOMAINS_JSON" | sed "s/'/''/g")
CONFIG_ESCAPED=$(echo "$CONFIG_JSON" | sed "s/'/''/g")

# 插入数据库
duckdb "$DB_FILE" << SQL
INSERT INTO targets (id, name, type, seed_domains, config, status, created_at)
VALUES (
    '$TARGET_ID',
    '$NAME',
    '$TYPE',
    '$SEED_DOMAINS_ESCAPED',
    '$CONFIG_ESCAPED',
    'active',
    '$TIMESTAMP'
);
SQL

if [ $? -eq 0 ]; then
    # 返回创建的目标
    cat << EOF
{
  "id": "$TARGET_ID",
  "name": "$NAME",
  "type": "$TYPE",
  "seed_domains": $SEED_DOMAINS_JSON,
  "seed_ips": [],
  "keywords": [],
  "metadata": {},
  "created_at": "$TIMESTAMP",
  "last_scan_at": null,
  "status": "active",
  "config": $CONFIG_JSON
}
EOF
else
    echo '{"error": "添加目标失败"}' >&2
    exit 1
fi
