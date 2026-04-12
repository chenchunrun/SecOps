#!/bin/bash
# 初始化 DuckDB 数据库
# 用法: init_db.sh [--force]

ASSET_DIR="${HOME}/.cybersec/assets"
DB_FILE="${ASSET_DIR}/assets.duckdb"

# 检查 duckdb 是否安装
if ! command -v duckdb &> /dev/null; then
    echo '{"error": "duckdb 未安装。请运行: brew install duckdb 或 pip install duckdb-cli"}' >&2
    exit 1
fi

# 创建目录
mkdir -p "$ASSET_DIR"

# 如果使用 --force，删除旧数据库
if [ "$1" == "--force" ] && [ -f "$DB_FILE" ]; then
    rm -f "$DB_FILE"
fi

# 如果数据库已存在，跳过初始化
if [ -f "$DB_FILE" ]; then
    # 验证数据库结构
    TABLE_COUNT=$(duckdb "$DB_FILE" -noheader -csv "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='main'" 2>/dev/null)
    if [ "$TABLE_COUNT" -ge 4 ]; then
        echo '{"success": true, "message": "数据库已存在且结构完整", "path": "'"$DB_FILE"'"}'
        exit 0
    fi
fi

# 创建数据库和表
duckdb "$DB_FILE" << 'SQL'
-- 监控目标表
CREATE TABLE IF NOT EXISTS targets (
    id VARCHAR PRIMARY KEY,
    name VARCHAR NOT NULL,
    type VARCHAR DEFAULT 'domain',
    seed_domains JSON DEFAULT '[]',
    seed_ips JSON DEFAULT '[]',
    keywords JSON DEFAULT '[]',
    metadata JSON DEFAULT '{}',
    config JSON DEFAULT '{}',
    status VARCHAR DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_scan_at TIMESTAMP,
    CONSTRAINT valid_type CHECK (type IN ('organization', 'domain', 'ipRange', 'custom')),
    CONSTRAINT valid_status CHECK (status IN ('active', 'paused', 'deleted'))
);

-- 资产记录表
CREATE TABLE IF NOT EXISTS assets (
    id VARCHAR PRIMARY KEY,
    target_id VARCHAR NOT NULL,
    type VARCHAR NOT NULL,
    value VARCHAR NOT NULL,
    attributes JSON DEFAULT '{}',
    tags JSON DEFAULT '[]',
    risk_level VARCHAR DEFAULT 'unknown',
    risk_reason VARCHAR,
    first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_changed_at TIMESTAMP,
    status VARCHAR DEFAULT 'active',
    related_asset_ids JSON DEFAULT '[]',
    parent_asset_id VARCHAR,
    CONSTRAINT valid_asset_type CHECK (type IN ('domain', 'subdomain', 'ip', 'port', 'certificate', 'webapp', 'cloud_bucket', 'api_endpoint')),
    CONSTRAINT valid_risk CHECK (risk_level IN ('safe', 'low', 'medium', 'high', 'critical', 'unknown')),
    CONSTRAINT valid_asset_status CHECK (status IN ('active', 'inactive', 'deleted')),
    UNIQUE(target_id, type, value)
);

-- 变更记录表
CREATE TABLE IF NOT EXISTS changes (
    id VARCHAR PRIMARY KEY,
    target_id VARCHAR,
    asset_id VARCHAR,
    change_type VARCHAR NOT NULL,
    field VARCHAR,
    old_value VARCHAR,
    new_value VARCHAR,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR DEFAULT 'info',
    description VARCHAR,
    is_acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_at TIMESTAMP,
    CONSTRAINT valid_change_type CHECK (change_type IN ('added', 'removed', 'modified', 'portOpened', 'portClosed', 'ipChanged', 'certExpiring', 'riskIncreased')),
    CONSTRAINT valid_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
);

-- 扫描历史表
CREATE TABLE IF NOT EXISTS scan_history (
    id VARCHAR PRIMARY KEY,
    target_id VARCHAR NOT NULL,
    scan_type VARCHAR DEFAULT 'full',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    status VARCHAR DEFAULT 'running',
    new_assets INTEGER DEFAULT 0,
    updated_assets INTEGER DEFAULT 0,
    removed_assets INTEGER DEFAULT 0,
    error_message VARCHAR,
    CONSTRAINT valid_scan_type CHECK (scan_type IN ('full', 'quick', 'subdomain', 'port', 'scheduled')),
    CONSTRAINT valid_scan_status CHECK (status IN ('running', 'completed', 'failed', 'cancelled'))
);

-- 告警配置表
CREATE TABLE IF NOT EXISTS alert_rules (
    id VARCHAR PRIMARY KEY,
    target_id VARCHAR,
    rule_type VARCHAR NOT NULL,
    condition JSON NOT NULL,
    action VARCHAR DEFAULT 'notify',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_triggered_at TIMESTAMP,
    CONSTRAINT valid_rule_type CHECK (rule_type IN ('new_asset', 'risk_change', 'port_change', 'cert_expiry', 'custom'))
);

-- 定时任务表
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id VARCHAR PRIMARY KEY,
    target_id VARCHAR NOT NULL,
    task_type VARCHAR NOT NULL,
    cron_expression VARCHAR NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_task_type CHECK (task_type IN ('full_scan', 'quick_scan', 'subdomain_enum', 'port_scan', 'cert_check'))
);

-- ============ 两高一弱检测表 ============

-- 基线检测历史表
CREATE TABLE IF NOT EXISTS baseline_scans (
    id VARCHAR PRIMARY KEY,
    target_id VARCHAR,
    scan_type VARCHAR NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    status VARCHAR DEFAULT 'running',
    high_vulns_count INTEGER DEFAULT 0,
    high_ports_count INTEGER DEFAULT 0,
    weak_passwords_count INTEGER DEFAULT 0,
    summary JSON DEFAULT '{}',
    CONSTRAINT valid_baseline_type CHECK (scan_type IN ('full', 'high_vuln', 'high_port', 'weak_password')),
    CONSTRAINT valid_baseline_status CHECK (status IN ('running', 'completed', 'failed'))
);

-- 高危漏洞记录表
CREATE TABLE IF NOT EXISTS baseline_vulns (
    id VARCHAR PRIMARY KEY,
    scan_id VARCHAR NOT NULL,
    target_id VARCHAR,
    asset_id VARCHAR,
    asset_value VARCHAR NOT NULL,
    cve_id VARCHAR,
    vuln_name VARCHAR NOT NULL,
    cvss_score DECIMAL(3,1),
    severity VARCHAR DEFAULT 'high',
    description VARCHAR,
    solution VARCHAR,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fixed_at TIMESTAMP,
    status VARCHAR DEFAULT 'open',
    CONSTRAINT valid_vuln_severity CHECK (severity IN ('medium', 'high', 'critical')),
    CONSTRAINT valid_vuln_status CHECK (status IN ('open', 'fixing', 'fixed', 'ignored'))
);

-- 高危端口记录表
CREATE TABLE IF NOT EXISTS baseline_ports (
    id VARCHAR PRIMARY KEY,
    scan_id VARCHAR NOT NULL,
    target_id VARCHAR,
    asset_id VARCHAR,
    asset_value VARCHAR NOT NULL,
    port INTEGER NOT NULL,
    protocol VARCHAR DEFAULT 'tcp',
    service VARCHAR,
    risk_level VARCHAR DEFAULT 'high',
    reason VARCHAR,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP,
    status VARCHAR DEFAULT 'open',
    CONSTRAINT valid_port_risk CHECK (risk_level IN ('medium', 'high', 'critical')),
    CONSTRAINT valid_port_status CHECK (status IN ('open', 'closed', 'filtered', 'ignored'))
);

-- 弱口令记录表
CREATE TABLE IF NOT EXISTS baseline_weak_credentials (
    id VARCHAR PRIMARY KEY,
    scan_id VARCHAR NOT NULL,
    target_id VARCHAR,
    asset_id VARCHAR,
    asset_value VARCHAR NOT NULL,
    service VARCHAR NOT NULL,
    port INTEGER,
    username VARCHAR,
    credential_type VARCHAR DEFAULT 'weak_password',
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fixed_at TIMESTAMP,
    status VARCHAR DEFAULT 'open',
    CONSTRAINT valid_cred_type CHECK (credential_type IN ('weak_password', 'default_password', 'no_password', 'leaked_password')),
    CONSTRAINT valid_cred_status CHECK (status IN ('open', 'fixed', 'ignored'))
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
CREATE INDEX IF NOT EXISTS idx_assets_risk ON assets(risk_level);
CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value);
CREATE INDEX IF NOT EXISTS idx_changes_target ON changes(target_id);
CREATE INDEX IF NOT EXISTS idx_changes_detected ON changes(detected_at);
CREATE INDEX IF NOT EXISTS idx_changes_unack ON changes(is_acknowledged);
CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_history(target_id);

-- 两高一弱索引
CREATE INDEX IF NOT EXISTS idx_baseline_scans_target ON baseline_scans(target_id);
CREATE INDEX IF NOT EXISTS idx_baseline_scans_type ON baseline_scans(scan_type);
CREATE INDEX IF NOT EXISTS idx_baseline_vulns_scan ON baseline_vulns(scan_id);
CREATE INDEX IF NOT EXISTS idx_baseline_vulns_status ON baseline_vulns(status);
CREATE INDEX IF NOT EXISTS idx_baseline_vulns_cve ON baseline_vulns(cve_id);
CREATE INDEX IF NOT EXISTS idx_baseline_ports_scan ON baseline_ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_baseline_ports_status ON baseline_ports(status);
CREATE INDEX IF NOT EXISTS idx_baseline_creds_scan ON baseline_weak_credentials(scan_id);
CREATE INDEX IF NOT EXISTS idx_baseline_creds_status ON baseline_weak_credentials(status);
SQL

if [ $? -eq 0 ]; then
    echo '{"success": true, "message": "数据库初始化完成", "path": "'"$DB_FILE"'", "tables": ["targets", "assets", "changes", "scan_history", "alert_rules", "scheduled_tasks", "baseline_scans", "baseline_vulns", "baseline_ports", "baseline_weak_credentials"]}'
else
    echo '{"error": "数据库初始化失败"}' >&2
    exit 1
fi
