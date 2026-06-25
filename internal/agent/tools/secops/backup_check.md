Check backup status for MySQL, PostgreSQL, Kubernetes, and file-based systems.

## Usage

- `system_type` — required: `mysql`, `postgresql`, `k8s`, `files`.
- `target` — required: backup target host, cluster name, or path.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to check backup status on a remote
machine via SSH.

## Output

Returns last backup time, status (`ok`, `stale`, `missing`), age in hours,
size, next scheduled backup, and any detected issues.
