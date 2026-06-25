Check database replication status for MySQL and PostgreSQL.

## Usage

- `system` — required: `mysql`, `postgresql`.
- `host` — required primary database host to check replication.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to check replication from a remote
machine via SSH.

## Output

Returns replication status, lag in seconds, master host, replica hosts, and
whether replication is healthy.
