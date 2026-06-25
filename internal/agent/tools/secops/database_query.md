Execute read-only queries on MySQL, PostgreSQL, MongoDB, and Redis databases.

## Usage

- `system` — required: `mysql`, `postgresql`, `mongodb`, `redis`.
- `host` — required database host address.
- `port` — required database port number.
- `database` — required database name.
- `query` — required read-only query (`SELECT` only for SQL systems).
- `timeout_sec` — query timeout in seconds.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to run the query from a remote machine
via SSH.

## Output

Returns result columns, rows, row count, duration, and any error message.
Only read-only operations are permitted.
