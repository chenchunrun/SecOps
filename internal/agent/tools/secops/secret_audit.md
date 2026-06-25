Scan a directory or file for leaked credentials, API keys, passwords, and private keys.

The scanner walks the target path recursively, skipping binary files and common
non-text directories (`.git`, `node_modules`, `vendor`, etc.), and applies
regex-based credential patterns covering GitHub PAT, AWS keys, Stripe keys,
Slack tokens, JWTs, database DSNs, and more.

## Usage

Provide `target_path` pointing to a directory or single file.

- `scan_type` — optional: `pattern` (default), `entropy`, or `ai`.
- `severity` — optional filter: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to scan files on a remote machine
via SSH.

## Output

Returns a list of findings with file, line number, credential type, a
redacted preview, severity, and a human-readable description.
