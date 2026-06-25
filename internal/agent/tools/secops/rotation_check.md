Check key rotation status for AWS, GCP, Azure, and Kubernetes.

## Usage

- `system_type` — required: `aws`, `gcp`, `azure`, `kubernetes`.
- `key_type` — required: `api_key`, `cert`, `password`.
- `target_id` — required identifier of the key or credential to check.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to check rotation status from a remote
machine via SSH.

## Output

Returns last rotation date, age in days, status (`ok`, `due`, `overdue`,
`unknown`), next rotation, and rotation policy days.
