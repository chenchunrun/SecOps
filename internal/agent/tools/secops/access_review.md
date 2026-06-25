Audit user, group, and service account permissions across AWS, GCP, Linux, and databases.

## Usage

- `system_type` — required: `aws`, `gcp`, `linux`, `database`.
- `review_type` — required: `users`, `permissions`, `service_accounts`.
- `target` — required: target resource, project, or host to review.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to run the review on a remote machine
via SSH.

## Output

Returns access entries with principal, permission, resource, age, last used,
and risk level, plus aggregated high-risk and stale counts.
