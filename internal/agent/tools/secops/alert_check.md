Check alerts from Prometheus, Grafana, Datadog, and PagerDuty.

## Usage

- `system` — required: `prometheus`, `grafana`, `datadog`, `pagerduty`.
- `filter` — optional text filter to match alert names, messages, or labels.
- `status` — optional status filter: `firing`, `resolved`, `acknowledged`.
- `time_range` — optional duration such as `1h`, `30m`, `24h`.
- `endpoint` — optional API endpoint URL for the alert system.
- `api_token` — optional API token for authentication.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to query alerts from a remote machine
via SSH.

## Output

Returns matching alerts with id, name, status, severity, fired time, message,
labels, and annotations.
