Query monitoring systems for metrics, alerts, and health status.

Supported systems: **Prometheus**, **Grafana**, **Datadog**, **New Relic**,
**InfluxDB**.

## Usage

- `system` — required: `prometheus`, `grafana`, `datadog`, `newrelic`, or
  `influxdb`.
- `query` — required: the query expression (PromQL, Grafana query, etc.).
- `endpoint` — optional: monitoring system endpoint URL.
- `time_range` — optional: e.g. `1h`, `6h`, `24h`.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to query monitoring from a remote
machine via SSH.

## Output

Returns query results with metric values, timestamps, and threshold status.
