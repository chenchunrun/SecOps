Monitor CPU, memory, disk, and network metrics. Detect anomalies like CPU spikes, memory leaks, disk full, and network saturation.

## Usage

- `target` — required hostname to monitor, e.g. `localhost`.
- `metrics` — required list: `cpu`, `memory`, `disk`, `network`, `process`.
- `duration` — monitoring duration such as `1m`, `5m`, `15m`, `1h`.
- `interval` — sampling interval such as `1s`, `5s`, `10s`, `30s`.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to collect metrics from a remote
machine via SSH.

## Output

Returns metric samples with name, value, unit, and timestamp, plus anomaly
detection results and a summary.
