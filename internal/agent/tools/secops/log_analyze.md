Parse and analyze log files from multiple sources.

Supports syslog, application logs, and arbitrary log files. Searches for
patterns, aggregates entries, and detects anomalies.

## Usage

- `log_source` — required: `syslog`, `application`, `auth`, `kernel`,
  `security`, `custom`.
- `target_path` — required for `custom` source; path to log file or directory.
- `pattern` — optional regex or keyword to search for.
- `time_range` — optional: e.g. `1h`, `24h`, `7d`.
- `severity` — optional minimum severity filter.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to analyze logs on a remote machine
via SSH.

## Output

Returns matched log entries, aggregation statistics, and detected anomalies
with timestamps and severity levels.
