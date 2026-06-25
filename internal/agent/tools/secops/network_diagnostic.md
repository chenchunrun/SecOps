Run network diagnostic commands for connectivity and path analysis.

Supported diagnostic types: **ping**, **traceroute**, **mtr**, **dns**,
**port_scan**.

## Usage

- `type` — required: `ping`, `traceroute`, `mtr`, `dns`, or `port_scan`.
- `target` — required: hostname or IP address to diagnose.
- `port` — optional: port number (for port_scan or specific checks).
- `count` — optional: number of probes (default varies by type).
- `timeout` — optional: timeout in seconds.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to run diagnostics from a remote
machine via SSH.

## Output

Returns diagnostic results including latency, hop details, DNS records, or
open/closed port status depending on the diagnostic type.
