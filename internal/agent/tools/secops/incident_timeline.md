Generate incident timeline from alerts, actions, escalations, and resolutions.

## Usage

- `incident_id` — required unique incident identifier.
- `events` — optional pre-collected timeline events.
- `events_file_path` — optional path to a JSON or JSONL file of incident events.

## Remote execution

Set `remote_host` (and optionally `remote_user`, `remote_port`,
`remote_key_path`, `remote_proxy_jump`) to load events from a remote machine
via SSH.

## Output

Returns a chronological event list with timestamps, actors, descriptions,
severity, metadata, duration, root cause, and impact summary.
